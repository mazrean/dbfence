package config

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mazrean/dbfence/internal/model"
)

func TestLoadConnection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, src string
		want      model.Connection
	}{
		{
			name: "mysql socket",
			src:  "connection \"mysql\" {\n socket = \"/run/mysqld/mysqld.sock\"\n user = \"root\"\n}\n",
			want: model.Connection{Engine: model.EngineMySQL, Auth: model.AuthPassword, Socket: "/run/mysqld/mysqld.sock", User: "root",
				TLS: model.TLSDisable, Port: 3306, ConnectTimeout: 10 * time.Second},
		},
		{
			name: "aws_iam defaults to tls require",
			src:  "connection \"mysql\" {\n host = \"db\"\n user = \"app\"\n aws_iam {\n  region = \"ap-northeast-1\"\n }\n}\n",
			want: model.Connection{Engine: model.EngineMySQL, Auth: model.AuthAWSIAM, AWSRegion: "ap-northeast-1", Host: "db", User: "app",
				TLS: model.TLSRequire, Port: 3306, ConnectTimeout: 10 * time.Second},
		},
		{
			name: "gcp_iam with a CA file",
			src:  "connection \"postgres\" {\n host = \"db\"\n user = \"sa@p.iam\"\n tls = \"verify-ca\"\n tls_ca_file = \"/etc/ca.pem\"\n gcp_iam {}\n}\n",
			want: model.Connection{Engine: model.EnginePostgres, Auth: model.AuthGCPIAM, Host: "db", User: "sa@p.iam", Database: "postgres",
				TLS: model.TLSVerifyCA, TLSCAFile: "/etc/ca.pem", Port: 5432, ConnectTimeout: 10 * time.Second},
		},
		{
			name: "postgres socket directory as host",
			src:  "connection \"postgres\" {\n host = \"/var/run/postgresql\"\n user = \"postgres\"\n tls = \"allow\"\n}\n",
			want: model.Connection{Engine: model.EnginePostgres, Auth: model.AuthPassword, Host: "/var/run/postgresql", User: "postgres",
				Database: "postgres", TLS: model.TLSAllow, Port: 5432, ConnectTimeout: 10 * time.Second},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := load(t, tt.src)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, cfg.Connection); diff != "" {
				t.Errorf("Connection mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLoadConnectionRelativeCAFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write(t, filepath.Join(dir, "dbfence.hcl"), "connection \"mysql\" {\n host = \"db\"\n user = \"u\"\n tls = \"verify-full\"\n tls_ca_file = \"certs/ca.pem\"\n}\n")
	cfg, err := Load(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "certs/ca.pem"); cfg.Connection.TLSCAFile != want {
		t.Errorf("tls_ca_file = %q, want %q", cfg.Connection.TLSCAFile, want)
	}
}

func TestLoadConnectionErrors(t *testing.T) {
	t.Parallel()
	runDiagCases(t, []diagCase{
		{
			name:  "socket on postgres",
			src:   "connection \"postgres\" {\n socket = \"/tmp/s\"\n user = \"u\"\n}\n",
			want:  []string{`"socket" is only supported for mysql`, "dbfence.hcl line 2"},
			count: 1,
		},
		{
			name:  "socket with host and port",
			src:   "connection \"mysql\" {\n socket = \"/tmp/s\"\n host = \"h\"\n port = 3306\n user = \"u\"\n}\n",
			want:  []string{"host cannot be set together with socket", "port cannot be set together with socket"},
			count: 2,
		},
		{
			name:  "missing host",
			src:   "connection \"mysql\" {\n user = \"u\"\n}\n",
			want:  []string{"connection.host or connection.socket is required"},
			count: 1,
		},
		{
			name:  "password and aws_iam",
			src:   "connection \"mysql\" {\n host = \"h\"\n user = \"u\"\n password = \"p\"\n aws_iam {}\n}\n",
			want:  []string{"Conflicting authentication", "password and aws_iam cannot both be set", "dbfence.hcl line 5"},
			count: 1,
		},
		{
			name:  "aws_iam and gcp_iam",
			src:   "connection \"postgres\" {\n host = \"h\"\n user = \"u\"\n aws_iam {}\n gcp_iam {}\n}\n",
			want:  []string{"aws_iam and gcp_iam cannot both be set"},
			count: 1,
		},
		{
			name:  "IAM without TLS",
			src:   "connection \"postgres\" {\n host = \"h\"\n user = \"u\"\n tls = \"prefer\"\n gcp_iam {}\n}\n",
			want:  []string{"Insecure tls", "dbfence.hcl line 4"},
			count: 1,
		},
		{
			name:  "aws_iam over a socket",
			src:   "connection \"mysql\" {\n socket = \"/tmp/s\"\n user = \"u\"\n aws_iam {}\n}\n",
			want:  []string{"aws_iam needs host and port"},
			count: 1,
		},
		{
			name:  "verify-ca on mysql",
			src:   "connection \"mysql\" {\n host = \"h\"\n user = \"u\"\n tls = \"verify-ca\"\n}\n",
			want:  []string{"Invalid tls", "for mysql"},
			count: 1,
		},
		{
			name:  "verify-full over a socket",
			src:   "connection \"mysql\" {\n socket = \"/tmp/s\"\n user = \"u\"\n tls = \"verify-full\"\n}\n",
			want:  []string{"socket connection does not have"},
			count: 1,
		},
		{
			name:  "CA file without verification",
			src:   "connection \"postgres\" {\n host = \"h\"\n user = \"u\"\n tls_ca_file = \"ca.pem\"\n}\n",
			want:  []string{"Unused tls_ca_file", "dbfence.hcl line 4"},
			count: 1,
		},
		{
			name:  "missing connection block",
			src:   "role \"r\" {}\n",
			want:  []string{`connection "postgres" or connection "mysql" block is required`},
			count: 1,
		},
	})
}
