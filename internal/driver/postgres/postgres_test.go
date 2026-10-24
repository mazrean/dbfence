package postgres

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/mazrean/dbfence/internal/auth"
	"github.com/mazrean/dbfence/internal/driver/internal/tlstest"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/password"
	"github.com/mazrean/dbfence/internal/plan"
)

func TestParseErrorHidesSettings(t *testing.T) {
	t.Parallel()
	_, err := pgx.ParseConfig("host='127.0.0.1' password='S3c\\'ret x' port='abc'")
	if err == nil {
		t.Fatal("ParseConfig succeeded")
	}
	msg := parseError(err).Error()
	if strings.Contains(msg, "ret x") {
		t.Errorf("error leaks the password: %s", msg)
	}
	if !strings.HasPrefix(msg, "postgres connection settings: ") || !strings.Contains(msg, "invalid port") {
		t.Errorf("error = %q, want it to mention the invalid port", msg)
	}
}

func testConnection() model.Connection {
	return model.Connection{Engine: model.EnginePostgres, Host: "db", Port: 5433, User: "admin", Database: "app",
		TLS: model.TLSDisable, ConnectTimeout: 3 * time.Second}
}

func TestParseConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		user     string
		tls      model.TLSMode
		caFile   bool
		wantTLS  bool
		fallback bool
	}{
		{name: "disable", user: "admin", tls: model.TLSDisable},
		{name: "allow tries plain first", user: "admin", tls: model.TLSAllow, fallback: true},
		{name: "prefer falls back to plain", user: "admin", tls: model.TLSPrefer, wantTLS: true, fallback: true},
		{name: "require", user: "admin", tls: model.TLSRequire, wantTLS: true},
		{name: "verify-ca with a CA file", user: "admin", tls: model.TLSVerifyCA, caFile: true, wantTLS: true},
		{name: "verify-full", user: "admin", tls: model.TLSVerifyFull, wantTLS: true},
		{name: "quotes, backslashes and spaces", user: `a'b\c d@e=f`, tls: model.TLSDisable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			conn := testConnection()
			conn.User, conn.TLS = tt.user, tt.tls
			if tt.caFile {
				conn.TLSCAFile = tlstest.CAFile(t)
			}
			cfg, err := parseConfig(conn)
			if err != nil {
				t.Fatal(err)
			}
			// The password is set for each connection (see openDB).
			if cfg.Host != "db" || cfg.Port != 5433 || cfg.User != tt.user || cfg.Password != "" || cfg.Database != "app" {
				t.Errorf("config = %s@%s:%d/%s password %q", cfg.User, cfg.Host, cfg.Port, cfg.Database, cfg.Password)
			}
			if cfg.ConnectTimeout != 3*time.Second {
				t.Errorf("ConnectTimeout = %v, want 3s", cfg.ConnectTimeout)
			}
			if got := cfg.TLSConfig != nil; got != tt.wantTLS {
				t.Errorf("TLS = %v, want %v", got, tt.wantTLS)
			}
			if got := len(cfg.Fallbacks) > 0; got != tt.fallback {
				t.Errorf("fallbacks = %v, want %v", got, tt.fallback)
			}
			if tt.tls == model.TLSVerifyFull && (cfg.TLSConfig.InsecureSkipVerify || cfg.TLSConfig.ServerName != "db") {
				t.Errorf("verify-full TLS config skips verification")
			}
			if tt.caFile && cfg.TLSConfig.RootCAs == nil {
				t.Errorf("tls_ca_file is not used")
			}
			if got := cfg.Copy().RuntimeParams["standard_conforming_strings"]; got != "on" {
				t.Errorf("standard_conforming_strings = %q, want on (also on per-database copies)", got)
			}
			if got := cfg.Copy().RuntimeParams["client_encoding"]; got != "UTF8" {
				t.Errorf("client_encoding = %q, want UTF8 (also on per-database copies)", got)
			}
		})
	}
}

// TestParseConfigIgnoresEnvironment checks that PG* environment variables
// and the password file do not fill in settings the configuration leaves
// out.
func TestParseConfigIgnoresEnvironment(t *testing.T) {
	passfile := filepath.Join(t.TempDir(), "pgpass")
	if err := os.WriteFile(passfile, []byte("*:*:*:*:from-passfile\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"PGPASSWORD": "from-env", "PGPASSFILE": passfile, "PGSSLMODE": "require", "PGCONNECT_TIMEOUT": "99",
		"PGHOST": "envhost", "PGDATABASE": "envdb", "PGOPTIONS": "-c standard_conforming_strings=off",
	} {
		t.Setenv(k, v)
	}
	cfg, err := parseConfig(testConnection())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Password != "" || cfg.TLSConfig != nil || cfg.ConnectTimeout != 3*time.Second || cfg.Host != "db" || cfg.Database != "app" {
		t.Errorf("config took settings from the environment: password %q, TLS %v, timeout %v, %s/%s",
			cfg.Password, cfg.TLSConfig != nil, cfg.ConnectTimeout, cfg.Host, cfg.Database)
	}
	if got := cfg.RuntimeParams["standard_conforming_strings"]; got != "on" {
		t.Errorf("standard_conforming_strings = %q, want on", got)
	}
}

func TestLiteral(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want string }{
		{"plain", "'plain'"},
		{"it's", "'it''s'"},
		{`a\b`, `E'a\\b'`},
		{`\'; DROP DATABASE prod; --`, `E'\\''; DROP DATABASE prod; --'`},
	}
	for _, tt := range tests {
		if got := plan.SQL("", Literal(tt.in)).SQL(); got != tt.want {
			t.Errorf("Literal(%q) = %s, want %s", tt.in, got, tt.want)
		}
	}
}

func TestWithDetail(t *testing.T) {
	t.Parallel()
	plain := errors.New("boom")
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"not a server error", plain, "boom"},
		{"no detail", &pgconn.PgError{Severity: "ERROR", Message: "m", Code: "42501"}, "ERROR: m (SQLSTATE 42501)"},
		{
			"detail and hint",
			&pgconn.PgError{Severity: "ERROR", Message: "m", Code: "2BP01", Detail: "owner of table t", Hint: "use CASCADE"},
			"ERROR: m (SQLSTATE 2BP01)\nDETAIL: owner of table t\nHINT: use CASCADE",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := withDetail(tt.err)
			if tt.err == nil {
				if got != nil {
					t.Fatalf("withDetail(nil) = %v", got)
				}
				return
			}
			if got.Error() != tt.want {
				t.Errorf("got %q, want %q", got.Error(), tt.want)
			}
			if !errors.Is(got, tt.err) {
				t.Errorf("withDetail does not wrap the original error")
			}
		})
	}
}

func TestNoticeError(t *testing.T) {
	t.Parallel()
	notice := func(severity, code string) *pgconn.Notice {
		return &pgconn.Notice{Severity: severity, SeverityUnlocalized: severity, Code: code, Message: "m"}
	}
	tests := []struct {
		name    string
		notices []*pgconn.Notice
		wantErr bool
	}{
		{"none", nil, false},
		{"notice", []*pgconn.Notice{notice("NOTICE", "00000")}, false},
		{"other warning", []*pgconn.Notice{notice("WARNING", "25P01")}, false},
		{"membership not revoked", []*pgconn.Notice{notice("NOTICE", "00000"), notice("WARNING", "01000")}, true},
		{"privilege not revoked", []*pgconn.Notice{notice("WARNING", "01006")}, true},
		{"privilege not granted", []*pgconn.Notice{notice("WARNING", "01007")}, true},
	}
	for _, tt := range tests {
		if err := noticeError(tt.notices); (err != nil) != tt.wantErr {
			t.Errorf("%s: err = %v", tt.name, err)
		}
	}
}

func TestIsSystemRole(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		want bool
	}{
		{"postgres", true}, {"pg_monitor", true}, {"rdsadmin", true}, {"rdsrepladmin", true},
		{"rdstopmgr", true}, {"rds_superuser", true}, {"cloudsqlsuperuser", true},
		{"azuresu", true}, {"azure_pg_admin", true}, {"azure_superuser", true}, {"alloydbadmin", true},
		{"app", false}, {"rdsuser", false}, {"postgres2", false},
	}
	for _, tt := range tests {
		if got := (Dialect{}).IsSystemRole(pg(tt.name)); got != tt.want {
			t.Errorf("IsSystemRole(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestAlterDatabaseImmutableAttributes(t *testing.T) {
	t.Parallel()
	cur := model.Database{Name: "app", Encoding: "LATIN1", LcCollate: "en_US.utf8", LcCtype: "C"}
	tests := []struct {
		name     string
		db       model.Database
		wantWarn bool
	}{
		{"same", model.Database{Encoding: "LATIN1", LcCollate: "en_US.utf8", LcCtype: "C"}, false},
		{"iso alias", model.Database{Encoding: "ISO-8859-1"}, false},
		{"lower case alias", model.Database{Encoding: "iso_8859_1"}, false},
		{"other encoding", model.Database{Encoding: "UTF8"}, true},
		{"codeset spelling", model.Database{LcCollate: "en_US.UTF-8"}, false},
		{"other locale", model.Database{LcCollate: "de_DE.utf8"}, true},
		{"other codeset", model.Database{LcCollate: "en_US.ISO-8859-1"}, true},
		{"C locale case", model.Database{LcCtype: "c"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.db.Name = "app"
			_, warns := Dialect{}.AlterDatabase(tt.db, cur)
			if got := len(warns) > 0; got != tt.wantWarn {
				t.Errorf("warnings = %v, want warning %v", warns, tt.wantWarn)
			}
		})
	}
}

func TestNormEncoding(t *testing.T) {
	t.Parallel()
	tests := []struct{ a, b string }{
		{"UTF8", "utf-8"}, {"UTF8", "unicode"}, {"EUC_JP", "euc-jp"}, {"LATIN9", "ISO-8859-15"},
		{"WIN1252", "windows-1252"}, {"SJIS", "Shift_JIS"}, {"ISO_8859_5", "iso-8859-5"}, {"KOI8R", "koi8"},
	}
	for _, tt := range tests {
		if normEncoding(tt.a) != normEncoding(tt.b) {
			t.Errorf("%q and %q normalize differently: %q, %q", tt.a, tt.b, normEncoding(tt.a), normEncoding(tt.b))
		}
	}
	if normEncoding("LATIN1") == normEncoding("LATIN2") {
		t.Error("LATIN1 and LATIN2 normalize equally")
	}
}

func TestAddACLFoldsGrantors(t *testing.T) {
	t.Parallel()
	obj := model.Object{Type: model.ObjectDatabase, Database: "app"}
	owner := aclEntry{obj: obj, grantee: "b", grantor: "owner", priv: "CONNECT"}
	other := aclEntry{obj: obj, grantee: "b", grantor: "a", priv: "CONNECT", grantable: true}
	for _, order := range [][]aclEntry{{owner, other}, {other, owner}} {
		st := &state{}
		cur := &model.Current{}
		for _, e := range order {
			st.addACL(cur, e)
		}
		if len(cur.Privileges) != 1 || !cur.Privileges[0].GrantOption || len(st.acl) != 2 {
			t.Errorf("order %v: privileges = %+v, acl = %d rows", order, cur.Privileges, len(st.acl))
		}
	}
}

func TestDropRoleSkipsProviderDatabases(t *testing.T) {
	t.Parallel()
	stmts := Dialect{}.DropRole(pg("x"), []string{"app", "postgres", "rdsadmin", "cloudsqladmin", "azure_maintenance", "template1", "alloydbadmin"})
	var dbs []string
	for _, s := range stmts {
		if s.Database != "" {
			dbs = append(dbs, s.Database)
		}
	}
	if strings.Join(dbs, ",") != "app,app,postgres,postgres" {
		t.Errorf("statements run on %v", dbs)
	}
}

func TestPasswordStatements(t *testing.T) {
	t.Parallel()
	// Created by PostgreSQL 17 for the password "\uFF21\uFF22\uFF23" (see
	// TestMatchPostgresServerVerifiers in internal/password).
	const pw = "\uFF21\uFF22\uFF23"
	const scram = "SCRAM-SHA-256$4096:hVrMMCRfbsmjKeiJO5B7cA==$bVbgkf3p1OpovgfV8hRTE0GymDA+Ha8HXo/RB0QIogU=:ViLbPN9ZenbZHybk4BJ5LLpa0nQYA/oONvEnDxw8WrA="
	md5 := password.PostgresMD5("app", "s3cret")
	tests := []struct {
		name       string
		password   string
		stored     string
		encryption string
		wantSQL    string
	}{
		{name: "scram match", password: pw, stored: scram},
		{name: "scram mismatch", password: "other", stored: scram, wantSQL: `ALTER ROLE "app" WITH PASSWORD 'other'`},
		{name: "md5 of the same password is upgraded", password: "s3cret", stored: md5, wantSQL: `ALTER ROLE "app" WITH PASSWORD 's3cret'`},
		{name: "md5 is kept under password_encryption = md5", password: "s3cret", stored: md5, encryption: "md5"},
		{name: "md5 mismatch under password_encryption = md5", password: "other", stored: md5, encryption: "md5", wantSQL: `ALTER ROLE "app" WITH PASSWORD 'other'`},
		{name: "scram is kept under password_encryption = md5", password: pw, stored: scram, encryption: "md5"},
		{name: "no password stored", password: "s3cret", wantSQL: `ALTER ROLE "app" WITH PASSWORD 's3cret'`},
		{name: "empty password matches no password", password: ""},
		{name: "empty password clears a stored one", password: "", stored: scram, wantSQL: `ALTER ROLE "app" WITH PASSWORD NULL`},
		{name: "backslash is sent as an escape string", password: `a\b'c`, wantSQL: `ALTER ROLE "app" WITH PASSWORD E'a\\b''c'`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := model.Role{ID: pg("app"), Password: &tt.password}
			d := Dialect{PasswordEncryption: tt.encryption}
			stmts, warns := d.AlterRole(r, model.RoleState{ID: r.ID, PasswordReadable: true, PasswordHash: []byte(tt.stored)}, false)
			if len(warns) > 0 {
				t.Errorf("warnings: %v", warns)
			}
			if tt.wantSQL == "" {
				if len(stmts) != 0 {
					t.Fatalf("password set: %v", stmts)
				}
				return
			}
			if len(stmts) != 1 {
				t.Fatalf("statements = %v, want one", stmts)
			}
			if got := stmts[0].SQL(); got != tt.wantSQL {
				t.Errorf("SQL = %s, want %s", got, tt.wantSQL)
			}
			if tt.password != "" && strings.Contains(stmts[0].Display(false), tt.password) {
				t.Errorf("password not redacted: %s", stmts[0].Display(false))
			}
		})
	}
}

func TestCreateRolePassword(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, password, want string
	}{
		{"plaintext", "first'pw", `CREATE ROLE "a" WITH PASSWORD 'first''pw'`},
		{"empty", "", `CREATE ROLE "a" WITH PASSWORD NULL`},
	}
	for _, tt := range tests {
		stmts := Dialect{}.CreateRole(model.Role{ID: pg("a"), Password: &tt.password})
		if got := stmts[0].SQL(); got != tt.want {
			t.Errorf("%s: SQL = %s, want %s", tt.name, got, tt.want)
		}
	}
}

func TestDedupLines(t *testing.T) {
	t.Parallel()
	base := errors.New("failed:\n\th: timeout\n\th: timeout")
	tests := []struct {
		err  error
		name string
		want string
	}{
		{name: "single line", err: errors.New("refused"), want: "refused"},
		{name: "repeated attempt", err: base, want: "failed:\n\th: timeout"},
		{
			name: "fallback attempt with no time left",
			err:  errors.New("failed:\n\th:1 (h): tls error: timeout: context deadline exceeded\n\th:1 (h): dial error: timeout: context deadline exceeded"),
			want: "failed:\n\th:1 (h): tls error: timeout: context deadline exceeded",
		},
		{
			name: "timeouts of different hosts",
			err:  errors.New("failed:\n\ta:1 (a): dial error: timeout: context deadline exceeded\n\tb:1 (b): dial error: timeout: context deadline exceeded"),
			want: "failed:\n\ta:1 (a): dial error: timeout: context deadline exceeded\n\tb:1 (b): dial error: timeout: context deadline exceeded",
		},
		{name: "distinct attempts", err: errors.New("failed:\n\ta: x\n\tb: y"), want: "failed:\n\ta: x\n\tb: y"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := dedupLines(tt.err)
			if got.Error() != tt.want {
				t.Errorf("dedupLines() = %q, want %q", got, tt.want)
			}
			if !errors.Is(got, tt.err) {
				t.Errorf("dedupLines() does not wrap %v", tt.err)
			}
		})
	}
}

// TestOpenTimeoutReportedOnce checks that a server that never answers
// is reported once, although sslmode=prefer makes two attempts.
func TestOpenTimeoutReportedOnce(t *testing.T) {
	t.Parallel()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	conn := testConnection()
	conn.Host, conn.Port, conn.TLS, conn.ConnectTimeout = "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, model.TLSPrefer, time.Second
	_, err = Open(t.Context(), conn, auth.Static("pw"))
	if err == nil {
		t.Fatal("Open() succeeded")
	}
	if n := strings.Count(err.Error(), ln.Addr().String()+" ("); n != 1 {
		t.Errorf("Open() error names the host %d times: %v", n, err)
	}
}

// TestOpenAsksForThePassword checks that Open takes the password of a
// connection from the source, and fails with its error.
func TestOpenAsksForThePassword(t *testing.T) {
	t.Parallel()
	conn := testConnection()
	conn.Host, conn.Port = "127.0.0.1", 1
	_, err := Open(t.Context(), conn, func(context.Context) (string, error) { return "", errors.New("no token today") })
	if err == nil || !strings.Contains(err.Error(), "no token today") {
		t.Errorf("Open() error = %v, want the password source error", err)
	}
}
