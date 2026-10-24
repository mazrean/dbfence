package postgres

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/password"
	"github.com/mazrean/dbfence/internal/plan"
)

func TestOpenParseErrorHidesPassword(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		dsn    string
		secret string
		want   string
	}{
		{
			name:   "spaces around equals",
			dsn:    "host=127.0.0.1 user=admin password = S3cret port=abc",
			secret: "S3cret",
		},
		{
			name:   "quoted password with escaped quote",
			dsn:    `host=127.0.0.1 password='S3c\'ret x' port=abc`,
			secret: "ret x",
			want:   "invalid port",
		},
		{
			name:   "keyword parse error quoting the input",
			dsn:    "host=127.0.0.1 password S3cret",
			secret: "S3cret",
			want:   "failed to parse as keyword/value",
		},
		{
			name:   "upper case keyword",
			dsn:    "host=127.0.0.1 PASSWORD=S3cret port=abc",
			secret: "S3cret",
		},
		{
			name:   "unescaped at sign in URL",
			dsn:    "postgres://admin:S3c@ret@h:bad/db",
			secret: "ret",
			want:   "invalid port",
		},
		{
			name:   "URL with invalid port",
			dsn:    "postgres://admin:S3cret@h:99999999/db",
			secret: "S3cret",
			want:   "invalid port",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Open(t.Context(), tt.dsn)
			if err == nil {
				t.Fatal("Open succeeded")
			}
			msg := err.Error()
			if strings.Contains(msg, tt.secret) || strings.Contains(msg, tt.dsn) {
				t.Errorf("error leaks the password: %s", msg)
			}
			if !strings.HasPrefix(msg, "parse postgres dsn: invalid connection string") || !strings.Contains(msg, tt.want) {
				t.Errorf("error = %q, want it to mention %q", msg, tt.want)
			}
		})
	}
}

func TestParseConfigDefaults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		dsn         string
		wantTimeout time.Duration
	}{
		{"default timeout", "postgres://u@h/db?options=-c%20standard_conforming_strings%3Doff", defaultConnectTimeout},
		{"explicit timeout", "postgres://u@h/db?connect_timeout=3", 3 * time.Second},
		{"keyword form", "host=h user=u", defaultConnectTimeout},
		{"client encoding overridden", "postgres://u@h/db?client_encoding=SQL_ASCII", defaultConnectTimeout},
		{"client encoding in keyword form", "host=h user=u client_encoding=LATIN1", defaultConnectTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := parseConfig(tt.dsn)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.ConnectTimeout != tt.wantTimeout {
				t.Errorf("ConnectTimeout = %v, want %v", cfg.ConnectTimeout, tt.wantTimeout)
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
	_, err = Open(t.Context(), "postgres://u:pw@"+ln.Addr().String()+"/postgres?sslmode=prefer&connect_timeout=1")
	if err == nil {
		t.Fatal("Open() succeeded")
	}
	if n := strings.Count(err.Error(), ln.Addr().String()+" ("); n != 1 {
		t.Errorf("Open() error names the host %d times: %v", n, err)
	}
}
