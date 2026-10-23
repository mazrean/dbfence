package postgres

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
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
		if got := Literal(tt.in); got != tt.want {
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
