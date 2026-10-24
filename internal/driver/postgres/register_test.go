package postgres

import (
	"testing"

	"github.com/mazrean/dbfence/internal/secret"
)

func TestParseConfigRegistersPassword(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		dsn  string
		pw   string
	}{
		{name: "URL", dsn: "postgres://u:pg-url-pw%2Fx@h/db", pw: "pg-url-pw/x"},
		{name: "keyword form", dsn: "host=h user=u password='pg kw pw'", pw: "pg kw pw"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseConfig(tt.dsn); err != nil {
				t.Fatal(err)
			}
			if got := secret.Default().Redact(tt.pw); got != secret.Placeholder {
				t.Errorf("Redact(%q) = %q, want the DSN password registered", tt.pw, got)
			}
		})
	}
}

func TestParseConfigKeepsNamesEqualToThePassword(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, dsn, shown string }{
		{name: "user", dsn: "postgres://pguser7:pguser7@h/db", shown: "pguser7"},
		{name: "database", dsn: "postgres://u:pgdb7x@h/pgdb7x", shown: "pgdb7x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseConfig(tt.dsn); err != nil {
				t.Fatal(err)
			}
			if got := secret.Default().Redact(tt.shown); got != tt.shown {
				t.Errorf("Redact(%q) = %q, want it shown: it is a name of the connection", tt.shown, got)
			}
		})
	}
}
