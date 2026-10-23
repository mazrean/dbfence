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
