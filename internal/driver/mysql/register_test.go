package mysql

import (
	"testing"

	"github.com/mazrean/dbfence/internal/secret"
)

func TestParseDSNRegistersPassword(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		dsn  string
		pw   string
	}{
		{name: "tcp", dsn: "u:my-dsn-pw@tcp(h:3306)/", pw: "my-dsn-pw"},
		{name: "password with a slash", dsn: "u:my/slash/pw@tcp(h:3306)/db", pw: "my/slash/pw"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseDSN(tt.dsn); err != nil {
				t.Fatal(err)
			}
			if got := secret.Default().Redact(tt.pw); got != secret.Placeholder {
				t.Errorf("Redact(%q) = %q, want the DSN password registered", tt.pw, got)
			}
		})
	}
}
