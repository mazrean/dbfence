package config

import (
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/secret"
)

// TestDiagnosticsMaskSecrets checks the error text itself, before the
// output sink redacts registered secrets: the source snippets must not
// show literal passwords or DSNs that were never registered.
func TestDiagnosticsMaskSecrets(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, src, leaked, shown string
	}{
		{
			name:   "password with an unknown interpolation",
			src:    pgConn + "user \"app\" {\n  password = \"Zq9pLx${word}Tk\"\n}\n",
			leaked: "Zq9pLx",
			shown:  "password =****",
		},
		{
			name:   "unterminated password string",
			src:    pgConn + "user \"app\" {\n  password = \"Kw7rNbVm3x\n}\n",
			leaked: "Kw7rNbVm3x",
			shown:  "password =****",
		},
		{
			name:   "dsn with an error after the literal",
			src:    "connection {\n  engine = \"postgres\"\n  dsn    = \"postgres://u:Hj4tPq8sWe@h/d\" + 1\n}\n",
			leaked: "Hj4tPq8sWe",
			shown:  "dsn    =****",
		},
		{
			name:   "valid password, another attribute of the line wrong",
			src:    pgConn + "user \"app\" { password = \"Rf5gYu2iOp\", login = \"maybe\" }\n",
			leaked: "Rf5gYu2iOp",
			shown:  `user "app" { password =****`,
		},
		{
			name:   "heredoc password body",
			src:    pgConn + "user \"app\" {\n  password = <<EOT\n${nope}Hx7kLm2pQz\nEOT\n}\n",
			leaked: "Hx7kLm2pQz",
			shown:  "****",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := load(t, tt.src)
			if err == nil {
				t.Fatal("Load succeeded, want an error")
			}
			if strings.Contains(err.Error(), tt.leaked) {
				t.Errorf("error shows %q:\n%s", tt.leaked, err)
			}
			if !strings.Contains(err.Error(), tt.shown) {
				t.Errorf("error does not show the masked source %q:\n%s", tt.shown, err)
			}
		})
	}
}

func TestMaskSecrets(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, want string
	}{
		{name: "password", in: `  password = "abc"`, want: `  password =******`},
		{name: "dsn keeps the line break", in: "dsn=\"x\"\r\nengine = 1\n", want: "dsn=***\r\nengine = 1\n"},
		{name: "quoted key", in: `{ "password" = "abc" }`, want: `{ "password" =********`},
		{name: "first assignment masks the rest of the line", in: `user "a" { password = "x", login = true }`, want: `user "a" { password =********************`},
		{name: "comparison is not an assignment", in: `x = password == "abc"`, want: `x = password == "abc"`},
		{name: "other names", in: "password_hash = \"a\"\nmy-dsn = \"b\"\nold_password = \"c\"\n", want: "password_hash = \"a\"\nmy-dsn = \"b\"\nold_password = \"c\"\n"},
		{name: "heredoc", in: "password = <<-EOT\n  secret\n  EOT\nlogin = true\n", want: "password =*******\n********\n  EOT\nlogin = true\n"},
		{name: "unterminated heredoc", in: "dsn = <<EOT\nsecret\n", want: "dsn =******\n******\n"},
		{name: "multi-byte characters keep their byte length", in: "password = \"é\"", want: "password =*****"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := string(maskSecrets([]byte(tt.in)))
			if got != tt.want {
				t.Errorf("maskSecrets(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if len(got) != len(tt.in) {
				t.Errorf("maskSecrets changed the length: %d, want %d", len(got), len(tt.in))
			}
		})
	}
}

// TestRegisterLiteralSecrets checks that literal values are registered
// even when Load fails before decoding them.
func TestRegisterLiteralSecrets(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, src  string
		registered []string
		visible    []string
	}{
		{
			name:       "password in a block that fails to parse",
			src:        pgConn + "user \"app\" { password = \"Ty6uIo9pAs\", login = \"maybe\" }\n",
			registered: []string{"Ty6uIo9pAs"},
		},
		{
			name:       "password in a block that fails to decode",
			src:        pgConn + "user \"app\" {\n  password = \"Nm4bVc7xZl\"\n  login = \"maybe\"\n}\n",
			registered: []string{"Nm4bVc7xZl"},
		},
		{
			name:       "literal parts of a password template",
			src:        pgConn + "user \"app\" {\n  password = \"Gh3jKl5zXc${nope}\"\n}\n",
			registered: []string{"Gh3jKl5zXc"},
		},
		{
			name:       "dsn literal and its URL password",
			src:        "connection {\n  engine = \"postgres\"\n  dsn    = \"postgres://u:Vb6nMq1wEr@h/d\"\n}\nuser \"app\" { login = \"maybe\" }\n",
			registered: []string{"postgres://u:Vb6nMq1wEr@h/d", "Vb6nMq1wEr"},
		},
		{
			name:    "text around a lookup in a dsn",
			src:     "connection {\n  engine = \"postgres\"\n  dsn    = \"postgres://dsnuser:${env(\"PW\")}@dsnhost/d\"\n}\nuser \"app\" { login = \"maybe\" }\n",
			visible: []string{"postgres://dsnuser:", "@dsnhost/d"},
		},
		{
			name:    "function arguments name secrets",
			src:     pgConn + "user \"app\" {\n  password = env(\"LOOKUP_NAME_ONLY\")\n  login = \"maybe\"\n}\n",
			visible: []string{"LOOKUP_NAME_ONLY"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := load(t, tt.src); err == nil {
				t.Fatal("Load succeeded, want an error")
			}
			for _, s := range tt.registered {
				if got := secret.Default().Redact(s); got != secret.Placeholder {
					t.Errorf("%q is not registered: Redact = %q", s, got)
				}
			}
			for _, s := range tt.visible {
				if got := secret.Default().Redact(s); got != s {
					t.Errorf("%q is registered: Redact = %q", s, got)
				}
			}
		})
	}
}
