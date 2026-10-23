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
		{
			name:   "heredoc inside a function call, unknown variable",
			src:    pgConn + "user \"app\" {\n  password = trimspace(<<EOT\nBb1Hx7kLm2pQz${nope}\nEOT\n  )\n}\n",
			leaked: "Bb1Hx7kLm2pQz",
			shown:  "****",
		},
		{
			name:   "heredoc inside a function call, parse error",
			src:    pgConn + "user \"app\" {\n  password = trimspace(<<EOT\nBb2Hx7kLm2pQz${\nEOT\n  )\n}\n",
			leaked: "Bb2Hx7kLm2pQz",
			shown:  "****",
		},
		{
			name:   "multi-line function call, unknown variable",
			src:    pgConn + "user \"app\" {\n  password = format(\n    \"Cc1Qm4vRt8z${nope}\"\n  )\n}\n",
			leaked: "Cc1Qm4vRt8z",
			shown:  "****",
		},
		{
			name:   "multi-line parentheses, parse error",
			src:    pgConn + "user \"app\" {\n  password = (\n    \"Dd1Pw9xTnQ2\" 1\n  )\n}\n",
			leaked: "Dd1Pw9xTnQ2",
			shown:  "****",
		},
		{
			name:   "multi-line dsn format, unknown variable",
			src:    "connection {\n  engine = \"postgres\"\n  dsn    = format(\n    \"postgres://u:Ee1Lp3sWq9@h/d${nope}\"\n  )\n}\n",
			leaked: "Ee1Lp3sWq9",
			shown:  "****",
		},
		{
			name:   "multi-line list index, unknown variable",
			src:    pgConn + "user \"app\" {\n  password = [\n    \"Ff1Gt5yHn7${nope}\"\n  ][0]\n}\n",
			leaked: "Ff1Gt5yHn7",
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
		{name: "multi-line call", in: "password = format(\n  \"a\",\n  \")\"\n)\nlogin = true\n", want: "password =********\n******\n*****\n*\nlogin = true\n"},
		{name: "heredoc inside a call", in: "dsn = trimspace(<<EOT\nsecret\nEOT\n)\nx = 1\n", want: "dsn =****************\n******\nEOT\n*\nx = 1\n"},
		{name: "brackets of a one-line block", in: "user \"a\" { password = \"x\" }\nlogin = true\n", want: "user \"a\" { password =******\nlogin = true\n"},
		{name: "brackets in a comment", in: "password = \"x\" # (\nlogin = true\n", want: "password =********\nlogin = true\n"},
		{name: "unclosed bracket masks the rest", in: "password = format(\nx = 1\n", want: "password =********\n*****\n"},
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
			name:       "literals in nested expressions",
			src:        pgConn + "user \"app\" {\n  password = format(\n    [\"Ff1Gt5yHn7${nope}\"][0], true ? \"Kk2Lm4Np6q\" : \"x\"\n  )\n}\n",
			registered: []string{"Ff1Gt5yHn7", "Kk2Lm4Np6q"},
		},
		{
			name:       "URL password in a dsn template",
			src:        "connection {\n  engine = \"postgres\"\n  dsn    = format(\"postgres://u:Ee1Lp3sWq9@h/d${nope}\")\n}\n",
			registered: []string{"Ee1Lp3sWq9"},
		},
		{
			name:       "password of a tfstate URL on another attribute",
			src:        pgConn + "database \"app\" {\n  name = tfstate(\"https://u:Gg1TfTok9q@h/x.tfstate\", \"out${nope}\")\n}\n",
			registered: []string{"Gg1TfTok9q"},
			visible:    []string{"https://u:", "@h/x.tfstate"},
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
