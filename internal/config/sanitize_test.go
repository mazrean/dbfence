package config

import (
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/secret"
)

// TestDiagnosticsMaskSecrets checks the error text itself, before the
// output sink redacts registered secrets: the source snippets must not
// show literal passwords that were never registered.
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
			name:   "connection password with an error after the literal",
			src:    "connection {\n  engine   = \"postgres\"\n  host     = \"h\"\n  user     = \"u\"\n  password = \"postgres://u:Hj4tPq8sWe@h/d\" + 1\n}\n",
			leaked: "Hj4tPq8sWe",
			shown:  "password =****",
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
			name:   "connection multi-line password format, unknown variable",
			src:    "connection {\n  engine   = \"postgres\"\n  host     = \"h\"\n  user     = \"u\"\n  password = format(\n    \"postgres://u:Ee1Lp3sWq9@h/d${nope}\"\n  )\n}\n",
			leaked: "Ee1Lp3sWq9",
			shown:  "****",
		},
		{
			name:   "multi-line list index, unknown variable",
			src:    pgConn + "user \"app\" {\n  password = [\n    \"Ff1Gt5yHn7${nope}\"\n  ][0]\n}\n",
			leaked: "Ff1Gt5yHn7",
			shown:  "****",
		},
		{
			name:   "connection password interpolation across lines, parse error",
			src:    "connection {\n  engine   = \"postgres\"\n  host     = \"h\"\n  user     = \"u\"\n  password = \"postgres://${\n    \"app\"\n  }:Rr9DsnPw7@h/d\" 1\n}\n",
			leaked: "Rr9DsnPw7",
			shown:  "****",
		},
		{
			name:   "connection password interpolation across lines, unknown variable",
			src:    "connection {\n  engine   = \"postgres\"\n  host     = \"h\"\n  user     = \"u\"\n  password = \"postgres://${\n    \"app\"\n  }:Rr8DsnPw7@h/${nope}\"\n}\n",
			leaked: "Rr8DsnPw7",
			shown:  "****",
		},
		{
			name:   "password interpolation across lines, parse error",
			src:    pgConn + "user \"app\" {\n  password = \"Hh1Xy${\n    1 +\n  }Zz9Qw8Er7\"\n}\n",
			leaked: "Zz9Qw8Er7",
			shown:  "****",
		},
		{
			name:   "literal argument after an interpolation across lines, parse error",
			src:    pgConn + "user \"app\" {\n  password = format(\"%s%s\", \"Jj1${\n 1}\",\n \"Jj2SecretTail9\" 1)\n}\n",
			leaked: "Jj2SecretTail9",
			shown:  "****",
		},
		{
			name:   "password on the line after =",
			src:    pgConn + "user \"app\" {\n  password =\n    \"Qq1NextLinePw9\"\n}\n",
			leaked: "Qq1NextLinePw9",
			shown:  "****",
		},
		{
			name:   "quoted string continued on the next line",
			src:    pgConn + "user \"app\" {\n  password = \"Qq2a\nQq2SecondLinePw9\"\n}\n",
			leaked: "Qq2SecondLinePw9",
			shown:  "****",
		},
		{
			name:   "block comment closes no bracket, parse error",
			src:    pgConn + "user \"app\" {\n  password = format( /* ) */\n    \"Qq3CommentPw9\" 1)\n}\n",
			leaked: "Qq3CommentPw9",
			shown:  "****",
		},
		{
			name:   "block comment closes no bracket, unknown variable",
			src:    pgConn + "user \"app\" {\n  password = format( /* ) */\n    \"Qq4CommentPw9${nope}\")\n}\n",
			leaked: "Qq4CommentPw9",
			shown:  "****",
		},
		{
			name:   "connection password on the line after =",
			src:    "connection {\n  engine   = \"postgres\"\n  host     = \"h\"\n  user     = \"u\"\n  password =\n    \"postgres://u:Qq5NextDsnPw9@h/d\"\n}\n",
			leaked: "Qq5NextDsnPw9",
			shown:  "****",
		},
		{
			name:   "continued string line that looks like an attribute",
			src:    pgConn + "user \"app\" {\n  password = \"part1\nHh1Key=Hh1ValueSecret9\"\n}\n",
			leaked: "Hh1ValueSecret9",
		},
		{
			name:   "continued string line that looks like a closing brace",
			src:    pgConn + "user \"app\" {\n  password = \"part1\n}Gg2ClosingSecret9\"\n}\n",
			leaked: "Gg2ClosingSecret9",
		},
		{
			name:   "multi-line block comment between = and the value",
			src:    pgConn + "user \"app\" {\n  password = /*\n */ \"Qq6BlkCmtPw9\" 1\n}\n",
			leaked: "Qq6BlkCmtPw9",
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
			if !parses("dbfence.hcl", []byte(tt.src)) {
				// Files that do not parse are quoted without source.
				if !strings.Contains(err.Error(), " line ") || strings.Contains(err.Error(), "*") {
					t.Errorf("error of a file that does not parse should name the line and quote no source:\n%s", err)
				}
				return
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
		{name: "password keeps the line break", in: "password=\"x\"\r\nengine = 1\n", want: "password=***\r\nengine = 1\n"},
		{name: "quoted key", in: `{ "password" = "abc" }`, want: `{ "password" =********`},
		{name: "first assignment masks the rest of the line", in: `user "a" { password = "x", login = true }`, want: `user "a" { password =********************`},
		{name: "comparison is not an assignment", in: `x = password == "abc"`, want: `x = password == "abc"`},
		{name: "other names", in: "password_hash = \"a\"\nmy-password = \"b\"\nold_password = \"c\"\n", want: "password_hash = \"a\"\nmy-password = \"b\"\nold_password = \"c\"\n"},
		{name: "heredoc", in: "password = <<-EOT\n  secret\n  EOT\nlogin = true\n", want: "password =*******\n********\n  EOT\nlogin = true\n"},
		{name: "unterminated heredoc", in: "password = <<EOT\nsecret\n", want: "password =******\n******\n"},
		{name: "multi-byte characters keep their byte length", in: "password = \"é\"", want: "password =*****"},
		{name: "multi-line call", in: "password = format(\n  \"a\",\n  \")\"\n)\nlogin = true\n", want: "password =********\n******\n*****\n*\nlogin = true\n"},
		{name: "heredoc inside a call", in: "password = trimspace(<<EOT\nsecret\nEOT\n)\nx = 1\n", want: "password =****************\n******\nEOT\n*\nx = 1\n"},
		{name: "brackets of a one-line block", in: "user \"a\" { password = \"x\" }\nlogin = true\n", want: "user \"a\" { password =******\nlogin = true\n"},
		{name: "brackets in a comment", in: "password = \"x\" # (\nlogin = true\n", want: "password =********\nlogin = true\n"},
		{name: "unclosed bracket masks the rest", in: "password = format(\nx = 1\n", want: "password =********\n*****\n"},
		{name: "interpolation across lines", in: "password = \"a${\n  b\n}c\"\nx = 1\n", want: "password =*****\n***\n***\nx = 1\n"},
		{name: "template directive across lines", in: "password = \"a%{ if\n  true }b%{ endif }\"\nx = 1\n", want: "password =********\n********************\nx = 1\n"},
		{name: "escaped interpolation", in: "password = \"a$${\"\nx = 1\n", want: "password =*******\nx = 1\n"},
		{name: "interpolation in a heredoc", in: "password = <<EOT\na${\nEOT\n}\nEOT\nx = 1\n", want: "password =******\n***\n***\n*\nEOT\nx = 1\n"},
		{name: "unterminated string inside an interpolation", in: "password = \"a${\"b\n}\"\nx = 1\n", want: "password =*******\n**\nx = 1\n"},
		{name: "value on the next line", in: "password =\n  \"abc\"\nx = 1\n", want: "password =\n*******\nx = 1\n"},
		{name: "blank and comment lines before the value", in: "password =\n\n# c\n  \"abc\"\n}\n", want: "password =\n\n***\n*******\n}\n"},
		{name: "string broken across lines", in: "password = \"a\nbc\"\nx = 1\n", want: "password =***\n***\nx = 1\n"},
		{name: "continuation ends at a block header", in: "password = \"a\"\nuser \"b\" {\n", want: "password =****\nuser \"b\" {\n"},
		{name: "continuation ends at a quoted key", in: "password = \"a\"\n\"login\" = true\n", want: "password =****\n\"login\" = true\n"},
		{name: "comparison does not end the continuation", in: "password =\n  x == \"abc\"\n}\n", want: "password =\n************\n}\n"},
		{name: "brackets in a block comment", in: "password = f( /* ) */\n  \"a\")\nx = 1\n", want: "password =***********\n******\nx = 1\n"},
		{name: "block comment across lines", in: "password = /*\n*/ \"a\"\nx = 1\n", want: "password =***\n******\nx = 1\n"},
		{name: "next assignment is masked after a continuation", in: "password =\n  \"a\"\npassword = \"b\"\nx = 1\n", want: "password =\n*****\npassword =****\nx = 1\n"},
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
			name:       "connection password",
			src:        "connection {\n  engine   = \"postgres\"\n  host     = \"h\"\n  user     = \"u\"\n  password = \"Vb6nMq1wEr\"\n}\nuser \"app\" { login = \"maybe\" }\n",
			registered: []string{"Vb6nMq1wEr"},
		},
		{
			name:       "literals in nested expressions",
			src:        pgConn + "user \"app\" {\n  password = format(\n    [\"Ff1Gt5yHn7${nope}\"][0], true ? \"Kk2Lm4Np6q\" : \"x\"\n  )\n}\n",
			registered: []string{"Ff1Gt5yHn7", "Kk2Lm4Np6q"},
		},
		{
			name:       "password of a tfstate URL on another attribute",
			src:        pgConn + "database \"app\" {\n  name = tfstate(\"https://u:Gg1TfTok9q@h/x.tfstate\", \"out${nope}\")\n}\n",
			registered: []string{"Gg1TfTok9q"},
			visible:    []string{"https://u:", "@h/x.tfstate"},
		},
		{
			name:       "tfstate URL token as the username",
			src:        pgConn + "database \"app\" {\n  name = tfstate(\"https://Tk1UserTok9q@h/x.tfstate\", \"out${nope}\")\n}\n",
			registered: []string{"Tk1UserTok9q"},
			visible:    []string{"https://", "@h/x.tfstate"},
		},
		{
			name:       "tfstate URL token in the query",
			src:        pgConn + "database \"app\" {\n  name = tfstate(\"https://h/x.tfstate?token=Tk2QueryTok9q&v=Tk4Sig%2F9q\", \"out${nope}\")\n}\n",
			registered: []string{"Tk2QueryTok9q", "token=Tk2QueryTok9q&v=Tk4Sig%2F9q", "Tk4Sig/9q"},
			visible:    []string{"https://h/x.tfstate"},
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
