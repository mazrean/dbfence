package config

import (
	"strings"
	"testing"
)

func TestLoadAttributeValues(t *testing.T) {
	t.Parallel()
	long64 := strings.Repeat("a", 64)
	runDiagCases(t, []diagCase{
		{
			name:  "pg empty password",
			src:   pgConn + "user \"a\" {\n  password = \"\"\n}\n",
			want:  []string{"Empty password", `user "a" at`, "dbfence.hcl:6,1", "it clears the password"},
			deny:  []string{"password = "},
			count: 1,
		},
		{
			name:  "pg md5-looking password",
			src:   pgConn + "user \"a\" {\n  password = \"md5aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n}\n",
			want:  []string{"Password looks like a verifier", `user "a" at`},
			deny:  []string{"md5aaaa"},
			count: 1,
		},
		{
			name:  "pg scram-looking password",
			src:   pgConn + "user \"a\" {\n  password = \"SCRAM-SHA-256$4096:c2FsdA==$a:b\"\n}\n",
			want:  []string{"Password looks like a verifier"},
			deny:  []string{"c2FsdA"},
			count: 1,
		},
		{
			name:  "NUL in password is reported without the value",
			src:   myConn + "user \"a\" { password = \"secretA\\u0000tailsecret\" }\n",
			want:  []string{"must not contain NUL characters"},
			deny:  []string{"secretA", "tailsecret"},
			count: 1,
		},
		{
			name:  "connection_limit below -1",
			src:   pgConn + "user \"a\" {\n  connection_limit = -5\n}\n",
			want:  []string{"Invalid connection_limit", "dbfence.hcl line 7", "got -5"},
			count: 1,
		},
		{
			name:  "connection_limit above int32",
			src:   pgConn + "role \"a\" { connection_limit = 3000000000 }\n",
			want:  []string{"Invalid connection_limit", "got 3000000000"},
			count: 1,
		},
		{
			name:  "pg role name over 63 bytes",
			src:   pgConn + "role \"long\" {\n  name = \"" + long64 + "\"\n}\n",
			want:  []string{"Name too long", "dbfence.hcl line 7", "64 bytes long; postgres allows at most 63"},
			count: 1,
		},
		{
			name:  "pg multibyte database name over 63 bytes",
			src:   pgConn + "database \"" + strings.Repeat("é", 32) + "\" {}\n",
			want:  []string{"Name too long", "64 bytes"},
			count: 1,
		},
		{
			name:  "pg schema name over 63 bytes",
			src:   pgConn + "database \"d\" {}\nschema \"" + long64 + "\" { database = database.d.name }\n",
			want:  []string{"Name too long"},
			count: 1,
		},
		{
			name:  "pg reserved role names",
			src:   pgConn + "user \"public\" {}\nrole \"none\" {}\nrole \"pg_x\" {}\n",
			want:  []string{`user name "public" is reserved`, `role name "none" is reserved`, `role name "pg_x" is reserved`},
			count: 3,
		},
		{
			name:  "mysql user name over 32 characters",
			src:   myConn + "user \"" + strings.Repeat("u", 33) + "\" {}\n",
			want:  []string{"33 characters long; mysql allows at most 32"},
			count: 1,
		},
		{
			name:  "mysql database name over 64 characters",
			src:   myConn + "database \"" + strings.Repeat("d", 65) + "\" {}\n",
			want:  []string{"65 characters long; mysql allows at most 64"},
			count: 1,
		},
		{
			name:  "mysql host over 255 characters",
			src:   myConn + "user \"u\" {\n  host = \"" + strings.Repeat("h", 256) + "\"\n}\n",
			want:  []string{"dbfence.hcl line 7", "256 characters long; mysql allows at most 255"},
			count: 1,
		},
		{
			name:  "pg empty optional strings",
			src:   pgConn + "role \"o\" {}\ndatabase \"d\" {\n  owner = \"\"\n  encoding = \"\"\n}\nschema \"s\" {\n  database = database.d.name\n  owner = \"\"\n}\n",
			want:  []string{"owner must not be empty", "encoding must not be empty", "dbfence.hcl line 8", "dbfence.hcl line 13"},
			count: 3,
		},
		{
			name:  "mysql charset, collation and auth_plugin are identifiers",
			src:   myConn + "database \"d\" {\n  charset = \"utf8mb4; DROP\"\n  collation = \"\"\n}\nuser \"u\" {\n  auth_plugin = \"a b\"\n}\n",
			want:  []string{"Invalid charset", "Invalid collation", "Invalid auth_plugin", "dbfence.hcl line 7", "dbfence.hcl line 11"},
			count: 3,
		},
	})
}

func TestLoadAttributeValuesValid(t *testing.T) {
	t.Parallel()
	for _, src := range []string{
		pgConn + "role \"a\" { connection_limit = -1 }\nrole \"b\" { connection_limit = 2147483647 }\nrole \"" + strings.Repeat("a", 63) + "\" {}\nuser \"public_app\" { password = \"x\" }\n",
		myConn + "user \"u\" {\n  password = \"\"\n  auth_plugin = \"caching_sha2_password\"\n}\ndatabase \"d\" {\n  charset = \"utf8mb4\"\n  collation = \"utf8mb4_0900_ai_ci\"\n}\nuser \"" + strings.Repeat("é", 32) + "\" {}\n",
	} {
		if _, err := load(t, src); err != nil {
			t.Errorf("Load() error = %v", err)
		}
	}
}
