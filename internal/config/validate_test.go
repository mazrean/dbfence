package config

import (
	"strings"
	"testing"
)

// Both connection blocks end on line 4, so content after them starts on line 5.
const (
	pgConn = "connection {\n engine = \"postgres\"\n dsn = \"x\"\n}\n"
	myConn = "connection {\n engine = \"mysql\"\n dsn = \"x\"\n}\n"
)

type diagCase struct {
	name, src string
	want      []string
	deny      []string
	count     int
}

func runDiagCases(t *testing.T, tests []diagCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := load(t, tt.src)
			if err == nil {
				t.Fatal("Load() succeeded")
			}
			msg := err.Error()
			for _, w := range tt.want {
				if !strings.Contains(msg, w) {
					t.Errorf("error does not contain %q:\n%s", w, msg)
				}
			}
			for _, w := range tt.deny {
				if strings.Contains(msg, w) {
					t.Errorf("error contains %q:\n%s", w, msg)
				}
			}
			if got := 1 + strings.Count(msg, "Error: "); got != tt.count {
				t.Errorf("%d diagnostics, want %d:\n%s", got, tt.count, msg)
			}
		})
	}
}

// TestLoadDiagnostics checks the diagnostics of invalid configurations: how
// many there are, what they say and that they point at the right line.
func TestLoadDiagnostics(t *testing.T) {
	t.Parallel()
	runDiagCases(t, []diagCase{
		{
			name:  "unsupported engine points at engine",
			src:   "connection {\n dsn = \"x\"\n engine = \"Postgres\"\n}\n",
			want:  []string{"Unsupported engine", "dbfence.hcl line 3"},
			count: 1,
		},
		{
			name:  "duplicate connection names the first",
			src:   pgConn + pgConn,
			want:  []string{"dbfence.hcl line 5", "the first one is at", "dbfence.hcl:1,1"},
			count: 1,
		},
		{
			name:  "duplicate label names the first and the shared namespace",
			src:   pgConn + "role \"a\" {}\nuser \"a\" {}\n",
			want:  []string{"dbfence.hcl line 6", `role "a" at`, "dbfence.hcl:5,6", "share a namespace"},
			count: 1,
		},
		{
			name:  "duplicate database label",
			src:   pgConn + "database \"d\" {}\ndatabase \"d\" {}\n",
			want:  []string{"dbfence.hcl line 6", `database "d" at`},
			count: 1,
		},
		{
			name:  "errors of later blocks are not hidden",
			src:   myConn + "database \"a\" { owner = \"x\" }\ndatabase \"b\" { encoding = \"UTF8\" }\nignore { roles = [\"(bad\"] }\n",
			want:  []string{`"owner" is only supported`, `"encoding" is only supported`, "Invalid ignore pattern"},
			count: 3,
		},
		{
			name:  "engine-only attribute points at the attribute",
			src:   pgConn + "database \"app\" {\n  encoding = \"UTF8\"\n  charset = \"utf8\"\n}\n",
			want:  []string{"dbfence.hcl line 7", `"charset" is only supported for mysql`},
			count: 1,
		},
		{
			name:  "ignore pattern points at its attribute",
			src:   pgConn + "ignore {\n  roles = [\"ok\"]\n  schemas = [\"a(\"]\n}\n",
			want:  []string{"dbfence.hcl line 7", "schemas pattern"},
			count: 1,
		},
		{
			name:  "ignore pattern is anchored like diff",
			src:   pgConn + "ignore { roles = [\"\\\\Qrds_\"] }\n",
			want:  []string{"Invalid ignore pattern"},
			count: 1,
		},
		{
			name:  "ignore schemas on mysql",
			src:   myConn + "ignore { schemas = [\"x\"] }\n",
			want:  []string{`"schemas" is only supported for postgres`},
			count: 1,
		},
		{
			name:  "invalid privilege points at privileges",
			src:   pgConn + "role \"r\" {}\ndatabase \"d\" {}\ngrant {\n  role = role.r.id\n  database = database.d.name\n  privileges = [\"SELECT\"]\n}\n",
			want:  []string{"dbfence.hcl line 10", `privilege "SELECT" is not valid`},
			count: 1,
		},
		{
			name:  "duplicate name points at the second block",
			src:   pgConn + "database \"d1\" { name = \"same\" }\ndatabase \"d2\" { name = \"same\" }\n",
			want:  []string{"dbfence.hcl line 6", `database "same" (block "d2") is declared more than once`, `database "d1" at`},
			count: 1,
		},
		{
			name:  "role name clash across role and user",
			src:   pgConn + "role \"a\" { name = \"x\" }\nuser \"x\" {}\n",
			want:  []string{"dbfence.hcl line 6", `role "x" (user "x") is declared more than once`, `role "a" at`},
			count: 1,
		},
		{
			name:  "undeclared grant role points at role",
			src:   pgConn + "database \"d\" {}\ngrant {\n  database = database.d.name\n  role = \"ap\"\n  privileges = [\"CONNECT\"]\n}\n",
			want:  []string{"dbfence.hcl line 8", `role "ap", which is not declared`},
			count: 1,
		},
		{
			name:  "undeclared schema database points at database",
			src:   pgConn + "schema \"s\" {\n  database = \"nope\"\n}\n",
			want:  []string{"dbfence.hcl line 6", `database "nope", which is not declared`},
			count: 1,
		},
		{
			name: "overlapping ALL grants are reported once",
			src: myConn + "user \"u\" {}\ndatabase \"app\" {}\n" +
				"grant {\n  role = user.u.id\n  database = database.app.name\n  privileges = [\"ALL\"]\n}\n" +
				"grant {\n  role = user.u.id\n  database = database.app.name\n  privileges = [\"ALL\"]\n}\n",
			want:  []string{"Duplicate privilege", "dbfence.hcl line 15", "privileges ALTER, ALTER ROUTINE", "dbfence.hcl:7,1"},
			count: 1,
		},
		{
			name: "pg overlap with a different grant option has a hint",
			src: pgConn + "role \"r\" {}\ndatabase \"d\" {}\n" +
				"grant {\n  role = role.r.id\n  database = database.d.name\n  privileges = [\"ALL\"]\n}\n" +
				"grant {\n  role = role.r.id\n  database = database.d.name\n  privileges = [\"CONNECT\"]\n  with_grant_option = true\n}\n",
			want:  []string{"privilege CONNECT is already granted", "list them in their own grant block"},
			count: 1,
		},
		{
			name: "mysql grant option is per database",
			src: myConn + "user \"u\" {}\ndatabase \"app\" {}\n" +
				"grant {\n  role = user.u.id\n  database = database.app.name\n  privileges = [\"SELECT\"]\n}\n" +
				"grant {\n  role = user.u.id\n  database = database.app.name\n  privileges = [\"INSERT\"]\n  with_grant_option = true\n}\n",
			want:  []string{"Conflicting grant option", "dbfence.hcl line 16", "dbfence.hcl:7,1 uses false"},
			count: 1,
		},
	})
}

func TestLoadGrantOptionSplit(t *testing.T) {
	t.Parallel()
	// PostgreSQL keeps the grant option per privilege; MySQL accepts
	// several blocks per database when they agree on it.
	for _, src := range []string{
		pgConn + "role \"r\" {}\ndatabase \"d\" {}\n" +
			"grant {\n role = role.r.id\n database = database.d.name\n privileges = [\"CONNECT\"]\n}\n" +
			"grant {\n role = role.r.id\n database = database.d.name\n privileges = [\"CREATE\"]\n with_grant_option = true\n}\n",
		myConn + "role \"r\" {}\ndatabase \"d\" {}\n" +
			"grant {\n role = role.r.id\n database = database.d.name\n privileges = [\"SELECT\"]\n with_grant_option = true\n}\n" +
			"grant {\n role = role.r.id\n database = database.d.name\n privileges = [\"INSERT\"]\n with_grant_option = true\n}\n",
	} {
		if _, err := load(t, src); err != nil {
			t.Errorf("Load() error = %v", err)
		}
	}
}
