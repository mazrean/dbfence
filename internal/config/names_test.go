package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mazrean/dbfence/internal/model"
	"github.com/zclconf/go-cty/cty/function"
)

func TestLoadRejectsControlCharacters(t *testing.T) {
	t.Parallel()
	const msg = "must not contain control characters"
	runDiagCases(t, []diagCase{
		{
			name:  "C0 in role name",
			src:   pgConn + "role \"r\" {\n name = \"a\\u0001b\"\n}\n",
			want:  []string{"Invalid name", "role name " + msg, "dbfence.hcl line 6"},
			count: 1,
		},
		{
			name:  "newline in database name",
			src:   pgConn + "database \"d\" {\n name = \"a\\nb\"\n}\n",
			want:  []string{"database name " + msg},
			count: 1,
		},
		{
			name:  "DEL in owner",
			src:   pgConn + "database \"d\" {\n owner = \"o\\u007f\"\n}\n",
			want:  []string{"owner " + msg},
			count: 1,
		},
		{
			name:  "C1 in schema name",
			src:   pgConn + "database \"d\" {}\nschema \"s\" {\n database = \"d\"\n name = \"x\\u0085\"\n}\n",
			want:  []string{"schema name " + msg},
			count: 1,
		},
		{
			name:  "control character in member_of",
			src:   pgConn + "role \"r\" {\n member_of = [\"g\\tx\"]\n}\n",
			want:  []string{"member_of entry " + msg},
			count: 1,
		},
		{
			name:  "control character in a MySQL host",
			src:   myConn + "user \"u\" {\n host = \"h\\u0000\"\n}\n",
			want:  []string{"host " + msg},
			count: 1,
		},
		{
			name:  "control character in a grant role",
			src:   pgConn + "database \"d\" {}\ngrant {\n role = \"r\\r\"\n database = \"d\"\n privileges = [\"CONNECT\"]\n}\n",
			want:  []string{"role " + msg},
			count: 2, // also an undeclared role
		},
	})
}

// fuzzSeeds are configurations the HCL fuzz target starts from.
var fuzzSeeds = []string{
	pgConn,
	myConn,
	pgConn + `database "app" { owner = role.app.name }
role "app" { login = true, password = "pw", member_of = [role.g.name] }
role "g" {}
schema "s" { database = database.app.name, owner = role.app.name }
grant { role = role.app.name, database = database.app.name, privileges = ["CONNECT"] }
grant { role = "PUBLIC", database = database.app.name, privileges = [] }
ignore { roles = ["tmp_.*"], databases = ["x"], schemas = ["app\\..*"] }
`,
	myConn + `database "app" { charset = "utf8mb4" }
user "u" { host = "10.0.%", member_of = ["r@%"], auth_plugin = "caching_sha2_password" }
role "r" {}
grant { role = user.u.id, database_pattern = "app\\_%", privileges = ["SELECT"], with_grant_option = true }
`,
	pgConn + "role \"r\" {\n name = \"a\\u0001b\"\n}\n",
	"connection {",
}

// FuzzLoad loads arbitrary single-file configurations. No function is
// available, so nothing reaches the network or the environment. Load must
// not panic, and an accepted configuration has no control characters in
// any name.
func FuzzLoad(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	// Inputs run one at a time in each fuzzing process, so they share
	// one file.
	path := filepath.Join(f.TempDir(), "dbfence.hcl")
	f.Fuzz(func(t *testing.T, src string) {
		// The parser is not what is under test here; skip inputs it
		// would spend all the time on.
		if len(src) > 1<<14 {
			t.Skip()
		}
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(path, map[string]function.Function{})
		if err != nil {
			return
		}
		d := cfg.Desired
		var names []string
		for _, db := range d.Databases {
			names = append(names, db.Name, db.Owner)
		}
		for _, r := range d.Roles {
			names = append(names, r.ID.Name, r.ID.Host)
			for _, m := range r.MemberOf {
				names = append(names, m.Name, m.Host)
			}
		}
		for _, s := range d.Schemas {
			names = append(names, s.Database, s.Name, s.Owner)
		}
		for _, p := range d.Privileges {
			names = append(names, p.Grantee.Name, p.Grantee.Host, p.Object.Database, p.Object.Schema, p.Object.Pattern)
		}
		for _, n := range names {
			if model.HasControl(n) {
				t.Errorf("accepted name %q with a control character", n)
			}
		}
	})
}
