package config

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mazrean/dbfence/internal/model"
)

func TestLoadSchemaDatabaseReferences(t *testing.T) {
	t.Parallel()
	// schema.b.database refers to a schema declared later.
	cfg, err := load(t, pgConn+`database "app" {}
role "r" {}
grant {
  role       = role.r.id
  database   = schema.b.database
  schema     = schema.b.name
  privileges = ["USAGE"]
}
schema "b" { database = schema.a.database }
schema "a" { database = database.app.name }
`)
	if err != nil {
		t.Fatal(err)
	}
	want := []model.Schema{{Database: "app", Name: "b"}, {Database: "app", Name: "a"}}
	if diff := cmp.Diff(want, cfg.Desired.Schemas); diff != "" {
		t.Errorf("schemas (-want +got):\n%s", diff)
	}
	if got := cfg.Desired.Privileges[0].Object.Database; got != "app" {
		t.Errorf("grant database = %q, want app", got)
	}
}

func TestLoadReferenceErrors(t *testing.T) {
	t.Parallel()
	runDiagCases(t, []diagCase{
		{
			name:  "schema database self reference",
			src:   pgConn + "database \"app\" {}\nschema \"a\" {\n  database = schema.a.database\n}\n",
			want:  []string{"Cyclic reference", `schema "a"`, "dbfence.hcl line 7"},
			count: 1,
		},
		{
			name:  "schema database cycle",
			src:   pgConn + "schema \"a\" { database = schema.b.database }\nschema \"b\" { database = schema.a.database }\n",
			want:  []string{"Cyclic reference"},
			count: 2,
		},
		{
			name:  "schema database typo",
			src:   pgConn + "database \"app\" {}\nschema \"a\" { database = database.ap.name }\n",
			want:  []string{"Unsupported attribute", `attribute named "ap"`},
			count: 1,
		},
		{
			name:  "name references another block",
			src:   pgConn + "database \"app\" {}\nrole \"r\" {\n  name = \"${database.app.name}_owner\"\n}\n",
			want:  []string{"References not allowed", "name cannot reference other blocks", "dbfence.hcl line 7"},
			count: 1,
		},
		{
			name:  "host references another block",
			src:   myConn + "role \"a\" {}\nrole \"r\" { host = role.a.host }\n",
			want:  []string{"host cannot reference other blocks"},
			count: 1,
		},
	})
}
