package config

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mazrean/dbfence/internal/model"
)

func TestLoadPublicGrants(t *testing.T) {
	t.Parallel()
	db := model.Object{Type: model.ObjectDatabase, Database: "app"}
	api := model.Object{Type: model.ObjectSchema, Database: "app", Schema: "api"}
	tests := []struct {
		name        string
		src         string
		wantPrivs   []model.Privilege
		wantObjects []model.Object
	}{
		{
			name:        "upper case with privileges",
			src:         "grant {\n role = \"PUBLIC\"\n database = \"app\"\n privileges = [\"connect\", \"temp\"]\n}",
			wantPrivs:   []model.Privilege{{Grantee: model.PublicRole, Object: db, Name: "CONNECT"}, {Grantee: model.PublicRole, Object: db, Name: "TEMPORARY"}},
			wantObjects: []model.Object{db},
		},
		{
			name:        "lower case, empty privileges on a schema",
			src:         "grant {\n role = \"public\"\n database = \"app\"\n schema = \"api\"\n privileges = []\n}",
			wantObjects: []model.Object{api},
		},
		{
			name:        "two blocks on one object, with_grant_option = false",
			src:         "grant {\n role = \"Public\"\n database = \"app\"\n privileges = [\"CONNECT\"]\n with_grant_option = false\n}\ngrant {\n role = \"PUBLIC\"\n database = \"app\"\n privileges = [\"TEMPORARY\"]\n}",
			wantPrivs:   []model.Privilege{{Grantee: model.PublicRole, Object: db, Name: "CONNECT"}, {Grantee: model.PublicRole, Object: db, Name: "TEMPORARY"}},
			wantObjects: []model.Object{db},
		},
		{
			name:        "two empty blocks",
			src:         "grant {\n role = \"PUBLIC\"\n database = \"app\"\n privileges = []\n}\ngrant {\n role = \"PUBLIC\"\n database = \"app\"\n privileges = []\n}",
			wantObjects: []model.Object{db},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := load(t, pgConn+"database \"app\" {}\nschema \"api\" {\n database = \"app\"\n}\n"+tt.src)
			if err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(tt.wantPrivs, cfg.Desired.Privileges); d != "" {
				t.Errorf("Privileges (-want +got):\n%s", d)
			}
			if d := cmp.Diff(tt.wantObjects, cfg.Desired.PublicObjects); d != "" {
				t.Errorf("PublicObjects (-want +got):\n%s", d)
			}
		})
	}
}

func TestLoadPublicGrantErrors(t *testing.T) {
	t.Parallel()
	pgDB := pgConn + "database \"app\" {}\n"
	runDiagCases(t, []diagCase{
		{
			name:  "MySQL rejects PUBLIC",
			src:   myConn + "database \"app\" {}\ngrant {\n role = \"PUBLIC\"\n database = \"app\"\n privileges = [\"SELECT\"]\n}\n",
			want:  []string{"Unsupported grantee", "only supported for postgres", `"PUBLIC@<host>"`, "dbfence.hcl line 7"},
			count: 1,
		},
		{
			name:  "MySQL rejects lower case public too",
			src:   myConn + "database \"app\" {}\ngrant {\n role = \"public\"\n database = \"app\"\n privileges = []\n}\n",
			want:  []string{"Unsupported grantee"},
			deny:  []string{"Empty privileges"},
			count: 1,
		},
		{
			name:  "grant option for PUBLIC",
			src:   pgDB + "grant {\n role = \"PUBLIC\"\n database = \"app\"\n privileges = [\"CONNECT\"]\n with_grant_option = true\n}\n",
			want:  []string{"Invalid grant option", "dbfence.hcl line 10"},
			count: 1,
		},
		{
			name:  "empty privileges for a role",
			src:   pgDB + "role \"r\" {}\ngrant {\n role = \"r\"\n database = \"app\"\n privileges = []\n}\n",
			want:  []string{"Empty privileges", `only a grant to role = "PUBLIC"`},
			count: 1,
		},
		{
			name:  "empty privileges combined with PUBLIC grants",
			src:   pgDB + "grant {\n role = \"PUBLIC\"\n database = \"app\"\n privileges = [\"CONNECT\"]\n}\ngrant {\n role = \"public\"\n database = \"app\"\n privileges = []\n}\n",
			want:  []string{"Conflicting PUBLIC grants", "dbfence.hcl line 14", "dbfence.hcl:6,1"},
			count: 1,
		},
		{
			name:  "PUBLIC on an undeclared database",
			src:   pgConn + "grant {\n role = \"PUBLIC\"\n database = \"other\"\n privileges = []\n}\n",
			want:  []string{"Undeclared database"},
			deny:  []string{"Undeclared role"},
			count: 1,
		},
		{
			name:  "PUBLIC privilege not valid on a schema",
			src:   pgDB + "schema \"api\" {\n database = \"app\"\n}\ngrant {\n role = \"PUBLIC\"\n database = \"app\"\n schema = \"api\"\n privileges = [\"CONNECT\"]\n}\n",
			want:  []string{"Invalid privilege"},
			count: 1,
		},
		{
			name:  "role named PUBLIC in another case",
			src:   pgConn + "role \"r\" {\n name = \"PUBLIC\"\n}\n",
			want:  []string{"Reserved name", "PUBLIC pseudo-role"},
			count: 1,
		},
	})
}
