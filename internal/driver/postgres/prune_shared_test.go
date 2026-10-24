package postgres

import (
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/model"
)

// TestPruneKeepsRolesReachingUnmanagedOutsideDeclaredDatabases checks that
// --prune keeps a role whose REASSIGN OWNED or DROP OWNED would change a
// schema with an unmanaged name in a surviving undeclared database, or a
// shared object dbfence does not manage or did not inspect.
func TestPruneKeepsRolesReachingUnmanagedOutsideDeclaredDatabases(t *testing.T) {
	t.Parallel()
	evil := model.Object{Type: model.ObjectSchema, Database: "postgres", Schema: "evil\x01"}
	plain := model.Object{Type: model.ObjectSchema, Database: "postgres", Schema: "plain"}
	tests := []struct {
		otherOwners map[model.Object]string
		name        string
		keep        string
		otherACL    []aclEntry
		shared      []sharedDep
	}{
		{
			name:        "owns an unmanaged schema in an undeclared database",
			otherOwners: map[model.Object]string{evil: "old"},
			keep:        "owns, holds or granted something",
		},
		{
			name:     "holds a privilege on an unmanaged schema in an undeclared database",
			otherACL: []aclEntry{{obj: evil, grantee: "old", grantor: "postgres", priv: "USAGE"}},
			keep:     "owns, holds or granted something",
		},
		{
			name:     "granted a privilege to an unmanaged role in an undeclared database",
			otherACL: []aclEntry{{obj: plain, grantee: "bad\x01", grantor: "old", priv: "USAGE"}},
			keep:     "owns, holds or granted something",
		},
		{
			name:   "owns a database that was not inspected",
			shared: []sharedDep{{role: "old", class: "pg_database", name: "evil\n"}},
			keep:   `owns or has privileges on database "evil\n", which dbfence does not manage`,
		},
		{
			name:   "owns a tablespace",
			shared: []sharedDep{{role: "old", class: "pg_tablespace", name: "ts"}},
			keep:   `owns or has privileges on tablespace "ts"`,
		},
		{
			name:   "has a privilege on a parameter",
			shared: []sharedDep{{role: "old", class: "pg_parameter_acl"}},
			keep:   "owns or has privileges on an entry of pg_parameter_acl",
		},
		{
			name:        "owns a managed schema and an inspected database",
			otherOwners: map[model.Object]string{plain: "old"},
			otherACL:    []aclEntry{{obj: plain, grantee: "app", grantor: "old", priv: "USAGE"}},
			shared:      []sharedDep{{role: "old", class: "pg_database", name: "postgres"}, {role: "other", class: "pg_tablespace", name: "ts"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			desired := &model.Desired{Engine: model.EnginePostgres, Databases: []model.Database{{Name: "app"}}}
			cur := &model.Current{
				CurrentUser:        pg("postgres"),
				Roles:              []model.RoleState{{ID: pg("postgres"), Superuser: true}, {ID: pg("old")}, {ID: pg("app")}},
				Databases:          []model.Database{{Name: "postgres", Owner: "postgres"}, {Name: "app", Owner: "postgres"}},
				Schemas:            []model.Schema{{Database: "app", Name: "public", Owner: "pg_database_owner"}},
				InspectedDatabases: []string{"app"},
			}
			desired.Roles = []model.Role{{ID: pg("app")}}
			st := &state{
				desired: desired, user: "postgres", superuser: true, version: 170000,
				connectable: map[string]bool{"postgres": true, "app": true},
				owners: map[model.Object]string{
					{Type: model.ObjectDatabase, Database: "app"}:      "postgres",
					{Type: model.ObjectDatabase, Database: "postgres"}: "postgres",
				},
				otherOwners: tt.otherOwners,
				otherACL:    tt.otherACL,
				shared:      tt.shared,
			}
			if _, err := cur.DropUntrusted(model.EnginePostgres); err != nil {
				t.Fatal(err)
			}
			p, err := compute(t, desired, cur, &Driver{st: st}, diff.Options{Prune: true})
			if err != nil {
				t.Fatal(err)
			}
			got := sqlOf(p.Statements())
			warns := strings.Join(p.Warnings, "\n")
			if dropped := strings.Contains(got, `REASSIGN OWNED BY "old"`); dropped != (tt.keep == "") {
				t.Errorf("REASSIGN OWNED BY old planned = %v, want %v:\n%s\nwarnings:\n%s", dropped, tt.keep == "", got, warns)
			}
			if tt.keep != "" && !strings.Contains(warns, tt.keep) {
				t.Errorf("warnings do not contain %q:\n%s", tt.keep, warns)
			}
		})
	}
}
