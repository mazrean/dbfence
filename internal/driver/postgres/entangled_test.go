package postgres

import (
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/model"
)

// TestPruneKeepsContainersOfUnmanaged checks that --prune keeps an
// undeclared database owned by a role dbfence does not manage and holding
// a schema with an unmanaged name, and an undeclared schema owned by and
// granting to such a role: dropping them would drop what dbfence does not
// manage.
func TestPruneKeepsContainersOfUnmanaged(t *testing.T) {
	t.Parallel()
	desired := &model.Desired{Engine: model.EnginePostgres, Databases: []model.Database{{Name: "app"}}}
	bad := "bad\x01"
	oldS := model.Object{Type: model.ObjectSchema, Database: "app", Schema: "old"}
	evil := model.Object{Type: model.ObjectSchema, Database: "olddb", Schema: "evil\x01"}
	olddb := model.Object{Type: model.ObjectDatabase, Database: "olddb"}
	cur := &model.Current{
		CurrentUser:     pg("postgres"),
		CurrentDatabase: "postgres",
		Roles:           []model.RoleState{{ID: pg("postgres"), Superuser: true}, {ID: pg(bad)}},
		Databases: []model.Database{
			{Name: "postgres", Owner: "postgres"}, {Name: "app", Owner: "postgres"}, {Name: "olddb", Owner: bad},
			{Name: "plaindb", Owner: "postgres"},
		},
		Schemas: []model.Schema{
			{Database: "app", Name: "public", Owner: "pg_database_owner"},
			{Database: "app", Name: "old", Owner: bad},
			{Database: "app", Name: "plain", Owner: "postgres"},
		},
		OtherSchemas:       []model.Schema{{Database: "olddb", Name: "evil\x01", Owner: bad}},
		InspectedDatabases: []string{"app"},
		Privileges: []model.Privilege{
			{Grantee: pg(bad), Object: oldS, Name: "USAGE"},
			{Grantee: pg(bad), Object: olddb, Name: "CONNECT"},
		},
	}
	st := &state{
		desired: desired, user: "postgres", superuser: true, version: 170000,
		connectable: map[string]bool{"postgres": true, "app": true, "olddb": true, "plaindb": true},
		owners: map[model.Object]string{
			{Type: model.ObjectDatabase, Database: "app"}:      "postgres",
			{Type: model.ObjectDatabase, Database: "postgres"}: "postgres",
			{Type: model.ObjectDatabase, Database: "plaindb"}:  "postgres",
			olddb: bad,
			oldS:  bad,
		},
		otherOwners: map[model.Object]string{evil: bad},
		acl: []aclEntry{
			{obj: oldS, grantee: bad, grantor: bad, priv: "USAGE"},
			{obj: olddb, grantee: bad, grantor: bad, priv: "CONNECT"},
		},
		objects: map[model.Object]int{oldS: 3},
		roles:   map[string]roleAccess{},
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
	for _, s := range []string{`DROP DATABASE "olddb"`, `DROP SCHEMA "old"`} {
		if strings.Contains(got, s) {
			t.Errorf("plan contains %s:\n%s", s, got)
		}
	}
	for _, s := range []string{`DROP DATABASE "plaindb"`, `DROP SCHEMA "plain"`} {
		if !strings.Contains(got, s) {
			t.Errorf("plan does not contain %s:\n%s", s, got)
		}
	}
	for _, w := range []string{
		`database "olddb": it is owned by role "bad\x01", which dbfence does not manage, so it is not pruned`,
		`schema "old" in database "app": it is owned by role "bad\x01", which dbfence does not manage, so it is not pruned`,
	} {
		if !strings.Contains(warns, w) {
			t.Errorf("warnings do not contain %q:\n%s", w, warns)
		}
	}
}
