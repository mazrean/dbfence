package postgres

import (
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/model"
)

// TestPruneKeepsOwnerOfUnmanagedDatabase checks that --prune keeps a role
// owning a database whose name dbfence does not manage: REASSIGN OWNED
// would change that database's owner.
func TestPruneKeepsOwnerOfUnmanagedDatabase(t *testing.T) {
	t.Parallel()
	bad := "evil\n"
	desired := &model.Desired{
		Engine:    model.EnginePostgres,
		Databases: []model.Database{{Name: "app"}},
	}
	cur := &model.Current{
		CurrentUser: pg("postgres"),
		Roles:       []model.RoleState{{ID: pg("postgres"), Superuser: true}, {ID: pg("old")}},
		Databases:   []model.Database{{Name: "postgres", Owner: "postgres"}, {Name: "app", Owner: "postgres"}, {Name: bad, Owner: "old"}},
	}
	st := &state{
		desired: desired, user: "postgres", superuser: true, version: 170000,
		connectable: map[string]bool{"postgres": true, "app": true, bad: true},
		owners: map[model.Object]string{
			{Type: model.ObjectDatabase, Database: "app"}:      "postgres",
			{Type: model.ObjectDatabase, Database: "postgres"}: "postgres",
			{Type: model.ObjectDatabase, Database: bad}:        "old",
		},
	}
	if _, err := cur.DropUntrusted(model.EnginePostgres); err != nil {
		t.Fatal(err)
	}
	p, err := compute(t, desired, cur, &Driver{st: st}, diff.Options{Prune: true})
	if err != nil {
		t.Fatal(err)
	}
	got := sqlOf(p.Statements())
	t.Logf("plan:\n%s\nwarnings:\n%s", got, strings.Join(p.Warnings, "\n"))
	if strings.Contains(got, `REASSIGN OWNED BY "old"`) {
		t.Errorf("prune reassigns (REASSIGN OWNED) the owner of the unmanaged database %q", bad)
	}
}

// TestPruneKeepsOwnerOfUnmanagedSchema is the same for a schema with an
// unmanaged name in a declared database.
func TestPruneKeepsOwnerOfUnmanagedSchema(t *testing.T) {
	t.Parallel()
	bad := "evil\x01"
	desired := &model.Desired{
		Engine:    model.EnginePostgres,
		Databases: []model.Database{{Name: "app"}},
	}
	cur := &model.Current{
		CurrentUser:        pg("postgres"),
		Roles:              []model.RoleState{{ID: pg("postgres"), Superuser: true}, {ID: pg("old")}},
		Databases:          []model.Database{{Name: "postgres", Owner: "postgres"}, {Name: "app", Owner: "postgres"}},
		Schemas:            []model.Schema{{Database: "app", Name: "public", Owner: "pg_database_owner"}, {Database: "app", Name: bad, Owner: "old"}},
		InspectedDatabases: []string{"app"},
	}
	st := &state{
		desired: desired, user: "postgres", superuser: true, version: 170000,
		connectable: map[string]bool{"postgres": true, "app": true},
		owners: map[model.Object]string{
			{Type: model.ObjectDatabase, Database: "app"}:            "postgres",
			{Type: model.ObjectSchema, Database: "app", Schema: bad}: "old",
		},
	}
	if _, err := cur.DropUntrusted(model.EnginePostgres); err != nil {
		t.Fatal(err)
	}
	p, err := compute(t, desired, cur, &Driver{st: st}, diff.Options{Prune: true})
	if err != nil {
		t.Fatal(err)
	}
	got := sqlOf(p.Statements())
	t.Logf("plan:\n%s\nwarnings:\n%s", got, strings.Join(p.Warnings, "\n"))
	if strings.Contains(got, `REASSIGN OWNED BY "old"`) {
		t.Errorf("prune reassigns (REASSIGN OWNED in app) the owner of the unmanaged schema %q", bad)
	}
}

// TestPruneKeepsGrantorOfMembershipInUnmanagedRole checks that --prune
// keeps a role that is a member of an unmanaged role and (PostgreSQL 16+)
// granted membership in it to a managed role, which DROP OWNED would revoke.
func TestPruneKeepsGrantorOfMembershipInUnmanagedRole(t *testing.T) {
	t.Parallel()
	bad := "evil\n"
	desired := &model.Desired{
		Engine:    model.EnginePostgres,
		Databases: []model.Database{{Name: "app"}},
		Roles:     []model.Role{{ID: pg("hu")}},
	}
	cur := &model.Current{
		CurrentUser: pg("postgres"),
		Roles: []model.RoleState{{ID: pg("postgres"), Superuser: true}, {ID: pg("hu"), MemberOf: []model.RoleID{pg(bad)}, MemberOptions: map[model.RoleID]model.MembershipState{pg(bad): {Inherit: true, Set: true}}},
			{ID: pg("old"), MemberOf: []model.RoleID{pg(bad)}, MemberOptions: map[model.RoleID]model.MembershipState{pg(bad): {Admin: true}}}, {ID: pg(bad)}},
		Databases: []model.Database{{Name: "postgres", Owner: "postgres"}, {Name: "app", Owner: "postgres"}},
	}
	st := &state{
		desired: desired, user: "postgres", superuser: true, version: 170000,
		connectable: map[string]bool{"postgres": true, "app": true},
		owners:      map[model.Object]string{{Type: model.ObjectDatabase, Database: "app"}: "postgres"},
		members: []memberEntry{
			{role: bad, member: "old", grantor: "postgres", admin: true},
			{role: bad, member: "hu", grantor: "old", inherit: true, set: true},
		},
	}
	if _, err := cur.DropUntrusted(model.EnginePostgres); err != nil {
		t.Fatal(err)
	}
	p, err := compute(t, desired, cur, &Driver{st: st}, diff.Options{Prune: true})
	if err != nil {
		t.Fatal(err)
	}
	got := sqlOf(p.Statements())
	t.Logf("plan:\n%s\nwarnings:\n%s", got, strings.Join(p.Warnings, "\n"))
	if strings.Contains(got, `DROP OWNED BY "old"`) {
		t.Errorf("prune runs DROP OWNED BY old, whose CASCADE revokes the membership of hu in the unmanaged role %q", bad)
	}
}
