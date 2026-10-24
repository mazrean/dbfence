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

// TestPruneKeepsSchemasWithObjectsOfUnmanaged checks that --prune keeps an
// undeclared schema with a managed name and owner that contains objects in
// a database where a role dbfence does not manage owns objects or holds
// privileges (pg_shdepend), or that contains a schema with a name dbfence
// does not manage or owned by such a role, whose objects may depend on it:
// DROP SCHEMA ... CASCADE could drop them. A schema without objects is
// still dropped (without CASCADE).
func TestPruneKeepsSchemasWithObjectsOfUnmanaged(t *testing.T) {
	t.Parallel()
	bad := "bad\x01"
	desired := &model.Desired{Engine: model.EnginePostgres, Databases: []model.Database{{Name: "app", Owner: "postgres"}, {Name: "other", Owner: "postgres"}}}
	sch := func(db, name string) model.Object { return model.Object{Type: model.ObjectSchema, Database: db, Schema: name} }
	dbObj := func(name string) model.Object { return model.Object{Type: model.ObjectDatabase, Database: name} }
	tests := []struct {
		deps map[string]string
		// schema is an extra schema of database app.
		schema  *model.Schema
		name    string
		warn    string
		dropped []string
		kept    []string
	}{
		{
			name:    "unmanaged role owns objects in the database",
			deps:    map[string]string{"app": bad},
			dropped: []string{`DROP SCHEMA "empty"`, `DROP SCHEMA "elsewhere" CASCADE`},
			kept:    []string{`DROP SCHEMA "old"`},
			warn:    `schema "old" in database "app": it contains 1 objects, which may include objects of or privileges held by role "bad\x01", which dbfence does not manage (it owns objects or holds privileges in database "app"), so it is not pruned`,
		},
		{
			name:    "the database contains a schema with an unmanaged name",
			schema:  &model.Schema{Database: "app", Name: "evil\x01", Owner: "postgres"},
			dropped: []string{`DROP SCHEMA "empty"`, `DROP SCHEMA "elsewhere" CASCADE`},
			kept:    []string{`DROP SCHEMA "old"`, "evil"},
			warn:    `schema "old" in database "app": it contains 1 objects, on which objects in schema "evil\x01", which dbfence does not manage, may depend (DROP SCHEMA ... CASCADE would drop them too), so it is not pruned`,
		},
		{
			name:    "the database contains a schema owned by an unmanaged role",
			schema:  &model.Schema{Database: "app", Name: "theirs", Owner: bad},
			dropped: []string{`DROP SCHEMA "empty"`, `DROP SCHEMA "elsewhere" CASCADE`},
			kept:    []string{`DROP SCHEMA "old"`, `DROP SCHEMA "theirs"`},
			warn:    `schema "old" in database "app": it contains 1 objects, on which objects in schema "theirs", owned by role "bad\x01", which dbfence does not manage, may depend (DROP SCHEMA ... CASCADE would drop them too), so it is not pruned`,
		},
		{
			name:    "no unmanaged dependencies",
			dropped: []string{`DROP SCHEMA "empty"`, `DROP SCHEMA "elsewhere" CASCADE`, `DROP SCHEMA "old" CASCADE`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cur := &model.Current{
				CurrentUser:     pg("postgres"),
				CurrentDatabase: "postgres",
				Roles:           []model.RoleState{{ID: pg("postgres"), Superuser: true}, {ID: pg(bad)}},
				Databases: []model.Database{
					{Name: "postgres", Owner: "postgres"}, {Name: "app", Owner: "postgres"}, {Name: "other", Owner: "postgres"},
				},
				Schemas: []model.Schema{
					{Database: "app", Name: "public", Owner: "pg_database_owner"},
					{Database: "app", Name: "old", Owner: "postgres"},
					{Database: "app", Name: "empty", Owner: "postgres"},
					{Database: "other", Name: "elsewhere", Owner: "postgres"},
				},
				InspectedDatabases: []string{"app", "other"},
			}
			st := &state{
				desired: desired, user: "postgres", superuser: true, version: 170000,
				connectable: map[string]bool{"postgres": true, "app": true, "other": true},
				owners: map[model.Object]string{
					dbObj("app"): "postgres", dbObj("postgres"): "postgres", dbObj("other"): "postgres",
					sch("app", "old"): "postgres", sch("app", "empty"): "postgres", sch("other", "elsewhere"): "postgres",
				},
				otherOwners: map[model.Object]string{},
				// The table in old is owned by bad.
				objects:       map[model.Object]int{sch("app", "old"): 1, sch("other", "elsewhere"): 2},
				roles:         map[string]roleAccess{},
				unmanagedDeps: tt.deps,
			}
			if s := tt.schema; s != nil {
				cur.Schemas = append(cur.Schemas, *s)
				st.owners[sch(s.Database, s.Name)] = s.Owner
				st.objects[sch(s.Database, s.Name)] = 1
			}
			if _, err := cur.DropUntrusted(model.EnginePostgres); err != nil {
				t.Fatal(err)
			}
			st.entangleSchemaObjects(cur)
			p, err := compute(t, desired, cur, &Driver{st: st}, diff.Options{Prune: true})
			if err != nil {
				t.Fatal(err)
			}
			got := sqlOf(p.Statements())
			warns := strings.Join(p.Warnings, "\n")
			for _, s := range tt.kept {
				if strings.Contains(got, s) {
					t.Errorf("plan contains %s:\n%s", s, got)
				}
			}
			for _, s := range tt.dropped {
				if !strings.Contains(got, s) {
					t.Errorf("plan does not contain %s:\n%s", s, got)
				}
			}
			if tt.warn != "" && !strings.Contains(warns, tt.warn) {
				t.Errorf("warnings do not contain %q:\n%s", tt.warn, warns)
			}
		})
	}
}

// TestPruneKeepsUnreadDatabases checks that --prune keeps an undeclared
// database with a managed name and owner that dbfence cannot connect to
// (no CONNECT, or the connection failed): its schemas were never read, so
// DROP DATABASE could drop what dbfence does not manage.
func TestPruneKeepsUnreadDatabases(t *testing.T) {
	t.Parallel()
	desired := &model.Desired{Engine: model.EnginePostgres, Databases: []model.Database{{Name: "app", Owner: "postgres"}}}
	dbObj := func(name string) model.Object { return model.Object{Type: model.ObjectDatabase, Database: name} }
	tests := []struct {
		name        string
		connectable bool
	}{
		{name: "cannot connect"},
		{name: "connectable", connectable: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cur := &model.Current{
				CurrentUser:     pg("postgres"),
				CurrentDatabase: "postgres",
				Roles:           []model.RoleState{{ID: pg("postgres"), Superuser: true}},
				Databases: []model.Database{
					{Name: "postgres", Owner: "postgres"}, {Name: "app", Owner: "postgres"}, {Name: "olddb", Owner: "postgres"},
				},
				Schemas:            []model.Schema{{Database: "app", Name: "public", Owner: "pg_database_owner"}},
				InspectedDatabases: []string{"app"},
			}
			st := &state{
				desired: desired, user: "postgres", superuser: true, version: 170000,
				connectable: map[string]bool{"postgres": true, "app": true, "olddb": tt.connectable},
				owners: map[model.Object]string{
					dbObj("app"): "postgres", dbObj("postgres"): "postgres", dbObj("olddb"): "postgres",
				},
				otherOwners: map[model.Object]string{}, objects: map[model.Object]int{}, roles: map[string]roleAccess{},
			}
			st.entangleUnread(cur)
			if _, err := cur.DropUntrusted(model.EnginePostgres); err != nil {
				t.Fatal(err)
			}
			p, err := compute(t, desired, cur, &Driver{st: st}, diff.Options{Prune: true})
			if err != nil {
				t.Fatal(err)
			}
			got := sqlOf(p.Statements())
			warns := strings.Join(p.Warnings, "\n")
			if dropped := strings.Contains(got, `DROP DATABASE "olddb"`); dropped != tt.connectable {
				t.Errorf("DROP DATABASE \"olddb\" planned = %v, want %v:\n%s", dropped, tt.connectable, got)
			}
			w := `database "olddb": dbfence cannot connect to it and does not know what it contains, so it is not pruned`
			if warned := strings.Contains(warns, w); warned == tt.connectable {
				t.Errorf("warning %q present = %v, want %v:\n%s", w, warned, !tt.connectable, warns)
			}
		})
	}
}
