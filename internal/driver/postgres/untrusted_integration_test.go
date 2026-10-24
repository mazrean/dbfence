package postgres

import (
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/model"
)

// TestIntegrationUntrustedNames checks against a real server that roles,
// databases and schemas with control characters in their names are left
// alone with a warning, also under --prune, including a grant whose
// grantor is such a role.
func TestIntegrationUntrustedNames(t *testing.T) {
	t.Parallel()
	s := startServer(t)
	s.exec(t,
		`CREATE ROLE "evil`+"\n"+`role" CREATEROLE`,
		`CREATE ROLE "bad`+"\x1b"+`grp"`,
		"CREATE ROLE app LOGIN",
		`GRANT "bad`+"\x1b"+`grp" TO app`,
		`CREATE DATABASE "db`+"\x7f"+`x"`,
		"CREATE DATABASE app",
		`GRANT CONNECT ON DATABASE app TO "evil`+"\n"+`role" WITH GRANT OPTION`,
	)
	// A grant to app made by the unmanaged role.
	s.exec(t, `BEGIN; SET LOCAL ROLE "evil`+"\n"+`role"; GRANT CONNECT ON DATABASE app TO app; COMMIT`)
	d := s.open(t, "postgres")
	desired := &model.Desired{
		Engine:    model.EnginePostgres,
		Databases: []model.Database{{Name: "app"}},
		Roles:     []model.Role{{ID: pg("app"), MemberOf: []model.RoleID{}}},
	}
	cur, err := d.Inspect(t.Context(), desired)
	if err != nil {
		t.Fatal(err)
	}
	for _, opts := range []diff.Options{{}, {Prune: true}} {
		p, err := compute(t, desired, cur, d, opts)
		if err != nil {
			t.Fatal(err)
		}
		for _, st := range p.Statements() {
			if strings.ContainsFunc(st.SQL(), model.IsControl) || strings.ContainsFunc(st.AsRole, model.IsControl) {
				t.Errorf("prune %v: statement names an unmanaged object: %q (as %q)", opts.Prune, st.SQL(), st.AsRole)
			}
		}
		warns := strings.Join(p.Warnings, "\n")
		for _, w := range []string{
			`role "evil\nrole": its name contains control characters, so dbfence does not manage it`,
			`role "bad\x1bgrp"`,
			`database "db\x7fx"`,
			`CONNECT on database "app" granted to "app" differs from the configuration, but its grantor is a role dbfence does not manage`,
		} {
			if !strings.Contains(warns, w) {
				t.Errorf("prune %v: warnings do not contain %q:\n%s", opts.Prune, w, warns)
			}
		}
	}
}

// TestIntegrationPruneKeepsRolesReachingUnmanaged checks against a real
// server that --prune keeps roles whose REASSIGN OWNED or DROP OWNED would
// change a schema with an unmanaged name in an undeclared database (read
// without ignore.schemas), or a database Inspect does not read (here one
// that refuses connections), and still drops a role without such objects.
func TestIntegrationPruneKeepsRolesReachingUnmanaged(t *testing.T) {
	t.Parallel()
	s := startServer(t)
	s.exec(t,
		"CREATE ROLE owner_s", "CREATE ROLE holder_s", "CREATE ROLE owner_db", "CREATE ROLE plain",
		`CREATE SCHEMA "evil`+"\x01"+`" AUTHORIZATION owner_s`,
		`CREATE SCHEMA "evil`+"\x02"+`"`,
		`GRANT USAGE ON SCHEMA "evil`+"\x02"+`" TO holder_s`,
		`CREATE DATABASE "nc`+"\n"+`db" OWNER owner_db`,
		`ALTER DATABASE "nc`+"\n"+`db" ALLOW_CONNECTIONS false`,
		"CREATE DATABASE app",
	)
	d := s.open(t, "postgres")
	desired := &model.Desired{Engine: model.EnginePostgres, Databases: []model.Database{{Name: "app"}}}
	cur, err := d.Inspect(t.Context(), desired)
	if err != nil {
		t.Fatal(err)
	}
	p, err := compute(t, desired, cur, d, diff.Options{Prune: true})
	if err != nil {
		t.Fatal(err)
	}
	got := sqlOf(p.Statements())
	warns := strings.Join(p.Warnings, "\n")
	for _, role := range []string{"owner_s", "holder_s", "owner_db"} {
		if strings.Contains(got, `OWNED BY "`+role+`"`) || strings.Contains(got, `DROP ROLE "`+role+`"`) {
			t.Errorf("prune drops %s:\n%s\nwarnings:\n%s", role, got, warns)
		}
		if !strings.Contains(warns, `role "`+role+`" `) {
			t.Errorf("warnings do not say why %s is kept:\n%s", role, warns)
		}
	}
	if !strings.Contains(warns, `owns or has privileges on database "nc\ndb"`) {
		t.Errorf("warnings do not name the database owner_db owns:\n%s", warns)
	}
	if !strings.Contains(got, `DROP ROLE "plain"`) {
		t.Errorf("prune does not drop plain:\n%s\nwarnings:\n%s", got, warns)
	}
}

// TestIntegrationPruneKeepsContainersOfUnmanaged checks against a real
// server that --prune keeps the undeclared databases and schemas whose
// drop would drop what dbfence does not manage, read without a prunable
// role: a database owned by an unmanaged role, one holding a schema with
// an unmanaged name, one holding a table of an unmanaged role (seen in
// pg_shdepend), a schema owned by and one granting to an unmanaged role,
// and a schema holding a table of an unmanaged role.
func TestIntegrationPruneKeepsContainersOfUnmanaged(t *testing.T) {
	t.Parallel()
	s := startServer(t)
	bad := `"bad` + "\x01" + `"`
	s.exec(t,
		"CREATE ROLE "+bad,
		"CREATE DATABASE app", "CREATE DATABASE owned OWNER "+bad,
		"CREATE DATABASE named", "CREATE DATABASE tabled", "CREATE DATABASE plaindb",
	)
	s.exec(t, `\c named`, `CREATE SCHEMA "evil`+"\x01"+`"`)
	s.exec(t, `\c tabled`, "CREATE TABLE public.t (id int)", "ALTER TABLE public.t OWNER TO "+bad)
	s.exec(t, `\c app`,
		"CREATE SCHEMA old AUTHORIZATION "+bad,
		"CREATE SCHEMA granted", "GRANT USAGE ON SCHEMA granted TO "+bad,
		"CREATE SCHEMA plain",
		"CREATE SCHEMA tabled_s", "CREATE TABLE tabled_s.t (id int)", "ALTER TABLE tabled_s.t OWNER TO "+bad,
	)
	d := s.open(t, "postgres")
	desired := &model.Desired{Engine: model.EnginePostgres, Databases: []model.Database{{Name: "app"}}}
	cur, err := d.Inspect(t.Context(), desired)
	if err != nil {
		t.Fatal(err)
	}
	p, err := compute(t, desired, cur, d, diff.Options{Prune: true})
	if err != nil {
		t.Fatal(err)
	}
	got := sqlOf(p.Statements())
	warns := strings.Join(p.Warnings, "\n")
	for _, stmt := range []string{`DROP DATABASE "owned"`, `DROP DATABASE "named"`, `DROP DATABASE "tabled"`, `DROP SCHEMA "old"`, `DROP SCHEMA "granted"`, `DROP SCHEMA "tabled_s"`} {
		if strings.Contains(got, stmt) {
			t.Errorf("plan contains %s:\n%s\nwarnings:\n%s", stmt, got, warns)
		}
	}
	for _, stmt := range []string{`DROP DATABASE "plaindb"`, `DROP SCHEMA "plain"`} {
		if !strings.Contains(got, stmt) {
			t.Errorf("plan does not contain %s:\n%s\nwarnings:\n%s", stmt, got, warns)
		}
	}
	for _, w := range []string{
		`database "owned": it is owned by role "bad\x01"`,
		`database "named": it contains schema "evil\x01"`,
		`database "tabled": role "bad\x01", which dbfence does not manage, owns objects or holds privileges in it`,
		`schema "old" in database "app": it is owned by role "bad\x01"`,
		`schema "granted" in database "app": it grants USAGE to role "bad\x01"`,
		`schema "tabled_s" in database "app": it contains 1 objects, which may include objects of or privileges held by role "bad\x01"`,
	} {
		if !strings.Contains(warns, w) {
			t.Errorf("warnings do not contain %q:\n%s", w, warns)
		}
	}
}

// TestIntegrationPruneKeepsUnreadDatabases checks against a real server
// that --prune keeps an undeclared database the connected user owns but
// may not connect to: what it contains is not known.
func TestIntegrationPruneKeepsUnreadDatabases(t *testing.T) {
	t.Parallel()
	s := startServer(t)
	s.exec(t,
		"CREATE ROLE ur_admin LOGIN CREATEROLE CREATEDB PASSWORD 'pw'",
		"CREATE DATABASE app OWNER ur_admin",
		"CREATE DATABASE olddb OWNER ur_admin", "CREATE DATABASE plaindb OWNER ur_admin",
		"REVOKE ALL ON DATABASE olddb FROM PUBLIC, ur_admin",
	)
	d := s.open(t, "ur_admin")
	desired := &model.Desired{Engine: model.EnginePostgres, Databases: []model.Database{{Name: "app", Owner: "ur_admin"}}}
	cur, err := d.Inspect(t.Context(), desired)
	if err != nil {
		t.Fatal(err)
	}
	p, err := compute(t, desired, cur, d, diff.Options{Prune: true})
	if err != nil {
		t.Fatal(err)
	}
	got := sqlOf(p.Statements())
	warns := strings.Join(p.Warnings, "\n")
	if strings.Contains(got, `DROP DATABASE "olddb"`) {
		t.Errorf("plan drops olddb, which dbfence cannot connect to:\n%s\nwarnings:\n%s", got, warns)
	}
	if !strings.Contains(got, `DROP DATABASE "plaindb"`) {
		t.Errorf("plan does not drop plaindb:\n%s\nwarnings:\n%s", got, warns)
	}
	if w := `database "olddb": dbfence cannot connect to it and does not know what it contains, so it is not pruned`; !strings.Contains(warns, w) {
		t.Errorf("warnings do not contain %q:\n%s", w, warns)
	}
}
