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
