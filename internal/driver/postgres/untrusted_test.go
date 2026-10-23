package postgres

import (
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
)

const unmanagedGrantor = "its grantor is a role dbfence does not manage"

// TestUnmanagedGrantorIsNotNamed checks that changes to grants made by a
// role Inspect left out are skipped with a warning: changing them would
// have to name the grantor in GRANTED BY or SET ROLE.
func TestUnmanagedGrantorIsNotNamed(t *testing.T) {
	t.Parallel()
	db := model.Object{Type: model.ObjectDatabase, Database: "app"}
	bad := "evil\n"
	yes, no := true, false
	tests := []struct {
		run      func(st *state) ([]plan.Statement, []string)
		name     string
		want     string
		wantWarn string
	}{
		{
			name: "revoke of a privilege",
			run:  func(st *state) ([]plan.Statement, []string) { return st.revoke("hu", db, []string{"CONNECT"}, false) },
			want: `REVOKE CONNECT ON DATABASE "app" FROM "hu"`, wantWarn: `CONNECT on database "app" granted to "hu" differs from the configuration, but ` + unmanagedGrantor,
		},
		{
			name:     "revoke of a grant option",
			run:      func(st *state) ([]plan.Statement, []string) { return st.revoke("hu", db, []string{"CREATE"}, true) },
			wantWarn: "grant option for CREATE on database \"app\" granted to \"hu\" differs from the configuration, but " + unmanagedGrantor,
		},
		{
			name:     "revoke of a membership",
			run:      func(st *state) ([]plan.Statement, []string) { return st.revokeMembership("hu", "grp") },
			want:     `REVOKE "grp" FROM "hu" GRANTED BY "postgres"`,
			wantWarn: `membership of "hu" in "grp" differs from the configuration, but ` + unmanagedGrantor,
		},
		{
			name: "membership options",
			run: func(st *state) ([]plan.Statement, []string) {
				return st.alterMembership("hu", "grp", model.MembershipOptions{Set: &no}, model.MembershipState{Set: true})
			},
			want:     `GRANT "grp" TO "hu" WITH SET FALSE GRANTED BY "postgres"`,
			wantWarn: `options of the membership of "hu" in "grp" differ from the configuration, but ` + unmanagedGrantor,
		},
		{
			name: "inherit attribute",
			run: func(st *state) ([]plan.Statement, []string) {
				return st.inheritOptions(model.Role{ID: pg("hu"), Inherit: &no})
			},
			want:     `GRANT "grp" TO "hu" WITH INHERIT FALSE GRANTED BY "postgres"`,
			wantWarn: `membership of "hu" in "grp" has inherit = true, but ` + unmanagedGrantor,
		},
		{
			name: "inherit attribute of a membership in an unmanaged role",
			run: func(st *state) ([]plan.Statement, []string) {
				st.members = []memberEntry{{role: bad, member: "hu", grantor: "postgres", inherit: true}}
				return st.inheritOptions(model.Role{ID: pg("hu"), Inherit: &no})
			},
		},
		{
			name: "admin option is still granted",
			run: func(st *state) ([]plan.Statement, []string) {
				return st.alterMembership("hu", "grp", model.MembershipOptions{Admin: &yes}, model.MembershipState{})
			},
			want: `GRANT "grp" TO "hu" WITH ADMIN OPTION`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			st := &state{
				desired: &model.Desired{}, user: "postgres", superuser: true, version: 170000,
				owners: map[model.Object]string{db: "postgres"},
				acl: []aclEntry{
					{obj: db, grantee: "hu", grantor: bad, priv: "CONNECT"},
					{obj: db, grantee: "hu", grantor: "postgres", priv: "CONNECT"},
					{obj: db, grantee: "hu", grantor: bad, priv: "CREATE", grantable: true},
				},
				members: []memberEntry{
					{role: "grp", member: "hu", grantor: bad, inherit: true, set: true},
					{role: "grp", member: "hu", grantor: "postgres", inherit: true, set: true},
				},
			}
			stmts, warns := tt.run(st)
			if got := sqlOf(stmts); got != tt.want {
				t.Errorf("statements = %q, want %q", got, tt.want)
			}
			if got := strings.Join(warns, "\n"); !strings.HasPrefix(got, tt.wantWarn) || (tt.wantWarn == "" && got != "") {
				t.Errorf("warnings = %q, want %q", got, tt.wantWarn)
			}
			for _, s := range stmts {
				if strings.Contains(s.SQL(), "evil") || s.AsRole == bad {
					t.Errorf("statement names the unmanaged grantor: %s (as %q)", s.SQL(), s.AsRole)
				}
			}
		})
	}
}

// TestPruneSkipsUnmanagedOwnerMembership checks that pruning a role does
// not revoke its membership in a role dbfence does not manage, and says
// so.
func TestPruneSkipsUnmanagedOwnerMembership(t *testing.T) {
	t.Parallel()
	ps := model.Object{Type: model.ObjectSchema, Database: "pdb", Schema: "ps"}
	bad := strings.Repeat("o", 64)
	st := &state{
		desired: &model.Desired{}, user: "postgres", superuser: true, version: 170000,
		connectable: map[string]bool{"pdb": true},
		owners:      map[model.Object]string{ps: bad},
		acl:         []aclEntry{{obj: ps, grantee: "reader", grantor: "lead", priv: "USAGE"}},
		members:     []memberEntry{{role: bad, member: "lead", grantor: "postgres", inherit: true}},
	}
	d := &Driver{st: st}
	for _, s := range d.DropRole(pg("lead"), []string{"pdb"}) {
		if strings.Contains(s.SQL(), bad) {
			t.Errorf("statement names the unmanaged role: %s", s.SQL())
		}
	}
	warns := st.unmanagedOwnerMembershipWarnings(&model.Current{Roles: []model.RoleState{{ID: pg("lead")}}})
	if len(warns) != 1 || !strings.Contains(warns[0], `role "lead" has the privileges of the owner`) {
		t.Errorf("warnings = %q", warns)
	}
}

// TestUntrustedObjectsAreNotPlanned runs the sanitized state through diff:
// nothing is revoked from, granted to, or dropped for the objects left out.
func TestUntrustedObjectsAreNotPlanned(t *testing.T) {
	t.Parallel()
	bad := "evil\x1b[0m"
	db := model.Object{Type: model.ObjectDatabase, Database: "app"}
	desired := &model.Desired{
		Engine:     model.EnginePostgres,
		Databases:  []model.Database{{Name: "app"}},
		Schemas:    []model.Schema{{Database: "app", Name: "core"}},
		Roles:      []model.Role{{ID: pg("hu"), MemberOf: []model.RoleID{}}},
		Privileges: []model.Privilege{{Grantee: pg("hu"), Object: db, Name: "TEMPORARY"}},
	}
	cur := &model.Current{
		CurrentUser: pg("postgres"),
		Roles: []model.RoleState{
			{ID: pg("postgres"), Superuser: true},
			{ID: pg("hu"), MemberOf: []model.RoleID{pg(bad)}},
			{ID: pg(bad)},
		},
		Databases:          []model.Database{{Name: "postgres"}, {Name: "app"}, {Name: "d\u0085"}},
		Schemas:            []model.Schema{{Database: "app", Name: "core"}, {Database: "app", Name: "s\x7f"}},
		InspectedDatabases: []string{"app"},
		Privileges: []model.Privilege{
			{Grantee: pg("hu"), Object: db, Name: "CONNECT"},
			{Grantee: pg(bad), Object: db, Name: "CONNECT"},
			{Grantee: pg("hu"), Object: model.Object{Type: model.ObjectSchema, Database: "app", Schema: "s\x7f"}, Name: "USAGE"},
		},
	}
	st := &state{
		desired: desired, user: "postgres", superuser: true, version: 170000,
		connectable: map[string]bool{"postgres": true, "app": true, "d\u0085": true},
		owners:      map[model.Object]string{db: "postgres"},
		acl:         []aclEntry{{obj: db, grantee: "hu", grantor: bad, priv: "CONNECT"}},
		members:     []memberEntry{{role: bad, member: "hu", grantor: "postgres"}},
	}
	if _, err := cur.DropUntrusted(model.EnginePostgres); err != nil {
		t.Fatal(err)
	}
	for _, opts := range []diff.Options{{}, {Prune: true}} {
		p, err := compute(t, desired, cur, &Driver{st: st}, opts)
		if err != nil {
			t.Fatal(err)
		}
		got := sqlOf(p.Statements())
		for _, unwanted := range []string{"evil", "d\u0085", "s\x7f"} {
			if strings.Contains(got, unwanted) {
				t.Errorf("prune %v: plan names %q:\n%s", opts.Prune, unwanted, got)
			}
		}
		if !strings.Contains(got, `GRANT TEMPORARY ON DATABASE "app" TO "hu"`) {
			t.Errorf("prune %v: declared grant missing:\n%s", opts.Prune, got)
		}
		warns := strings.Join(p.Warnings, "\n")
		for _, w := range []string{`role "evil\x1b[0m": its name contains control characters`, `database "d\u0085"`, `schema "s\x7f" in database "app"`, unmanagedGrantor} {
			if !strings.Contains(warns, w) {
				t.Errorf("prune %v: warnings do not contain %q:\n%s", opts.Prune, w, warns)
			}
		}
	}
}
