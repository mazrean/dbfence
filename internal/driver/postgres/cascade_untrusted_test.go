package postgres

import (
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
)

const unmanagedDependent = "revoking it with CASCADE would also revoke what a role dbfence does not manage"

// TestCascadeSparesUnmanagedRoles checks that a revoke whose CASCADE would
// also take privileges or memberships from a role Inspect left out is not
// planned: it is reported instead.
func TestCascadeSparesUnmanagedRoles(t *testing.T) {
	t.Parallel()
	bad := "evil\n"
	db := model.Object{Type: model.ObjectDatabase, Database: "app"}
	no := false
	tests := []struct {
		run      func(st *state) ([]plan.Statement, []string)
		name     string
		want     string
		wantWarn string
	}{
		{
			name:     "grant option passed on to an unmanaged role",
			run:      func(st *state) ([]plan.Statement, []string) { return st.revoke("hu", db, []string{"CONNECT"}, true) },
			wantWarn: `grant option for CONNECT on database "app" granted to "hu" differs from the configuration, but ` + unmanagedDependent,
		},
		{
			name:     "privilege passed on to an unmanaged role",
			run:      func(st *state) ([]plan.Statement, []string) { return st.revoke("hu", db, []string{"CONNECT"}, false) },
			wantWarn: `CONNECT on database "app" granted to "hu" differs from the configuration, but ` + unmanagedDependent,
		},
		{
			name: "privilege passed on to a managed role",
			run:  func(st *state) ([]plan.Statement, []string) { return st.revoke("hu", db, []string{"TEMPORARY"}, false) },
			want: "-- CASCADE: privileges on database \"app\" that \"hu\" granted to \"x\" are revoked too; declared ones are granted again\n" +
				`REVOKE TEMPORARY ON DATABASE "app" FROM "hu" CASCADE`,
		},
		{
			// The grant option of hu is not revoked (its CASCADE reaches
			// the unmanaged role), so the grant hu made to x is revoked
			// on its own.
			name: "grant of a role whose CASCADE is not planned",
			run:  func(st *state) ([]plan.Statement, []string) { return st.revoke("x", db, []string{"CONNECT"}, false) },
			want: `as "hu": REVOKE CONNECT ON DATABASE "app" FROM "x"`,
		},
		{
			name:     "membership passed on to an unmanaged role",
			run:      func(st *state) ([]plan.Statement, []string) { return st.revokeMembership("hu", "grp") },
			wantWarn: `membership of "hu" in "grp" differs from the configuration, but ` + unmanagedDependent,
		},
		{
			name: "admin option used to grant an unmanaged role",
			run: func(st *state) ([]plan.Statement, []string) {
				return st.alterMembership("hu", "grp", model.MembershipOptions{Admin: &no}, model.MembershipState{Admin: true})
			},
			wantWarn: `ADMIN OPTION of "hu" on "grp" differs from the configuration, but ` + unmanagedDependent,
		},
		{
			// hu loses its membership, but that revoke is not planned,
			// so the grant hu made to x is revoked on its own.
			name: "membership granted by a role whose CASCADE is not planned",
			run:  func(st *state) ([]plan.Statement, []string) { return st.revokeMembership("x", "grp") },
			want: `REVOKE "grp" FROM "x" GRANTED BY "hu"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			st := &state{
				desired: &model.Desired{Roles: []model.Role{{ID: pg("hu"), MemberOf: []model.RoleID{}}}},
				user:    "postgres", superuser: true, version: 170000,
				owners: map[model.Object]string{db: "postgres"},
				acl: []aclEntry{
					{obj: db, grantee: "hu", grantor: "postgres", priv: "CONNECT", grantable: true},
					{obj: db, grantee: bad, grantor: "hu", priv: "CONNECT"},
					{obj: db, grantee: "x", grantor: "hu", priv: "CONNECT"},
					{obj: db, grantee: "hu", grantor: "postgres", priv: "TEMPORARY", grantable: true},
					{obj: db, grantee: "x", grantor: "hu", priv: "TEMPORARY"},
				},
				members: []memberEntry{
					{role: "grp", member: "hu", grantor: "postgres", admin: true},
					{role: "grp", member: bad, grantor: "hu"},
					{role: "grp", member: "x", grantor: "hu"},
				},
			}
			stmts, warns := tt.run(st)
			if got := sqlOf(stmts); got != tt.want {
				t.Errorf("SQL:\n%s\nwant:\n%s", got, tt.want)
			}
			if got := strings.Join(warns, "\n"); !strings.Contains(got, tt.wantWarn) || (tt.wantWarn == "") != (got == "") {
				t.Errorf("warnings:\n%s\nwant %q", got, tt.wantWarn)
			}
		})
	}
}

// TestCascadePlanSparesUnmanagedRoles runs the plan of the verifier's
// report: removing the grant option of a declared role must not revoke,
// through CASCADE, the privilege it passed on to a role dbfence does not
// manage.
func TestCascadePlanSparesUnmanagedRoles(t *testing.T) {
	t.Parallel()
	bad := "evil\n"
	db := model.Object{Type: model.ObjectDatabase, Database: "app"}
	desired := &model.Desired{
		Engine:     model.EnginePostgres,
		Databases:  []model.Database{{Name: "app"}},
		Roles:      []model.Role{{ID: pg("hu")}},
		Privileges: []model.Privilege{{Grantee: pg("hu"), Object: db, Name: "CONNECT"}},
	}
	cur := &model.Current{
		CurrentUser: pg("postgres"),
		Roles:       []model.RoleState{{ID: pg("postgres"), Superuser: true}, {ID: pg("hu")}, {ID: pg(bad)}},
		Databases:   []model.Database{{Name: "postgres"}, {Name: "app", Owner: "postgres"}},
		Privileges: []model.Privilege{
			{Grantee: pg("hu"), Object: db, Name: "CONNECT", GrantOption: true},
			{Grantee: pg(bad), Object: db, Name: "CONNECT"},
		},
	}
	st := &state{
		desired: desired, user: "postgres", superuser: true, version: 170000,
		connectable: map[string]bool{"postgres": true, "app": true},
		owners:      map[model.Object]string{db: "postgres"},
		acl: []aclEntry{
			{obj: db, grantee: "hu", grantor: "postgres", priv: "CONNECT", grantable: true},
			{obj: db, grantee: bad, grantor: "hu", priv: "CONNECT"},
		},
	}
	if _, err := cur.DropUntrusted(model.EnginePostgres); err != nil {
		t.Fatal(err)
	}
	for _, prune := range []bool{false, true} {
		p, err := compute(t, desired, cur, &Driver{st: st}, diff.Options{Prune: prune})
		if err != nil {
			t.Fatal(err)
		}
		if got := sqlOf(p.Statements()); strings.Contains(got, "CASCADE") {
			t.Errorf("prune %v: plan revokes through CASCADE what %q holds:\n%s", prune, bad, got)
		}
		if w := strings.Join(p.Warnings, "\n"); !strings.Contains(w, unmanagedDependent) {
			t.Errorf("prune %v: warnings do not contain %q:\n%s", prune, unmanagedDependent, w)
		}
	}
}
