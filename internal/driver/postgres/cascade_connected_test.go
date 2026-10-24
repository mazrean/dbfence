package postgres

import (
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
	"github.com/mazrean/dbfence/internal/policy"
)

// TestCascadeKeepsConnectedUser covers revokes whose CASCADE reaches the
// connected user "admin" (not a superuser): it may hold CONNECT on the
// database it is connected to, or a membership with the INHERIT and SET
// it relies on, only through the grants CASCADE removes. diff must not
// plan them, and the plan check must refuse them when they are planned.
func TestCascadeKeepsConnectedUser(t *testing.T) {
	t.Parallel()
	db := model.Object{Type: model.ObjectDatabase, Database: "postgres"}
	f := false
	// admin connects to "postgres" only through the CONNECT d2 granted it
	// from the grant option d1 granted d2. admin may SET ROLE d1.
	connectCur := func() *model.Current {
		return &model.Current{
			CurrentUser: pg("admin"), CurrentDatabase: "postgres",
			Roles: []model.RoleState{
				{ID: pg("admin"), Login: true, Inherit: true, CreateRole: true, MemberOf: []model.RoleID{pg("d1")},
					MemberOptions: map[model.RoleID]model.MembershipState{pg("d1"): {Set: true}}},
				{ID: pg("d1"), Inherit: true}, {ID: pg("d2"), Inherit: true}, {ID: pg("postgres"), Superuser: true, Login: true, Inherit: true},
			},
			Databases: []model.Database{{Name: "postgres", Owner: "postgres"}},
			Privileges: []model.Privilege{
				{Grantee: pg("postgres"), Object: db, Name: "CONNECT"},
				{Grantee: pg("d1"), Object: db, Name: "CONNECT", GrantOption: true},
				{Grantee: pg("d2"), Object: db, Name: "CONNECT", GrantOption: true},
				{Grantee: pg("admin"), Object: db, Name: "CONNECT"},
			},
		}
	}
	connectState := func(desired *model.Desired) *state {
		return &state{
			desired: desired, user: "admin", database: "postgres", version: 170000, createRole: true,
			connectable: map[string]bool{"postgres": true},
			owners:      map[model.Object]string{db: "postgres"},
			roles:       map[string]roleAccess{"d1": {set: true}, "d2": {admin: true}},
			members:     []memberEntry{{role: "d1", member: "admin", grantor: "postgres", set: true}},
			acl: []aclEntry{
				{obj: db, grantee: "postgres", grantor: "postgres", priv: "CONNECT", grantable: true},
				{obj: db, grantee: "d1", grantor: "postgres", priv: "CONNECT", grantable: true},
				{obj: db, grantee: "d2", grantor: "d1", priv: "CONNECT", grantable: true},
				{obj: db, grantee: "admin", grantor: "d2", priv: "CONNECT"},
			},
		}
	}
	// admin has INHERIT and SET on ops only through the grant x made
	// (its own grant from postgres carries only ADMIN OPTION), or holds
	// ops through mid, whose grant x made.
	memberCur := func(viaMid bool) *model.Current {
		admin := model.RoleState{ID: pg("admin"), Login: true, Inherit: true, CreateRole: true, MemberOf: []model.RoleID{pg("ops")},
			MemberOptions: map[model.RoleID]model.MembershipState{pg("ops"): {Admin: true, Inherit: true, Set: true}}}
		roles := []model.RoleState{
			{ID: pg("x"), Inherit: true, MemberOf: []model.RoleID{pg("ops")},
				MemberOptions: map[model.RoleID]model.MembershipState{pg("ops"): {Admin: true, Inherit: true, Set: true}}},
			{ID: pg("ops"), Inherit: true},
		}
		if viaMid {
			admin.MemberOf = []model.RoleID{pg("mid")}
			admin.MemberOptions = map[model.RoleID]model.MembershipState{pg("mid"): {Inherit: true, Set: true}}
			roles = append(roles, model.RoleState{ID: pg("mid"), Inherit: true, MemberOf: []model.RoleID{pg("ops")},
				MemberOptions: map[model.RoleID]model.MembershipState{pg("ops"): {Inherit: true, Set: true}}})
		}
		return &model.Current{
			CurrentUser: pg("admin"), CurrentDatabase: "postgres",
			Roles:     append([]model.RoleState{admin}, roles...),
			Databases: []model.Database{{Name: "postgres", Owner: "postgres"}},
		}
	}
	memberState := func(desired *model.Desired, viaMid bool) *state {
		members := []memberEntry{
			{role: "ops", member: "x", grantor: "admin", admin: true, inherit: true, set: true},
			{role: "ops", member: "admin", grantor: "x", inherit: true, set: true},
			{role: "ops", member: "admin", grantor: "postgres", admin: true},
		}
		if viaMid {
			members = []memberEntry{
				{role: "ops", member: "x", grantor: "admin", admin: true, inherit: true, set: true},
				{role: "ops", member: "mid", grantor: "x", inherit: true, set: true},
				{role: "mid", member: "admin", grantor: "postgres", inherit: true, set: true},
				{role: "ops", member: "admin", grantor: "postgres", admin: true},
			}
		}
		return &state{
			desired: desired, user: "admin", database: "postgres", version: 170000, createRole: true,
			connectable: map[string]bool{"postgres": true},
			owners:      map[model.Object]string{db: "postgres"},
			roles:       map[string]roleAccess{"x": {admin: true, set: true}, "ops": {admin: true, use: true, set: true}, "mid": {set: true}},
			members:     members,
		}
	}
	xNoAdmin := &model.Desired{Engine: model.EnginePostgres,
		Roles: []model.Role{{ID: pg("x"), MemberOf: []model.RoleID{pg("ops")},
			MemberOptions: map[model.RoleID]model.MembershipOptions{pg("ops"): {Admin: &f}}}},
	}
	xNotMember := &model.Desired{Engine: model.EnginePostgres, Roles: []model.Role{{ID: pg("x"), MemberOf: []model.RoleID{}}}}

	tests := []struct {
		desired  *model.Desired
		cur      *model.Current
		st       func(*model.Desired) *state
		name     string
		wantWarn string
		// stmt is the revoke the plan check must refuse.
		stmt plan.Statement
	}{
		{
			name: "REVOKE CONNECT from a grantor of the connected user's CONNECT",
			desired: &model.Desired{Engine: model.EnginePostgres,
				Roles:      []model.Role{{ID: pg("d2"), MemberOf: []model.RoleID{}}},
				Databases:  []model.Database{{Name: "postgres", Owner: "postgres"}},
				Privileges: []model.Privilege{{Grantee: pg("d2"), Object: db, Name: "TEMPORARY"}},
			},
			cur:      connectCur(),
			st:       connectState,
			stmt:     revokePrivileges("d2", db, []string{"CONNECT"}, false, plan.Keyword(" CASCADE")).WithRole("d1").WithDependents([]model.RoleID{pg("admin")}),
			wantWarn: `CONNECT on database "postgres" granted to "d2" differs from the configuration, but revoking it with CASCADE would also revoke CONNECT`,
		},
		{
			name: "REVOKE GRANT OPTION FOR CONNECT from a grantor of the connected user's CONNECT",
			desired: &model.Desired{Engine: model.EnginePostgres,
				Roles:      []model.Role{{ID: pg("d2"), MemberOf: []model.RoleID{}}},
				Databases:  []model.Database{{Name: "postgres", Owner: "postgres"}},
				Privileges: []model.Privilege{{Grantee: pg("d2"), Object: db, Name: "CONNECT"}},
			},
			cur:      connectCur(),
			st:       connectState,
			stmt:     revokePrivileges("d2", db, []string{"CONNECT"}, true, plan.Keyword(" CASCADE")).WithRole("d1").WithDependents([]model.RoleID{pg("admin")}),
			wantWarn: `grant option for CONNECT on database "postgres" granted to "d2" differs from the configuration, but revoking it with CASCADE would also revoke CONNECT`,
		},
		{
			name:     "REVOKE ADMIN OPTION from the grantor of the connected user's membership",
			desired:  xNoAdmin,
			cur:      memberCur(false),
			st:       func(d *model.Desired) *state { return memberState(d, false) },
			stmt:     revokeMembership("x", "ops", true, "admin", true).WithDependents([]model.RoleID{pg("admin")}),
			wantWarn: `ADMIN OPTION of "x" on "ops" differs from the configuration, but revoking it with CASCADE would also revoke memberships of "admin"`,
		},
		{
			name:     "REVOKE membership from the grantor of the connected user's membership",
			desired:  xNotMember,
			cur:      memberCur(false),
			st:       func(d *model.Desired) *state { return memberState(d, false) },
			stmt:     revokeMembership("x", "ops", false, "admin", true).WithDependents([]model.RoleID{pg("admin")}),
			wantWarn: `membership of "x" in "ops" differs from the configuration, but revoking it with CASCADE would also revoke memberships of "admin"`,
		},
		{
			name:     "REVOKE ADMIN OPTION from the grantor of a membership on the connected user's chain",
			desired:  xNoAdmin,
			cur:      memberCur(true),
			st:       func(d *model.Desired) *state { return memberState(d, true) },
			stmt:     revokeMembership("x", "ops", true, "admin", true).WithDependents([]model.RoleID{pg("mid")}),
			wantWarn: `ADMIN OPTION of "x" on "ops" differs from the configuration, but revoking it with CASCADE would also revoke memberships of "admin"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := diff.Compute(tt.desired, tt.cur, &Driver{st: tt.st(tt.desired)}, diff.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if got := sqlOf(p.Statements()); strings.Contains(got, "CASCADE") {
				t.Errorf("plan revokes with CASCADE:\n%s", got)
			}
			if !strings.Contains(strings.Join(p.Warnings, "\n"), tt.wantWarn) {
				t.Errorf("warnings = %q, want one containing %q", p.Warnings, tt.wantWarn)
			}
			if v := policy.Verify(p, tt.cur, tt.desired, policy.Options{System: Dialect{}}); len(v) != 0 {
				t.Errorf("Verify of the planned statements = %v, want none", v)
			}

			verify := func(s plan.Statement) []policy.Violation {
				return policy.Verify(&plan.Plan{Changes: []plan.Change{{Action: plan.ActionUpdate, Resource: "test", Statements: []plan.Statement{s}}}},
					tt.cur, tt.desired, policy.Options{System: Dialect{}})
			}
			if v := verify(tt.stmt); len(v) == 0 {
				t.Errorf("Verify passes %s", tt.stmt.SQL())
			}
			if v := verify(tt.stmt.WithDependents(nil)); len(v) != 0 {
				t.Errorf("Verify of %s without dependents = %v, want none", tt.stmt.SQL(), v)
			}
		})
	}
}
