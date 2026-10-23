package policy_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/driver/mysql"
	"github.com/mazrean/dbfence/internal/driver/postgres"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
	"github.com/mazrean/dbfence/internal/policy"
)

func my(name string) model.RoleID { return model.RoleID{Name: name, Host: "%"} }

// myCurrent is a MySQL server where the connected account dbfence has
// dba_role and app_role, with dba_role as its default role.
func myCurrent() *model.Current {
	return &model.Current{
		CurrentUser: my("dbfence"),
		Roles: []model.RoleState{
			{ID: my("dbfence"), Login: true, MemberOf: []model.RoleID{my("dba_role"), my("app_role")}, DefaultRoles: []model.RoleID{my("dba_role")}},
			{ID: my("dba_role")},
			{ID: my("app_role")},
			{ID: my("app"), Login: true, MemberOf: []model.RoleID{my("app_role")}, DefaultRoles: []model.RoleID{my("app_role")}},
		},
	}
}

// Statements built by the engine dialects, as diff would plan them, that
// the check must refuse or pass.
func TestVerifyDialectStatements(t *testing.T) {
	t.Parallel()
	myd, pgd := mysql.Dialect{}, postgres.Dialect{}
	roleState := func(c *model.Current, id model.RoleID) model.RoleState {
		if i := slices.IndexFunc(c.Roles, func(r model.RoleState) bool { return r.ID == id }); i >= 0 {
			return c.Roles[i]
		}
		return model.RoleState{ID: id}
	}
	setDefaults := func(c *model.Current, id model.RoleID, roles ...model.RoleID) []plan.Statement {
		return myd.SetDefaultRoles(model.Role{ID: id, MemberOf: roles}, roleState(c, id))
	}
	unknownDefaults := myCurrent()
	unknownDefaults.Roles[0].DefaultRoles, unknownDefaults.Roles[0].DefaultRolesUnknown = nil, true
	tests := []struct {
		current *model.Current
		desired *model.Desired
		name    string
		want    []string
		stmts   []plan.Statement
		pg      bool
	}{
		{
			name:  "default role none on the connected account",
			stmts: setDefaults(myCurrent(), my("dbfence")),
			want:  []string{`removes "dba_role"@"%" from the default roles of the connected user "dbfence"@"%"`},
		},
		{
			name:  "default roles of the connected account narrowed",
			stmts: setDefaults(myCurrent(), my("dbfence"), my("app_role")),
			want:  []string{`removes "dba_role"@"%" from the default roles`},
		},
		{name: "default roles of the connected account kept", stmts: setDefaults(myCurrent(), my("dbfence"), my("app_role"), my("dba_role"))},
		{name: "default role none on another account", stmts: setDefaults(myCurrent(), my("app"))},
		{
			name:    "unknown default roles of the connected account",
			current: unknownDefaults,
			stmts:   setDefaults(unknownDefaults, my("dbfence"), my("dba_role")),
			want:    []string{`removes "app_role"@"%" from the default roles`},
		},
		{
			name:    "unknown default roles of the connected account keep its memberships",
			current: unknownDefaults,
			stmts:   setDefaults(unknownDefaults, my("dbfence"), my("dba_role"), my("app_role")),
		},
		{
			name:    "connected account missing from the role list",
			current: &model.Current{CurrentUser: my("dbfence")},
			stmts:   setDefaults(myCurrent(), my("dbfence"), my("dba_role"), my("app_role")),
			want:    []string{"current default roles are unknown"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var system policy.System = myd
			cur, desired := myCurrent(), &model.Desired{Engine: model.EngineMySQL}
			if tt.pg {
				system, cur, desired = pgd, pgCurrent(), pgDesired()
			}
			if tt.current != nil {
				cur = tt.current
			}
			if tt.desired != nil {
				desired = tt.desired
			}
			p := &plan.Plan{Changes: []plan.Change{{Action: plan.ActionUpdate, Resource: "test", Statements: tt.stmts}}}
			got := policy.Verify(p, cur, desired, policy.Options{System: system, Prune: true})
			if len(got) != len(tt.want) {
				t.Fatalf("violations = %v, want %d matching %q", got, len(tt.want), tt.want)
			}
			for i, w := range tt.want {
				if s := got[i].String(); !strings.Contains(s, w) {
					t.Errorf("violation %d = %q, want substring %q", i, s, w)
				}
			}
		})
	}
}
