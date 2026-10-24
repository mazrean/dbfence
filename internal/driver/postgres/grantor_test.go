package postgres

import (
	"testing"

	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
	"github.com/mazrean/dbfence/internal/policy"
)

// TestPolicySeesGrantedBy checks that the grantor a statement names in
// GRANTED BY is in its Target, so that the plan check refuses a grantor
// dbfence does not manage.
func TestPolicySeesGrantedBy(t *testing.T) {
	t.Parallel()
	bad := "evil\n"
	yes := true
	tests := []struct {
		name    string
		grantor string
		stmt    plan.Statement
		want    int
	}{
		{name: "revoke granted by an unmanaged role", stmt: revokeMembership("hu", "grp", false, bad, false), grantor: bad, want: 1},
		{name: "revoke of admin option with CASCADE", stmt: revokeMembership("hu", "grp", true, bad, true), grantor: bad, want: 1},
		{name: "grant granted by an unmanaged role", stmt: grantMembership("hu", "grp", model.MembershipOptions{Inherit: &yes}, bad), grantor: bad, want: 1},
		{name: "revoke granted by a managed role", stmt: revokeMembership("hu", "grp", false, "postgres", false), grantor: "postgres"},
		{name: "revoke without GRANTED BY", stmt: revokeMembership("hu", "grp", false, "", false)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.stmt.Target().Grantor; got != (model.RoleID{Name: tt.grantor}) {
				t.Errorf("%s: Target().Grantor = %q, want %q", tt.stmt.SQL(), got.Name, tt.grantor)
			}
			p := &plan.Plan{Changes: []plan.Change{{Action: plan.ActionDrop, Resource: "test", Statements: []plan.Statement{tt.stmt}}}}
			desired := &model.Desired{Engine: model.EnginePostgres, Roles: []model.Role{{ID: pg("hu")}}}
			cur := &model.Current{CurrentUser: pg("postgres"), Roles: []model.RoleState{{ID: pg("postgres")}, {ID: pg("hu")}, {ID: pg("grp")}}}
			if v := policy.Verify(p, cur, desired, policy.Options{System: Dialect{}}); len(v) != tt.want {
				t.Errorf("%s: violations %v, want %d", tt.stmt.SQL(), v, tt.want)
			}
		})
	}
}
