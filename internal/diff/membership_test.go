package diff_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/driver/postgres"
	"github.com/mazrean/dbfence/internal/model"
)

func TestComputeMembershipOptions(t *testing.T) {
	t.Parallel()
	yes, no := true, false
	state := func(admin, inherit, set bool) map[model.RoleID]model.MembershipState {
		return map[model.RoleID]model.MembershipState{pgID("g"): {Admin: admin, Inherit: inherit, Set: set}}
	}
	tests := []struct {
		opts       *model.MembershipOptions
		have       map[model.RoleID]model.MembershipState
		name       string
		want       []string
		warns      []string
		member     bool
		unreadable bool
		connected  bool
	}{
		{
			name: "new membership carries the options",
			opts: &model.MembershipOptions{Admin: &yes, Inherit: &no},
			want: []string{`GRANT "g" TO "u" WITH ADMIN TRUE, INHERIT FALSE`},
		},
		{
			name: "converged", member: true, have: state(true, false, true),
			opts: &model.MembershipOptions{Admin: &yes, Inherit: &no, Set: &yes},
		},
		{
			name: "omitted options are not managed", member: true, have: state(true, false, false),
			opts: &model.MembershipOptions{Inherit: &no},
		},
		{name: "string form manages no options", member: true, have: state(true, false, false)},
		{
			name: "drift", member: true, have: state(true, true, true),
			opts: &model.MembershipOptions{Admin: &no, Set: &no},
			want: []string{`REVOKE ADMIN OPTION FOR "g" FROM "u"`, `GRANT "g" TO "u" WITH SET FALSE`},
		},
		{
			name: "unknown memberships are granted with the options", member: true, unreadable: true,
			opts: &model.MembershipOptions{Admin: &yes},
			want: []string{`GRANT "g" TO "u" WITH ADMIN OPTION`},
		},
		{
			name: "connected user keeps admin", member: true, connected: true, have: state(true, true, true),
			opts:  &model.MembershipOptions{Admin: &no, Inherit: &no},
			want:  []string{`GRANT "g" TO "u" WITH INHERIT FALSE`},
			warns: []string{`not revoking ADMIN OPTION on "g" from the connected user "u": dbfence may rely on it`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			role := model.Role{ID: pgID("u"), MemberOf: []model.RoleID{pgID("g")}}
			if tt.opts != nil {
				role.MemberOptions = map[model.RoleID]model.MembershipOptions{pgID("g"): *tt.opts}
			}
			u := model.RoleState{ID: pgID("u")}
			if tt.member {
				u.MemberOf, u.MemberOptions = []model.RoleID{pgID("g")}, tt.have
			}
			cur := &model.Current{CurrentUser: pgID("admin"), Roles: []model.RoleState{{ID: pgID("admin"), Superuser: true, Login: true}, u, {ID: pgID("g")}}}
			if tt.connected {
				cur.CurrentUser = pgID("u")
			}
			cur.Unreadable.Memberships = tt.unreadable
			p, err := diff.Compute(&model.Desired{Engine: model.EnginePostgres, Roles: []model.Role{role, {ID: pgID("g")}}}, cur, postgres.Dialect{}, diff.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(tt.want, statements(p), cmpopts.EquateEmpty()); d != "" {
				t.Errorf("statements (-want +got):\n%s", d)
			}
			var warns []string
			for _, w := range p.Warnings {
				if !tt.unreadable && w != "unmanaged user \"admin\" (use --prune to drop it)" {
					warns = append(warns, w)
				}
			}
			if d := cmp.Diff(tt.warns, warns, cmpopts.EquateEmpty()); d != "" {
				t.Errorf("warnings (-want +got):\n%s", d)
			}
		})
	}
}
