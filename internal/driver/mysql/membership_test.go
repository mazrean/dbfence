package mysql

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mazrean/dbfence/internal/model"
)

func TestMembershipAdminOption(t *testing.T) {
	t.Parallel()
	yes, no := true, false
	admin := func(v bool) map[model.RoleID]model.MembershipState {
		return map[model.RoleID]model.MembershipState{reader: {Admin: v, Inherit: true, Set: true}}
	}
	tests := []struct {
		opts      *model.MembershipOptions
		name      string
		want      []string
		warns     []string
		cur       model.RoleState
		connected bool
	}{
		{
			name: "new membership with admin",
			opts: &model.MembershipOptions{Admin: &yes},
			cur:  model.RoleState{ID: app, Login: true},
			want: []string{"GRANT 'reader'@'%' TO 'app'@'%' WITH ADMIN OPTION", "SET DEFAULT ROLE 'reader'@'%' TO 'app'@'%'"},
		},
		{
			name: "add admin",
			opts: &model.MembershipOptions{Admin: &yes},
			cur:  model.RoleState{ID: app, Login: true, MemberOf: []model.RoleID{reader}, MemberOptions: admin(false), DefaultRoles: []model.RoleID{reader}},
			want: []string{"GRANT 'reader'@'%' TO 'app'@'%' WITH ADMIN OPTION"},
		},
		{
			name: "drop admin revokes, grants again and restores the default role",
			opts: &model.MembershipOptions{Admin: &no},
			cur:  model.RoleState{ID: app, Login: true, MemberOf: []model.RoleID{reader}, MemberOptions: admin(true), DefaultRoles: []model.RoleID{reader}},
			want: []string{"REVOKE 'reader'@'%' FROM 'app'@'%'", "GRANT 'reader'@'%' TO 'app'@'%'", "SET DEFAULT ROLE 'reader'@'%' TO 'app'@'%'"},
		},
		{
			name: "converged admin",
			opts: &model.MembershipOptions{Admin: &yes},
			cur:  model.RoleState{ID: app, Login: true, MemberOf: []model.RoleID{reader}, MemberOptions: admin(true), DefaultRoles: []model.RoleID{reader}},
		},
		{
			name: "string form leaves admin alone",
			cur:  model.RoleState{ID: app, Login: true, MemberOf: []model.RoleID{reader}, MemberOptions: admin(true), DefaultRoles: []model.RoleID{reader}},
		},
		{
			name: "connected user keeps admin", connected: true,
			opts:  &model.MembershipOptions{Admin: &no},
			cur:   model.RoleState{ID: app, Login: true, MemberOf: []model.RoleID{reader}, MemberOptions: admin(true), DefaultRoles: []model.RoleID{reader}},
			warns: []string{`not revoking ADMIN OPTION on "reader"@"%" from the connected user "app"@"%": dbfence may rely on it`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			role := model.Role{ID: app, Login: new(true), MemberOf: []model.RoleID{reader}}
			if tt.opts != nil {
				role.MemberOptions = map[model.RoleID]model.MembershipOptions{reader: *tt.opts}
			}
			cur := &model.Current{CurrentUser: model.RoleID{Name: "root", Host: "localhost"}, Roles: []model.RoleState{tt.cur, {ID: reader}}}
			if tt.connected {
				cur.CurrentUser = app
			}
			got, warns := planSQL(t, &model.Desired{Engine: model.EngineMySQL, Roles: []model.Role{role, {ID: reader, Login: new(false)}}}, cur, Dialect{})
			if d := cmp.Diff(tt.want, got); d != "" {
				t.Errorf("statements (-want +got):\n%s", d)
			}
			if d := cmp.Diff(tt.warns, warns); d != "" {
				t.Errorf("warnings (-want +got):\n%s", d)
			}
		})
	}
}
