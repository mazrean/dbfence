package mysql

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mazrean/dbfence/internal/model"
)

func TestSetDefaultRoles(t *testing.T) {
	t.Parallel()
	writer := model.RoleID{Name: "writer", Host: "%"}
	tests := []struct {
		name     string
		memberOf []model.RoleID
		want     []string
		cur      model.RoleState
	}{
		{
			name:     "memberships granted by this plan are activated once",
			memberOf: []model.RoleID{reader, writer},
			cur:      model.RoleState{ID: app, Login: true},
			want: []string{
				"GRANT 'reader'@'%' TO 'app'@'%'",
				"GRANT 'writer'@'%' TO 'app'@'%'",
				"SET DEFAULT ROLE 'reader'@'%', 'writer'@'%' TO 'app'@'%'",
			},
		},
		{
			name:     "existing membership that is not a default role",
			memberOf: []model.RoleID{reader},
			cur:      model.RoleState{ID: app, Login: true, MemberOf: []model.RoleID{reader}},
			want:     []string{"SET DEFAULT ROLE 'reader'@'%' TO 'app'@'%'"},
		},
		{
			name:     "converged",
			memberOf: []model.RoleID{reader, writer},
			cur:      model.RoleState{ID: app, Login: true, MemberOf: []model.RoleID{writer, reader}, DefaultRoles: []model.RoleID{writer, reader}},
		},
		{
			name:     "unknown default roles are asserted",
			memberOf: []model.RoleID{reader},
			cur:      model.RoleState{ID: app, Login: true, MemberOf: []model.RoleID{reader}, DefaultRolesUnknown: true},
			want:     []string{"SET DEFAULT ROLE 'reader'@'%' TO 'app'@'%'"},
		},
		{
			name:     "revoked membership",
			memberOf: []model.RoleID{},
			cur:      model.RoleState{ID: app, Login: true, MemberOf: []model.RoleID{reader}, DefaultRoles: []model.RoleID{reader}},
			want:     []string{"REVOKE 'reader'@'%' FROM 'app'@'%'", "SET DEFAULT ROLE NONE TO 'app'@'%'"},
		},
		{
			name:     "no memberships and unknown default roles",
			memberOf: []model.RoleID{},
			cur:      model.RoleState{ID: app, Login: true, DefaultRolesUnknown: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			desired := &model.Desired{
				Engine: model.EngineMySQL,
				Roles:  []model.Role{{ID: reader}, {ID: writer}, {ID: app, MemberOf: tt.memberOf}},
			}
			cur := &model.Current{
				CurrentUser: model.RoleID{Name: "root", Host: "%"},
				Roles:       []model.RoleState{{ID: reader}, {ID: writer}, tt.cur},
			}
			got, _ := planSQL(t, desired, cur, Dialect{})
			if d := cmp.Diff(tt.want, got); d != "" {
				t.Errorf("statements (-want +got):\n%s", d)
			}
		})
	}
}

func TestDefaultRolesWarning(t *testing.T) {
	t.Parallel()
	unknown := &model.Current{Roles: []model.RoleState{{ID: app, DefaultRolesUnknown: true}}}
	known := &model.Current{Roles: []model.RoleState{{ID: app}}}
	withMembers := &model.Desired{Roles: []model.Role{{ID: app, MemberOf: []model.RoleID{reader}}}}
	withoutMembers := &model.Desired{Roles: []model.Role{{ID: app}}}
	tests := []struct {
		desired *model.Desired
		cur     *model.Current
		name    string
		want    bool
	}{
		{name: "unreadable with managed memberships", desired: withMembers, cur: unknown, want: true},
		{name: "unreadable without managed memberships", desired: withoutMembers, cur: unknown},
		{name: "readable", desired: withMembers, cur: known},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := defaultRolesWarning(tt.desired, tt.cur); (got != "") != tt.want {
				t.Errorf("defaultRolesWarning() = %q, want a warning: %v", got, tt.want)
			}
		})
	}
}
