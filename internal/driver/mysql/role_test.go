package mysql

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mazrean/dbfence/internal/model"
)

func TestCreateRolePlugin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		want string
		role model.Role
	}{
		{name: "plugin without password", role: model.Role{ID: app, AuthPlugin: "sha256_password"}, want: "CREATE USER 'app'@'%' IDENTIFIED WITH sha256_password"},
		{name: "passwordless plugin", role: model.Role{ID: app, AuthPlugin: "AWSAuthenticationPlugin"}, want: "CREATE USER 'app'@'%' IDENTIFIED WITH AWSAuthenticationPlugin"},
		{name: "plugin with password", role: model.Role{ID: app, AuthPlugin: "caching_sha2_password", Password: new("p")}, want: "CREATE USER 'app'@'%' IDENTIFIED WITH caching_sha2_password BY '<redacted>'"},
		{
			name: "plugin is quoted",
			role: model.Role{ID: app, AuthPlugin: "mysql_native_password AS '*0' -- ", Password: new("p")},
			want: "CREATE USER 'app'@'%' IDENTIFIED WITH `mysql_native_password AS '*0' -- ` BY '<redacted>'",
		},
		{name: "plugin with backtick", role: model.Role{ID: app, AuthPlugin: "a`b"}, want: "CREATE USER 'app'@'%' IDENTIFIED WITH `a``b`"},
		{name: "neither", role: model.Role{ID: app}, want: "CREATE USER 'app'@'%'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sqls(Dialect{}.CreateRole(tt.role)); got[0] != tt.want {
				t.Errorf("CreateRole = %s, want %s", got[0], tt.want)
			}
		})
	}
}

func TestAlterRolePlugin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		role      model.Role
		want      []string
		cur       model.RoleState
		wantWarns int
	}{
		{
			name: "plugin compared case-insensitively",
			role: model.Role{ID: app, AuthPlugin: "CACHING_SHA2_PASSWORD"},
			cur:  model.RoleState{ID: app, AuthPlugin: "caching_sha2_password"},
		},
		{
			name: "passwordless plugin is switched",
			role: model.Role{ID: app, AuthPlugin: "auth_socket"},
			cur:  model.RoleState{ID: app, AuthPlugin: "caching_sha2_password"},
			want: []string{"ALTER USER 'app'@'%' IDENTIFIED WITH auth_socket"},
		},
		{
			name:      "password plugin needs a password",
			role:      model.Role{ID: app, AuthPlugin: "sha256_password"},
			cur:       model.RoleState{ID: app, AuthPlugin: "caching_sha2_password"},
			wantWarns: 1,
		},
		{
			name: "plugin change sets the password",
			role: model.Role{ID: app, AuthPlugin: "mysql_native_password", Password: new("p")},
			cur:  model.RoleState{ID: app, AuthPlugin: "caching_sha2_password"},
			want: []string{"ALTER USER 'app'@'%' IDENTIFIED WITH mysql_native_password BY '<redacted>'"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stmts, warns := Dialect{}.AlterRole(tt.role, tt.cur, false)
			if d := cmp.Diff(tt.want, sqls(stmts)); d != "" {
				t.Errorf("statements (-want +got):\n%s", d)
			}
			if len(warns) != tt.wantWarns {
				t.Errorf("warnings = %q, want %d", warns, tt.wantWarns)
			}
		})
	}
}
