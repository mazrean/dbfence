package mysql

import (
	"strings"
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

func TestRoleWarnings(t *testing.T) {
	t.Parallel()
	active := []string{"caching_sha2_password", "sha256_password"}
	tests := []struct {
		name    string
		role    model.Role
		cur     []model.RoleState
		plugins []string
		want    []string
	}{
		{name: "new account without password", role: model.Role{ID: app, Login: new(true)}, plugins: active, want: []string{`"app"@"%" can log in without a password`}},
		{
			name: "existing account with an empty password", role: model.Role{ID: app, Login: new(true)}, plugins: active,
			cur:  []model.RoleState{{ID: app, AuthPlugin: "caching_sha2_password", PasswordReadable: true}},
			want: []string{`"app"@"%" can log in without a password`},
		},
		{
			name: "existing account with a password", role: model.Role{ID: app, Login: new(true)}, plugins: active,
			cur: []model.RoleState{{ID: app, AuthPlugin: "caching_sha2_password", PasswordReadable: true, PasswordHash: []byte("$A$005$x")}},
		},
		{
			name: "existing account with unknown credentials", role: model.Role{ID: app, Login: new(true)}, plugins: active,
			cur: []model.RoleState{{ID: app, AttributesUnknown: true}},
		},
		{
			name: "existing account on a passwordless plugin", role: model.Role{ID: app, Login: new(true)}, plugins: active,
			cur: []model.RoleState{{ID: app, AuthPlugin: "auth_socket", PasswordReadable: true}},
		},
		{name: "role", role: model.Role{ID: app, Login: new(false)}, plugins: active},
		{name: "declared password", role: model.Role{ID: app, Login: new(true), Password: new("p")}, plugins: active},
		{name: "active plugin", role: model.Role{ID: app, Login: new(true), Password: new("p"), AuthPlugin: "SHA256_PASSWORD"}, plugins: active},
		{
			name: "password plugin without password", role: model.Role{ID: app, Login: new(true), AuthPlugin: "sha256_password"}, plugins: active,
			want: []string{`"app"@"%" can log in without a password`},
		},
		{name: "passwordless plugin", role: model.Role{ID: app, Login: new(true), AuthPlugin: "auth_socket"}, plugins: []string{"auth_socket"}},
		{
			name: "inactive plugin", role: model.Role{ID: app, Login: new(true), Password: new("p"), AuthPlugin: "mysql_native_password"}, plugins: active,
			want: []string{`auth_plugin "mysql_native_password" of "app"@"%" is not an active authentication plugin on the server (MySQL 8.4 loads it only with --mysql-native-password=ON)`},
		},
		{name: "unknown plugins", role: model.Role{ID: app, Login: new(true), Password: new("p"), AuthPlugin: "mysql_native_password"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := roleWarnings(&model.Desired{Roles: []model.Role{tt.role}}, &model.Current{Roles: tt.cur}, tt.plugins)
			if len(got) != len(tt.want) {
				t.Fatalf("warnings = %q, want %q", got, tt.want)
			}
			for i, w := range tt.want {
				if !strings.Contains(got[i], w) {
					t.Errorf("warning %q does not contain %q", got[i], w)
				}
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
