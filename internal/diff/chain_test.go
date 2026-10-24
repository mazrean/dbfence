package diff_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/driver/mysql"
	"github.com/mazrean/dbfence/internal/driver/postgres"
	"github.com/mazrean/dbfence/internal/model"
)

// Memberships of other roles through which the connected user has roles
// are not revoked: it would lose those roles as if its own membership
// were revoked.
func TestComputeConnectedUserChain(t *testing.T) {
	t.Parallel()
	no := false
	role := func(id model.RoleID, memberOf ...model.RoleID) model.RoleState {
		return model.RoleState{ID: id, MemberOf: memberOf}
	}
	declare := func(id model.RoleID, memberOf ...model.RoleID) model.Role {
		return model.Role{ID: id, MemberOf: append([]model.RoleID{}, memberOf...)}
	}
	admin, ops, ops2, dba, top := pgID("admin"), pgID("ops"), pgID("ops2"), pgID("dba"), pgID("top")
	me, myOps, myDBA := model.RoleID{Name: "dbfence", Host: "%"}, model.RoleID{Name: "ops", Host: "%"}, model.RoleID{Name: "dba", Host: "%"}
	tests := []struct {
		dialect diff.Dialect
		name    string
		roles   []model.RoleState
		declare []model.Role
		want    []string
		warns   []string
	}{
		{
			name:    "intermediate membership",
			roles:   []model.RoleState{role(admin, ops), role(ops, dba), role(dba)},
			declare: []model.Role{declare(ops)},
			warns:   []string{`not revoking membership of "ops" in "dba": the connected user "admin" is a member of "dba" through it`},
		},
		{
			name:    "role reached further up the chain",
			roles:   []model.RoleState{role(admin, ops, dba), role(ops, dba, top), role(dba), role(top)},
			declare: []model.Role{declare(ops, dba)},
			warns:   []string{`not revoking membership of "ops" in "top": the connected user "admin" is a member of "top" through it`},
		},
		{
			name:    "role also granted directly",
			roles:   []model.RoleState{role(admin, ops, dba), role(ops, dba), role(dba)},
			declare: []model.Role{declare(ops)},
			want:    []string{`REVOKE "dba" FROM "ops"`},
		},
		{
			name:    "the last of two paths",
			roles:   []model.RoleState{role(admin, ops, ops2), role(ops, dba), role(ops2, dba), role(dba)},
			declare: []model.Role{declare(ops), declare(ops2)},
			want:    []string{`REVOKE "dba" FROM "ops"`},
			warns:   []string{`not revoking membership of "ops2" in "dba": the connected user "admin" is a member of "dba" through it`},
		},
		{
			name:    "role the connected user does not reach",
			roles:   []model.RoleState{role(admin), role(ops, dba), role(dba)},
			declare: []model.Role{declare(ops)},
			want:    []string{`REVOKE "dba" FROM "ops"`},
		},
		{
			name:    "mysql admin option dropped by revoke and grant",
			dialect: mysql.Dialect{},
			roles: []model.RoleState{
				{ID: me, MemberOf: []model.RoleID{myOps}, DefaultRoles: []model.RoleID{myOps}},
				{ID: myOps, MemberOf: []model.RoleID{myDBA}, MemberOptions: map[model.RoleID]model.MembershipState{myDBA: {Admin: true}}, DefaultRoles: []model.RoleID{myDBA}},
				{ID: myDBA},
			},
			declare: []model.Role{{ID: myOps, MemberOf: []model.RoleID{myDBA}, MemberOptions: map[model.RoleID]model.MembershipOptions{myDBA: {Admin: &no}}}},
			warns:   []string{`not changing the options of membership of "ops"@"%" in "dba"@"%": that revokes the membership and grants it again, and the connected user "dbfence"@"%" is a member of "dba"@"%" through it`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d, engine := tt.dialect, model.EngineMySQL
			if d == nil {
				d, engine = postgres.Dialect{}, model.EnginePostgres
			}
			cur := &model.Current{CurrentUser: tt.roles[0].ID, Roles: tt.roles}
			p, err := compute(t, &model.Desired{Engine: engine, Roles: tt.declare}, cur, d, diff.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(tt.want, statements(p), cmpopts.EquateEmpty()); d != "" {
				t.Errorf("statements (-want +got):\n%s", d)
			}
			warns := slices.DeleteFunc(slices.Clone(p.Warnings), func(w string) bool { return strings.HasPrefix(w, "unmanaged ") })
			if len(warns) != len(tt.warns) {
				t.Fatalf("warnings = %q, want %d matching %q", warns, len(tt.warns), tt.warns)
			}
			for i, w := range tt.warns {
				if !strings.Contains(warns[i], w) {
					t.Errorf("warning %d = %q, want substring %q", i, warns[i], w)
				}
			}
		})
	}
}
