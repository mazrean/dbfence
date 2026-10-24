package diff_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/driver/postgres"
	"github.com/mazrean/dbfence/internal/model"
)

// NOINHERIT on the connected user would take away the privileges of all
// its roles, so it is not planned.
func TestComputeConnectedUserInherit(t *testing.T) {
	t.Parallel()
	no := false
	admin, ops := pgID("admin"), pgID("ops")
	warn := `not setting NOINHERIT on the connected user "admin": it would lose the privileges of its roles, which dbfence may rely on`
	tests := []struct {
		name       string
		declare    model.Role
		want       []string
		warns      []string
		cur        model.RoleState
		unreadable bool
	}{
		{
			name:    "inherit removed",
			declare: model.Role{ID: admin, Inherit: &no},
			cur:     model.RoleState{ID: admin, Login: true, Inherit: true, MemberOf: []model.RoleID{ops}},
			warns:   []string{warn},
		},
		{
			name:    "inherit already off, memberships with inherit",
			declare: model.Role{ID: admin, Inherit: &no},
			cur: model.RoleState{ID: admin, Login: true, MemberOf: []model.RoleID{ops},
				MemberOptions: map[model.RoleID]model.MembershipState{ops: {Inherit: true}}},
			warns: []string{warn},
		},
		{
			name:    "inherit already off",
			declare: model.Role{ID: admin, Inherit: &no},
			cur:     model.RoleState{ID: admin, Login: true, MemberOf: []model.RoleID{ops}},
		},
		{
			name:       "role list unreadable",
			declare:    model.Role{ID: admin, Inherit: &no},
			unreadable: true,
			want:       []string{`CREATE ROLE "admin"`},
			warns:      []string{warn},
		},
		{
			name:    "another role",
			declare: model.Role{ID: ops, Inherit: &no},
			cur:     model.RoleState{ID: admin, Login: true, Inherit: true, MemberOf: []model.RoleID{ops}},
			want:    []string{`ALTER ROLE "ops" WITH NOINHERIT`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cur := &model.Current{CurrentUser: admin, Roles: []model.RoleState{tt.cur, {ID: ops, Inherit: true}}}
			if tt.unreadable {
				cur.Roles = nil
				cur.Unreadable.Roles = true
			}
			p, err := compute(t, &model.Desired{Engine: model.EnginePostgres, Roles: []model.Role{tt.declare}}, cur, postgres.Dialect{}, diff.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(tt.want, statements(p), cmpopts.EquateEmpty()); d != "" {
				t.Errorf("statements (-want +got):\n%s", d)
			}
			warns := slices.DeleteFunc(slices.Clone(p.Warnings), func(w string) bool {
				return strings.HasPrefix(w, "unmanaged ") || strings.HasPrefix(w, "cannot ")
			})
			if d := cmp.Diff(tt.warns, warns, cmpopts.EquateEmpty()); d != "" {
				t.Errorf("warnings (-want +got):\n%s", d)
			}
		})
	}
}

// admin -> ops -> dba: PostgreSQL 16 needs INHERIT (or SET) on every
// membership along the chain, and before 16 the INHERIT attribute of
// ops decides whether admin gets the privileges of dba through it. None
// of them may be turned off on ops while admin has its roles through it.
func TestComputeChainInheritAndSet(t *testing.T) {
	t.Parallel()
	no, yes := false, true
	admin, ops, dba, app := pgID("admin"), pgID("ops"), pgID("dba"), pgID("app")
	all := model.MembershipState{Inherit: true, Set: true}
	member := func(id model.RoleID, o model.MembershipOptions) model.Role {
		return model.Role{ID: id, MemberOf: []model.RoleID{dba}, MemberOptions: map[model.RoleID]model.MembershipOptions{dba: o}}
	}
	tests := []struct {
		name    string
		declare []model.Role
		want    []string
		warns   []string
	}{
		{
			name:    "inherit false on the membership of ops",
			declare: []model.Role{{ID: dba}, member(ops, model.MembershipOptions{Inherit: &no})},
			warns:   []string{`not setting inherit = false on the membership of "ops" in "dba", through which the connected user "admin" has its roles: dbfence may rely on its privileges`},
		},
		{
			name:    "set false on the membership of ops",
			declare: []model.Role{{ID: dba}, member(ops, model.MembershipOptions{Set: &no})},
			warns:   []string{`not setting set = false on the membership of "ops" in "dba", through which the connected user "admin" has its roles: dbfence may rely on SET ROLE to it`},
		},
		{
			name:    "noinherit on ops",
			declare: []model.Role{{ID: dba}, {ID: ops, Inherit: &no, MemberOf: []model.RoleID{dba}}},
			warns:   []string{`not setting NOINHERIT on "ops": the connected user "admin" has its roles through it, and dbfence may rely on their privileges`},
		},
		{
			name:    "noinherit on the end of the chain",
			declare: []model.Role{{ID: dba, Inherit: &no}},
			want:    []string{`ALTER ROLE "dba" WITH NOINHERIT`},
		},
		{
			name: "options off on a role outside the chain, inherit on in it",
			declare: []model.Role{
				{ID: dba},
				member(app, model.MembershipOptions{Inherit: &no, Set: &no}),
				{ID: admin, MemberOf: []model.RoleID{ops}, MemberOptions: map[model.RoleID]model.MembershipOptions{ops: {Inherit: &yes}}},
			},
			want: []string{`GRANT "dba" TO "app" WITH INHERIT FALSE, SET FALSE`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cur := &model.Current{CurrentUser: admin, Roles: []model.RoleState{
				{ID: admin, Login: true, Inherit: true, MemberOf: []model.RoleID{ops}, MemberOptions: map[model.RoleID]model.MembershipState{ops: all}},
				{ID: ops, Inherit: true, MemberOf: []model.RoleID{dba}, MemberOptions: map[model.RoleID]model.MembershipState{dba: all}},
				{ID: dba, Inherit: true},
				{ID: app, Login: true},
			}}
			p, err := compute(t, &model.Desired{Engine: model.EnginePostgres, Roles: tt.declare}, cur, postgres.Dialect{}, diff.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(tt.want, statements(p), cmpopts.EquateEmpty()); d != "" {
				t.Errorf("statements (-want +got):\n%s", d)
			}
			warns := slices.DeleteFunc(slices.Clone(p.Warnings), func(w string) bool {
				return strings.HasPrefix(w, "unmanaged ") || strings.HasPrefix(w, "cannot ")
			})
			if d := cmp.Diff(tt.warns, warns, cmpopts.EquateEmpty()); d != "" {
				t.Errorf("warnings (-want +got):\n%s", d)
			}
		})
	}
}
