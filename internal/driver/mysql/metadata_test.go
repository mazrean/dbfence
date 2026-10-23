package mysql

import (
	"testing"

	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
)

// The dialect says what each statement does and on which object, so that
// a plan can be checked without parsing its SQL.
func TestStatementMetadata(t *testing.T) {
	t.Parallel()
	d := Dialect{}
	u := model.RoleID{Name: "u", Host: "%"}
	g := model.RoleID{Name: "g", Host: "%"}
	pw := "pw"
	yes, no := true, false
	db := dbObj("app")
	pattern := model.Object{Type: model.ObjectDatabase, Database: "app_x", Pattern: "app\\_%"}
	type meta struct {
		change plan.RoleChange
		kind   plan.Kind
		target plan.Target
	}
	roleT := plan.Target{Object: plan.ObjectRole, Role: u}
	member := plan.Target{Object: plan.ObjectRole, Role: g, Grantee: u}
	onDB := plan.Target{Object: plan.ObjectDatabase, Database: "app", Grantee: u}
	tests := []struct {
		name  string
		stmts []plan.Statement
		want  []meta
	}{
		{
			name:  "create locked user with a password",
			stmts: d.CreateRole(model.Role{ID: u, Password: &pw, Login: &no}),
			want:  []meta{{kind: plan.KindCreateRole, target: roleT, change: plan.RoleChange{SetsPassword: true, LocksAccount: true}}},
		},
		{
			name:  "ensure user",
			stmts: d.EnsureRole(model.Role{ID: u}),
			want:  []meta{{kind: plan.KindCreateRole, target: roleT}},
		},
		{
			name: "alter user password, retained password and lock",
			stmts: first(d.AlterRole(model.Role{ID: u, Password: &pw, Login: &no},
				model.RoleState{ID: u, Login: true, AuthPlugin: "caching_sha2_password", RetainedPassword: true}, true)),
			want: []meta{
				{kind: plan.KindAlterRole, target: roleT, change: plan.RoleChange{SetsPassword: true}},
				{kind: plan.KindAlterRole, target: roleT, change: plan.RoleChange{SetsPassword: true}},
				{kind: plan.KindAlterRole, target: roleT, change: plan.RoleChange{LocksAccount: true}},
			},
		},
		{
			name:  "unlock user",
			stmts: first(d.AlterRole(model.Role{ID: u, Login: &yes}, model.RoleState{ID: u}, false)),
			want:  []meta{{kind: plan.KindAlterRole, target: roleT}},
		},
		{name: "drop user", stmts: d.DropRole(u, nil), want: []meta{{kind: plan.KindDropRole, target: roleT}}},
		{
			name:  "grant membership with admin",
			stmts: first(d.GrantMembership(u, g, model.MembershipOptions{Admin: &yes})),
			want:  []meta{{kind: plan.KindGrantMembership, target: member.WithOption(true)}},
		},
		{
			name:  "drop admin option",
			stmts: first(d.AlterMembership(u, g, model.MembershipOptions{Admin: &no}, model.MembershipState{Admin: true})),
			want:  []meta{{kind: plan.KindRevokeMembership, target: member}, {kind: plan.KindGrantMembership, target: member}},
		},
		{name: "revoke membership", stmts: first(d.RevokeMembership(u, g)), want: []meta{{kind: plan.KindRevokeMembership, target: member}}},
		{
			name:  "set default roles",
			stmts: d.SetDefaultRoles(model.Role{ID: u, MemberOf: []model.RoleID{g}}, model.RoleState{}),
			want:  []meta{{kind: plan.KindSetDefaultRole, target: roleT}},
		},
		{
			name:  "create database",
			stmts: d.CreateDatabase(model.Database{Name: "app", Charset: "utf8mb4"}),
			want:  []meta{{kind: plan.KindCreateDatabase, target: plan.Target{Object: plan.ObjectDatabase, Database: "app"}}},
		},
		{
			name:  "alter database",
			stmts: first(d.AlterDatabase(model.Database{Name: "app", Charset: "utf8mb4"}, model.Database{Name: "app", Charset: "latin1"})),
			want:  []meta{{kind: plan.KindAlterDatabase, target: plan.Target{Object: plan.ObjectDatabase, Database: "app"}}},
		},
		{name: "drop database", stmts: d.DropDatabase("app"), want: []meta{{kind: plan.KindDropDatabase, target: plan.Target{Object: plan.ObjectDatabase, Database: "app"}}}},
		{
			name:  "grant with grant option",
			stmts: d.Grant(u, db, []string{"SELECT"}, true),
			want:  []meta{{kind: plan.KindGrant, target: onDB.WithOption(true)}},
		},
		{
			name:  "revoke on a pattern",
			stmts: first(d.Revoke(u, pattern, []string{"SELECT"})),
			want:  []meta{{kind: plan.KindRevoke, target: plan.Target{Object: plan.ObjectDatabase, Database: "app_x", Pattern: "app\\_%", Grantee: u}}},
		},
		{
			name:  "revoke grant option",
			stmts: first(d.RevokeGrantOption(u, db, nil)),
			want:  []meta{{kind: plan.KindRevoke, target: onDB.WithOption(true)}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if len(tt.stmts) != len(tt.want) {
				t.Fatalf("got %d statements %q, want %d", len(tt.stmts), sqls(tt.stmts), len(tt.want))
			}
			for i, s := range tt.stmts {
				got := meta{kind: s.Kind(), target: s.Target(), change: s.RoleChange()}
				if got.change.ConnectionLimit != nil {
					t.Errorf("%s: MySQL statement sets a connection limit", s.SQL())
				}
				if got != tt.want[i] {
					t.Errorf("%s:\nmetadata %+v\nwant     %+v", s.SQL(), got, tt.want[i])
				}
			}
		})
	}
}
