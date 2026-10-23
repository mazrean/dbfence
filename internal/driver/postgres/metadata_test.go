package postgres

import (
	"strconv"
	"testing"

	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
)

// The dialect says what each statement does and on which object, so that
// a plan can be checked without parsing its SQL.
func TestStatementMetadata(t *testing.T) {
	t.Parallel()
	d := Dialect{}
	pw := "pw"
	yes, no := true, false
	limit := 3
	r := pg("r")
	g := pg("g")
	db := model.Object{Type: model.ObjectDatabase, Database: "app"}
	sch := model.Schema{Database: "app", Name: "s"}
	schObj := model.Object{Type: model.ObjectSchema, Database: "app", Schema: "s"}
	type meta struct {
		change plan.RoleChange
		kind   plan.Kind
		// limit is the connection limit set, or "" for none.
		limit  string
		target plan.Target
	}
	roleT := plan.Target{Object: plan.ObjectRole, Role: r}
	inApp := roleT
	inApp.Database = "app"
	member := plan.Target{Object: plan.ObjectRole, Role: g, Grantee: r}
	dbT := plan.Target{Object: plan.ObjectDatabase, Database: "app"}
	schT := plan.Target{Object: plan.ObjectSchema, Database: "app", Schema: "s"}
	// A Driver that revokes another grantor's grant as that grantor.
	drv := &Driver{st: &state{
		desired: &model.Desired{}, user: "adm", superuser: true, version: 170000,
		owners: map[model.Object]string{db: "o"},
		acl:    []aclEntry{{obj: db, grantee: "r", grantor: "h", priv: "CONNECT", grantable: true}},
	}}
	tests := []struct {
		name  string
		stmts []plan.Statement
		want  []meta
	}{
		{
			name:  "create role",
			stmts: d.CreateRole(model.Role{ID: r, Login: &no, Superuser: &no, ConnectionLimit: &limit, Password: &pw}),
			want: []meta{{
				kind: plan.KindCreateRole, target: roleT, limit: "3",
				change: plan.RoleChange{DisablesLogin: true, RemovesSuperuser: true, SetsPassword: true},
			}},
		},
		{
			name: "alter role: only what changes",
			stmts: first(d.AlterRole(model.Role{ID: r, Login: &no, Superuser: &no, CreateDB: &yes},
				model.RoleState{ID: r, Login: true}, false)),
			want: []meta{{kind: plan.KindAlterRole, target: roleT, change: plan.RoleChange{DisablesLogin: true}}},
		},
		{
			name: "alter role: superuser removed, limit set",
			stmts: first(d.AlterRole(model.Role{ID: r, Superuser: &no, ConnectionLimit: &limit, Password: &pw},
				model.RoleState{ID: r, Superuser: true, ConnectionLimit: -1}, true)),
			want: []meta{{kind: plan.KindAlterRole, target: roleT, limit: "3", change: plan.RoleChange{RemovesSuperuser: true, SetsPassword: true}}},
		},
		{
			name:  "drop role",
			stmts: d.DropRole(r, []string{"app"}),
			want: []meta{
				{kind: plan.KindReassign, target: inApp},
				{kind: plan.KindDropOwned, target: inApp},
				{kind: plan.KindDropRole, target: roleT},
			},
		},
		{
			name:  "grant membership with admin",
			stmts: first(d.GrantMembership(r, g, model.MembershipOptions{Admin: &yes, Inherit: &no})),
			want:  []meta{{kind: plan.KindGrantMembership, target: member.WithOption(true)}},
		},
		{
			name:  "revoke admin option",
			stmts: first(d.AlterMembership(r, g, model.MembershipOptions{Admin: &no}, model.MembershipState{Admin: true})),
			want:  []meta{{kind: plan.KindRevokeMembership, target: member.WithOption(true)}},
		},
		{name: "revoke membership", stmts: first(d.RevokeMembership(r, g)), want: []meta{{kind: plan.KindRevokeMembership, target: member}}},
		{name: "create database", stmts: d.CreateDatabase(model.Database{Name: "app", Owner: "r"}), want: []meta{{kind: plan.KindCreateDatabase, target: dbT}}},
		{
			name:  "alter database",
			stmts: first(d.AlterDatabase(model.Database{Name: "app", Owner: "r"}, model.Database{Name: "app", Owner: "o"})),
			want:  []meta{{kind: plan.KindAlterDatabase, target: dbT}},
		},
		{name: "drop database", stmts: d.DropDatabase("app"), want: []meta{{kind: plan.KindDropDatabase, target: dbT}}},
		{name: "create schema", stmts: d.CreateSchema(sch), want: []meta{{kind: plan.KindCreateSchema, target: schT}}},
		{
			name:  "alter schema",
			stmts: d.AlterSchema(model.Schema{Database: "app", Name: "s", Owner: "r"}, sch),
			want:  []meta{{kind: plan.KindAlterSchema, target: schT}},
		},
		{name: "drop schema", stmts: d.DropSchema(sch), want: []meta{{kind: plan.KindDropSchema, target: schT}}},
		{
			name:  "grant to PUBLIC on a schema",
			stmts: d.Grant(model.PublicRole, schObj, []string{"USAGE"}, false),
			want:  []meta{{kind: plan.KindGrant, target: plan.Target{Object: plan.ObjectSchema, Database: "app", Schema: "s", Grantee: model.PublicRole}}},
		},
		{
			name:  "revoke grant option",
			stmts: first(d.RevokeGrantOption(r, db, []string{"CONNECT"})),
			want:  []meta{{kind: plan.KindRevoke, target: plan.Target{Object: plan.ObjectDatabase, Database: "app", Grantee: r, Option: true}}},
		},
		{
			name:  "revoke as the grantor",
			stmts: first(drv.Revoke(r, db, []string{"CONNECT"})),
			want:  []meta{{kind: plan.KindRevoke, target: plan.Target{Object: plan.ObjectDatabase, Database: "app", Grantee: r}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if len(tt.stmts) != len(tt.want) {
				t.Fatalf("got %d statements\n%s\nwant %d", len(tt.stmts), sqlOf(tt.stmts), len(tt.want))
			}
			for i, s := range tt.stmts {
				c := s.RoleChange()
				got := meta{kind: s.Kind(), target: s.Target()}
				if c.ConnectionLimit != nil {
					got.limit = strconv.Itoa(*c.ConnectionLimit)
				}
				c.ConnectionLimit = nil
				got.change = c
				if got != tt.want[i] {
					t.Errorf("%s:\nmetadata %+v\nwant     %+v", s.SQL(), got, tt.want[i])
				}
			}
		})
	}
}
