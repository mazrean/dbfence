package postgres

import (
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/driver/internal/sqltest"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
)

// nameSeeds are names that try to break out of quoting.
var nameSeeds = []string{
	"app", "public", "", `a"b`, `"; DROP ROLE x; --`, "a'b", `\'; DROP ROLE x; --`, "x/*", `a\`, `E'`, "$$", "$1$",
	"semi;colon", "new\nline", "nul\x00", "é", "\xff\xfe", "--", strings.Repeat("n", 70),
}

func concat(lists ...[]plan.Statement) []plan.Statement {
	var out []plan.Statement
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

// dialectStatements renders every statement the Dialect can produce
// from the names a, b and c.
func dialectStatements(d Dialect, a, b, c string) []plan.Statement {
	yes, no := true, false
	limit := -1
	role := model.Role{ID: pg(a), Password: &c, Login: &no, Superuser: &yes, Inherit: &no, ConnectionLimit: &limit}
	cur := model.RoleState{ID: pg(a), Login: true, PasswordReadable: true, PasswordHash: []byte(b)}
	db := model.Database{Name: a, Owner: b, Encoding: c, LcCollate: a, LcCtype: b}
	schema := model.Schema{Database: a, Name: b, Owner: c}
	stmts := concat(
		d.CreateRole(role),
		d.CreateRole(model.Role{ID: pg(b), Password: new(string)}),
		d.EnsureRole(role),
		first(d.AlterRole(role, cur, true)),
		first(d.AlterRole(role, cur, false)),
		d.DropRole(pg(a), []string{b, c, "postgres", "template1"}),
		first(d.GrantMembership(pg(a), pg(b), model.MembershipOptions{Admin: &yes})),
		first(d.GrantMembership(pg(a), pg(b), model.MembershipOptions{Admin: &no, Inherit: &yes, Set: &no})),
		first(d.AlterMembership(pg(a), pg(b), model.MembershipOptions{Admin: &no, Inherit: &no}, model.MembershipState{Admin: true})),
		first(d.RevokeMembership(pg(a), pg(b))),
		d.CreateDatabase(db),
		first(d.AlterDatabase(db, model.Database{Name: a})),
		d.DropDatabase(a),
		d.CreateSchema(schema),
		d.AlterSchema(schema, model.Schema{Database: a, Name: b}),
		d.DropSchema(schema),
	)
	for _, obj := range []model.Object{{Type: model.ObjectDatabase, Database: a}, {Type: model.ObjectSchema, Database: b, Schema: c}} {
		for _, grantee := range []model.RoleID{pg(b), model.PublicRole} {
			stmts = concat(stmts,
				d.Grant(grantee, obj, []string{"CREATE", "USAGE"}, grantee != model.PublicRole),
				first(d.Revoke(grantee, obj, []string{"CREATE"})),
				first(d.RevokeGrantOption(grantee, obj, []string{"CREATE"})),
			)
		}
	}
	return stmts
}

// FuzzDialectSingleStatement checks that, whatever the names, every
// statement the PostgreSQL Dialect renders is a single statement with no
// ';' or comment outside quoted identifiers and literals.
func FuzzDialectSingleStatement(f *testing.F) {
	for i, a := range nameSeeds {
		f.Add(a, nameSeeds[(i+1)%len(nameSeeds)], nameSeeds[(i+5)%len(nameSeeds)])
	}
	f.Fuzz(func(t *testing.T, a, b, c string) {
		for _, d := range []Dialect{{}, {PasswordEncryption: "md5"}} {
			for _, s := range dialectStatements(d, a, b, c) {
				if err := sqltest.CheckSingle(s.SQL(), sqltest.PostgreSQL); err != nil {
					t.Errorf("%q: %v", s.SQL(), err)
				}
			}
		}
	})
}

// FuzzInspectedACL feeds arbitrary grantees, grantors and members into
// the inspected ACL and membership state that the Driver plans revokes
// and membership changes from. PostgreSQL decodes aclitem values itself
// (aclexplode), so this is the boundary where they enter dbfence. Every
// statement must be a single statement, and a grantor dbfence does not
// manage must never be named (GRANTED BY, or AsRole for SET ROLE).
func FuzzInspectedACL(f *testing.F) {
	for i, a := range nameSeeds {
		f.Add(a, nameSeeds[(i+3)%len(nameSeeds)], nameSeeds[(i+7)%len(nameSeeds)], i%2 == 0)
	}
	f.Fuzz(func(t *testing.T, grantor, other, role string, superuser bool) {
		db := model.Object{Type: model.ObjectDatabase, Database: "app"}
		sc := model.Object{Type: model.ObjectSchema, Database: "app", Schema: "s"}
		no := false
		st := &state{
			desired: &model.Desired{
				Roles:      []model.Role{{ID: pg("hu"), MemberOf: []model.RoleID{pg("grp")}}, {ID: pg("dep"), MemberOf: []model.RoleID{pg("grp")}}},
				Privileges: []model.Privilege{{Grantee: pg("dep"), Object: db, Name: "CONNECT"}},
			},
			user: "adm", superuser: superuser, version: 170000,
			connectable: map[string]bool{"app": true},
			roles:       map[string]roleAccess{grantor: {set: true, admin: true, use: true}, other: {set: true}, "grp": {admin: true}},
			owners:      map[model.Object]string{db: other, sc: grantor},
			acl: []aclEntry{
				{obj: db, grantee: "hu", grantor: grantor, priv: "CONNECT", grantable: true},
				{obj: db, grantee: "dep", grantor: "hu", priv: "CONNECT"},
				{obj: db, grantee: other, grantor: "hu", priv: "CONNECT"},
				{obj: sc, grantee: "hu", grantor: other, priv: "USAGE", grantable: true},
				{obj: sc, grantee: role, grantor: "hu", priv: "USAGE"},
			},
			members: []memberEntry{
				{role: "grp", member: "hu", grantor: grantor, admin: true, inherit: true, set: true},
				{role: "grp", member: "dep", grantor: "hu", inherit: true},
				{role: role, member: "hu", grantor: other, inherit: true},
				{role: grantor, member: "hu", grantor: "adm", inherit: true},
			},
		}
		d := &Driver{st: st}
		var stmts []plan.Statement
		for _, obj := range []model.Object{db, sc} {
			for _, privs := range [][]string{{"CONNECT"}, {"USAGE"}} {
				stmts = concat(stmts, first(d.Revoke(pg("hu"), obj, privs)), first(d.RevokeGrantOption(pg("hu"), obj, privs)))
			}
		}
		stmts = concat(stmts,
			first(d.RevokeMembership(pg("hu"), pg("grp"))),
			first(d.AlterMembership(pg("hu"), pg("grp"), model.MembershipOptions{Admin: &no, Set: &no}, model.MembershipState{Admin: true, Set: true})),
			first(d.AlterRole(model.Role{ID: pg("hu"), Inherit: &no}, model.RoleState{ID: pg("hu"), Inherit: true}, false)),
			d.DropRole(pg("hu"), []string{"app"}),
		)
		for _, s := range stmts {
			if err := sqltest.CheckSingle(s.SQL(), sqltest.PostgreSQL); err != nil {
				t.Errorf("%q: %v", s.SQL(), err)
			}
			for _, name := range []string{grantor, other, role} {
				if !unmanagedRole(name) {
					continue
				}
				if s.AsRole == name || strings.Contains(s.SQL(), Ident(name).String()) {
					t.Errorf("statement names the unmanaged role %q: %s (as %q)", name, s.SQL(), s.AsRole)
				}
			}
		}
	})
}
