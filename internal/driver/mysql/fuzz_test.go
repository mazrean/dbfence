package mysql

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/mazrean/dbfence/internal/driver/internal/sqltest"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
)

// nameSeeds are names that try to break out of quoting.
var nameSeeds = []string{
	"app", "", "%", "a'b", "a\\'; DROP USER x; #", "a`b", "`; DROP DATABASE x; -- ", "x/*", "a\\", "\\'", "'\\",
	"semi;colon", "new\nline", "nul\x00", "é", "\xff\xfe", "--", "#", "a_b%c\\_",
}

// dialectStatements renders every statement the Dialect can produce
// from the names a, b and c.
func dialectStatements(d Dialect, a, b, c string) []plan.Statement {
	ida, idb := model.RoleID{Name: a, Host: b}, model.RoleID{Name: b, Host: c}
	yes, no := true, false
	role := model.Role{ID: ida, Password: &c, AuthPlugin: b, Login: &no, MemberOf: []model.RoleID{idb, {Name: c, Host: a}}}
	cur := model.RoleState{ID: ida, AuthPlugin: c, Login: true, RetainedPassword: true, DefaultRoles: []model.RoleID{idb}}
	stmts := concat(
		d.CreateRole(role),
		d.CreateRole(model.Role{ID: ida, AuthPlugin: c}),
		d.EnsureRole(role),
		first(d.AlterRole(role, cur, true)),
		first(d.AlterRole(model.Role{ID: ida, Password: &a, Login: &yes}, model.RoleState{ID: ida, AttributesUnknown: true}, true)),
		d.DropRole(ida, []string{a, b}),
		first(d.GrantMembership(ida, idb, model.MembershipOptions{Admin: &yes})),
		first(d.AlterMembership(ida, idb, model.MembershipOptions{Admin: &no}, model.MembershipState{Admin: true})),
		first(d.RevokeMembership(ida, idb)),
		d.SetDefaultRoles(role, cur),
		d.SetDefaultRoles(model.Role{ID: ida, MemberOf: []model.RoleID{}}, cur),
		d.CreateDatabase(model.Database{Name: a, Charset: b, Collation: c}),
		first(d.AlterDatabase(model.Database{Name: a, Charset: b, Collation: c}, model.Database{Name: a})),
		d.DropDatabase(a),
	)
	for _, obj := range []model.Object{
		{Type: model.ObjectDatabase, Database: a},
		{Type: model.ObjectDatabase, Pattern: b},
		{Type: model.ObjectDatabase, Database: a, Pattern: c},
	} {
		stmts = concat(stmts,
			d.Grant(idb, obj, []string{"SELECT", "INSERT"}, true),
			first(d.Revoke(idb, obj, []string{"SELECT"})),
			first(d.RevokeGrantOption(idb, obj, []string{"SELECT"})),
		)
	}
	return stmts
}

func concat(lists ...[]plan.Statement) []plan.Statement {
	var out []plan.Statement
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

// FuzzDialectSingleStatement checks that, whatever the names, every
// statement the MySQL Dialect renders is a single statement with no ';'
// or comment outside quoted identifiers and literals, in every
// combination of the settings that change quoting.
func FuzzDialectSingleStatement(f *testing.F) {
	for i, a := range nameSeeds {
		f.Add(a, nameSeeds[(i+1)%len(nameSeeds)], nameSeeds[(i+5)%len(nameSeeds)])
	}
	f.Fuzz(func(t *testing.T, a, b, c string) {
		for _, d := range []Dialect{
			{}, {NoBackslashEscapes: true}, {PartialRevokes: true}, {CaseInsensitiveNames: true},
			{NoBackslashEscapes: true, PartialRevokes: true},
		} {
			for _, s := range dialectStatements(d, a, b, c) {
				if err := sqltest.CheckSingle(s.SQL(), sqltest.MySQL(d.NoBackslashEscapes)); err != nil {
					t.Errorf("%+v: %q: %v", d, s.SQL(), err)
				}
				if s.AsRole != "" {
					t.Errorf("%q runs as %q", s.SQL(), s.AsRole)
				}
			}
		}
	})
}

// FuzzMatchPattern checks the LIKE matcher on patterns read from the
// server: it terminates, an escaped name matches itself, '%' matches
// everything, and a pattern without wildcards matches only itself.
func FuzzMatchPattern(f *testing.F) {
	for _, s := range [][2]string{
		{"app\\_%", "app_1"}, {"%%%%%%%%%%%%%%%%%%%%%%%%b", strings.Repeat("a", 64)}, {"a_c", "abc"},
		{"_", "é"}, {"\\", "\\"}, {"a\\", "a"}, {"%\\%", "%"}, {"", ""}, {"%", "\xff"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, p, name string) {
		if len(p) > 256 || len(name) > 256 {
			t.Skip()
		}
		got := matchPattern(p, name)
		if !matchPattern("%", name) {
			t.Errorf("%%%% does not match %q", name)
		}
		if utf8.ValidString(name) && !matchPattern(escapeWildcards(name), name) {
			t.Errorf("escaped %q does not match itself", name)
		}
		if !strings.ContainsAny(p, `%_\`) && got != (p == name) {
			t.Errorf("matchPattern(%q, %q) = %v for a literal pattern", p, name, got)
		}
	})
}
