package mysql

import (
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
)

// unquoted returns sql without its identifiers and string literals, read
// the way the server reads them: backquoted identifiers with doubled
// backquotes, and single-quoted literals with doubled quotes and, unless
// NO_BACKSLASH_ESCAPES is set, backslash escapes.
func unquoted(sql string, noBackslashEscapes bool) string {
	var sb strings.Builder
	var quote rune
	escaped := false
	for _, r := range sql {
		switch {
		case escaped:
			escaped = false
		case quote == '\'' && r == '\\' && !noBackslashEscapes:
			escaped = true
		case quote != 0:
			if r == quote {
				// A doubled quote reopens the quoted text.
				quote = 0
			}
		case r == '`' || r == '\'':
			quote = r
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func TestUnquoted(t *testing.T) {
	t.Parallel()
	tests := []struct {
		sql, want string
		noBS      bool
	}{
		{sql: "DROP USER 'a;b'@'%'", want: "DROP USER @"},
		{sql: "DROP DATABASE `a``;b`", want: "DROP DATABASE "},
		{sql: `GRANT 'a\';' TO x`, want: "GRANT  TO x"},
		{sql: `GRANT 'a\';' TO x`, noBS: true, want: "GRANT ;"},
		{sql: "SELECT 1; SELECT 2", want: "SELECT 1; SELECT 2"},
	}
	for _, tt := range tests {
		if got := unquoted(tt.sql, tt.noBS); got != tt.want {
			t.Errorf("unquoted(%q, %v) = %q, want %q", tt.sql, tt.noBS, got, tt.want)
		}
	}
}

// Every statement the dialect renders is one SQL command: no ';' appears
// outside identifiers and literals, whatever the names and passwords hold.
func TestStatementsHaveNoSeparator(t *testing.T) {
	t.Parallel()
	const evil = "x';\\'; DROP DATABASE prod; -- `;"
	acct := model.RoleID{Name: evil, Host: evil}
	other := model.RoleID{Name: "r;" + evil, Host: "%"}
	pw := evil
	login, locked := true, false
	yes, no := true, false
	db := model.Database{Name: evil, Charset: "utf8;mb4", Collation: evil}
	objs := []model.Object{
		{Type: model.ObjectDatabase, Database: evil},
		{Type: model.ObjectDatabase, Database: "a_%;b", Pattern: "a_%;" + evil},
	}
	for _, d := range []Dialect{{}, {NoBackslashEscapes: true}, {PartialRevokes: true}, {CaseInsensitiveNames: true}} {
		stmts := [][]plan.Statement{
			d.CreateRole(model.Role{ID: acct, Password: &pw, AuthPlugin: "caching;sha2", Login: &locked}),
			d.EnsureRole(model.Role{ID: acct, Password: &pw, Login: &login}),
			d.DropRole(acct, nil),
			first(d.GrantMembership(acct, other, model.MembershipOptions{Admin: &yes})),
			first(d.AlterMembership(acct, other, model.MembershipOptions{Admin: &no}, model.MembershipState{Admin: true})),
			first(d.RevokeMembership(acct, other)),
			d.SetDefaultRoles(model.Role{ID: acct, MemberOf: []model.RoleID{other, acct}}, model.RoleState{}),
			d.SetDefaultRoles(model.Role{ID: acct, MemberOf: []model.RoleID{}}, model.RoleState{DefaultRoles: []model.RoleID{other}}),
			d.CreateDatabase(db),
			first(d.AlterDatabase(db, model.Database{Name: evil})),
			d.DropDatabase(evil),
		}
		alter, _ := d.AlterRole(model.Role{ID: acct, Password: &pw, AuthPlugin: "mysql_native_password", Login: &login},
			model.RoleState{ID: acct, AuthPlugin: "caching_sha2_password", RetainedPassword: true}, true)
		stmts = append(stmts, alter)
		for _, obj := range objs {
			stmts = append(stmts,
				d.Grant(acct, obj, []string{"SELECT", "INSERT"}, true),
				first(d.Revoke(acct, obj, []string{"SELECT"})),
				first(d.RevokeGrantOption(acct, obj, nil)),
			)
		}
		n := 0
		for _, ss := range stmts {
			for _, s := range ss {
				n++
				if code := unquoted(s.SQL(), d.NoBackslashEscapes); strings.Contains(code, ";") {
					t.Errorf("%+v: statement contains ';' outside quotes:\n%s\ncode: %s", d, s.SQL(), code)
				}
				if s.AsRole != "" {
					t.Errorf("%+v: MySQL statement runs as role %q:\n%s", d, s.AsRole, s.SQL())
				}
			}
		}
		if n < len(stmts) {
			t.Errorf("%+v: only %d statements rendered for %d calls", d, n, len(stmts))
		}
	}
}
