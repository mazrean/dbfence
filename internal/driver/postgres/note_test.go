package postgres

import (
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
)

// unquoted returns sql without its quoted identifiers and literals, which
// is what the server parses as keywords and comments.
func unquoted(sql string) string {
	var sb strings.Builder
	var quote rune
	for _, r := range sql {
		switch {
		case quote != 0:
			if r == quote {
				// A doubled quote reopens the quoted text.
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// Notes explaining a statement are shown in the plan but never sent to
// the server, so a role name read from the server cannot end a comment
// and run as SQL.
func TestNotesAreNotExecuted(t *testing.T) {
	t.Parallel()
	const evil = "x\nALTER ROLE mallory SUPERUSER; --\r"
	// A CASCADE never reaches a role with a line break in its name (such
	// roles are not managed), so the dependents in its note only try to
	// close a comment.
	const sneaky = "x */ ALTER ROLE mallory SUPERUSER; --"
	ps := model.Object{Type: model.ObjectSchema, Database: "pdb", Schema: "ps"}
	db := model.Object{Type: model.ObjectDatabase, Database: "hdb"}
	tests := []struct {
		stmts func() []plan.Statement
		name  string
	}{
		{
			name: "revoke of a grant option cascades to a dependent",
			stmts: func() []plan.Statement {
				st := &state{
					desired: &model.Desired{}, user: "adm", superuser: true, version: 170000,
					roles:  map[string]roleAccess{},
					owners: map[model.Object]string{db: "own"},
					acl: []aclEntry{
						{obj: db, grantee: "hu", grantor: "own", priv: "CONNECT", grantable: true},
						{obj: db, grantee: sneaky, grantor: "hu", priv: "CONNECT"},
					},
				}
				s, _ := st.revoke("hu", db, []string{"CONNECT"}, true)
				return s
			},
		},
		{
			name: "revoke of a membership cascades to a dependent",
			stmts: func() []plan.Statement {
				st := &state{
					desired: &model.Desired{Roles: []model.Role{{ID: pg("m"), MemberOf: []model.RoleID{}}}},
					user:    "adm", superuser: true, version: 170000,
					roles: map[string]roleAccess{},
					members: []memberEntry{
						{role: "grp", member: "m", grantor: "adm", admin: true},
						{role: "grp", member: sneaky, grantor: "m"},
					},
				}
				s, _ := st.revokeMembership("m", "grp")
				return s
			},
		},
		{
			name: "dropped role revoked first and regranted after",
			stmts: func() []plan.Statement {
				d := &Driver{st: &state{
					desired: &model.Desired{
						Roles:      []model.Role{{ID: pg("own")}, {ID: pg("other")}},
						Privileges: []model.Privilege{{Grantee: pg("other"), Object: ps, Name: "USAGE"}},
					},
					user: "postgres", superuser: true, version: 170000,
					acl: []aclEntry{
						{obj: ps, grantee: "own", grantor: "own", priv: "USAGE"},
						{obj: ps, grantee: evil, grantor: "own", priv: "USAGE", grantable: true},
						{obj: ps, grantee: "other", grantor: evil, priv: "USAGE"},
					},
					members:     []memberEntry{{role: "own", member: evil, grantor: "postgres", inherit: true}},
					owners:      map[model.Object]string{ps: "own", {Type: model.ObjectDatabase, Database: "pdb"}: "own"},
					connectable: map[string]bool{"pdb": true},
				}}
				return d.DropRole(pg(evil), []string{"pdb"})
			},
		},
		{
			name: "schema dropped with its objects",
			stmts: func() []plan.Statement {
				d := &Driver{st: &state{objects: map[model.Object]int{ps: 2}}}
				return d.DropSchema(model.Schema{Database: "pdb", Name: "ps"})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stmts := tt.stmts()
			notes := 0
			for _, s := range stmts {
				notes += len(s.Notes())
				code := unquoted(s.SQL())
				if strings.Contains(code, "--") || strings.Contains(code, "ALTER ROLE") {
					t.Errorf("executed SQL contains a comment or injected statement:\n%s", s.SQL())
				}
				for _, n := range s.Notes() {
					if strings.ContainsAny(n, "\n\r") {
						t.Errorf("note %q contains a line break", n)
					}
				}
			}
			if notes == 0 {
				t.Errorf("no notes explain the statements:\n%s", sqlOf(stmts))
			}
		})
	}
}

// Role names read from the server reach plan output and warnings escaped.
func TestRenderEscapesServerNames(t *testing.T) {
	t.Parallel()
	st := &state{desired: &model.Desired{}, roles: map[string]roleAccess{}, user: "dbfence"}
	p := &plan.Plan{
		Warnings: st.pruneWarnings(&model.Current{Roles: []model.RoleState{{ID: pg("x\nDROP DATABASE \"prod\"")}}}),
		Changes: []plan.Change{{Action: plan.ActionDrop, Resource: "safe",
			Statements: Dialect{}.DropRole(pg("x\x1b[2K\r\n-- No changes."), nil)}},
	}
	tests := []struct {
		write func(*strings.Builder) error
		name  string
	}{
		{name: "Render", write: func(sb *strings.Builder) error { return p.Render(sb, false) }},
		{name: "WriteWarnings", write: func(sb *strings.Builder) error { return p.WriteWarnings(sb) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var sb strings.Builder
			if err := tt.write(&sb); err != nil {
				t.Fatal(err)
			}
			for l := range strings.SplitSeq(sb.String(), "\n") {
				if strings.ContainsAny(l, "\x1b\r") || strings.HasPrefix(l, "DROP DATABASE") || strings.HasPrefix(l, "-- No changes") {
					t.Errorf("line %q comes from a role name", l)
				}
			}
		})
	}
}
