package plan

import (
	"strings"
	"testing"
)

func TestStatementRedaction(t *testing.T) {
	t.Parallel()
	s := SQL("", "CREATE ROLE \"a\" WITH PASSWORD ", Secret("'p@ss'"))
	if got, want := s.SQL(), `CREATE ROLE "a" WITH PASSWORD 'p@ss'`; got != want {
		t.Errorf("SQL() = %q, want %q", got, want)
	}
	if got, want := s.Display(false), `CREATE ROLE "a" WITH PASSWORD '<redacted>'`; got != want {
		t.Errorf("Display(false) = %q, want %q", got, want)
	}
	if got := s.Display(true); got != s.SQL() {
		t.Errorf("Display(true) = %q, want %q", got, s.SQL())
	}
}

func TestStatementNotesAreNotSQL(t *testing.T) {
	t.Parallel()
	s := SQL("", "REVOKE X").WithNote("x\nDROP DATABASE prod; --")
	if got, want := s.SQL(), "REVOKE X"; got != want {
		t.Errorf("SQL() = %q, want %q", got, want)
	}
	if got, want := s.Display(true), "REVOKE X"; got != want {
		t.Errorf("Display(true) = %q, want %q", got, want)
	}
	if got := s.Notes(); len(got) != 1 {
		t.Errorf("Notes() = %q, want one note", got)
	}
}

// AsRole is carried beside the SQL: the executable text is the bare
// statement, never a SET ROLE chained in front of it.
func TestStatementWithRole(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		wantRole  string
		wantWhere string
		stmt      Statement
	}{
		{name: "configured connection", stmt: SQL("", "REVOKE X")},
		{name: "database only", stmt: SQL("app", "REVOKE X"), wantWhere: `on database "app"`},
		{name: "role only", stmt: SQL("", "REVOKE X").WithRole("ro"), wantRole: "ro", wantWhere: `as role "ro"`},
		{
			name: "database and role", stmt: SQL("app", "REVOKE X").WithRole(`r"o`).WithNote("n"),
			wantRole: `r"o`, wantWhere: `on database "app", as role "r\"o"`,
		},
		{name: "last role wins", stmt: SQL("", "REVOKE X").WithRole("a").WithRole("b"), wantRole: "b", wantWhere: `as role "b"`},
		{name: "control characters escaped", stmt: SQL("", "REVOKE X").WithRole("x\n-- y"), wantRole: "x\n-- y", wantWhere: `as role "x\n-- y"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.stmt.SQL(); got != "REVOKE X" {
				t.Errorf("SQL() = %q, want the bare statement", got)
			}
			if got := tt.stmt.Display(true); got != "REVOKE X" {
				t.Errorf("Display(true) = %q, want the bare statement", got)
			}
			if tt.stmt.AsRole != tt.wantRole {
				t.Errorf("AsRole = %q, want %q", tt.stmt.AsRole, tt.wantRole)
			}
			if got := tt.stmt.Where(); got != tt.wantWhere {
				t.Errorf("Where() = %q, want %q", got, tt.wantWhere)
			}
		})
	}
}

func TestRender(t *testing.T) {
	t.Parallel()
	schema := Change{
		Action: ActionCreate, Resource: `schema "api"`,
		Statements: []Statement{SQL("app", `CREATE SCHEMA "api"`)},
	}
	tests := []struct {
		name string
		plan *Plan
		want string
	}{
		{
			name: "changes and warnings",
			plan: &Plan{Warnings: []string{`unmanaged role "x"`}, Changes: []Change{schema}},
			want: "-- warning: unmanaged role \"x\"\n\n-- [create] schema \"api\"\n-- (on database \"app\")\nCREATE SCHEMA \"api\";\n\n" +
				"-- Plan: 1 to create, 0 to change, 0 to drop (1 statement).\n",
		},
		{
			name: "every action with drops",
			plan: &Plan{Changes: []Change{
				schema,
				{Action: ActionUpdate, Resource: `role "a"`, Statements: []Statement{SQL("", "A"), SQL("", "B")}},
				{Action: ActionGrant, Resource: "g", Statements: []Statement{SQL("", "G")}},
				{Action: ActionRevoke, Resource: "r", Statements: []Statement{SQL("", "R")}},
				{Action: ActionDrop, Resource: `database "d"`, Statements: []Statement{SQL("", "D")}},
				{Action: ActionDrop, Resource: `role "x"`, Statements: []Statement{SQL("", "X")}},
			}},
			want: "-- Plan: 1 to create, 1 to change, 1 to grant, 1 to revoke, 2 to drop (7 statements).\n" +
				"-- DESTRUCTIVE: this plan drops 2 objects: database \"d\", role \"x\"\n",
		},
		{
			name: "notes are shown before the statement",
			plan: &Plan{Changes: []Change{{
				Action: ActionRevoke, Resource: "r",
				Statements: []Statement{SQL("app", "REVOKE X CASCADE").WithNote("second").WithNote("first")},
			}}},
			want: "-- [revoke] r\n-- (on database \"app\")\n-- first\n-- second\nREVOKE X CASCADE;\n\n" +
				"-- Plan: 0 to create, 0 to change, 1 to revoke, 0 to drop (1 statement).\n",
		},
		{
			name: "statement run as another role",
			plan: &Plan{Changes: []Change{{
				Action: ActionRevoke, Resource: "r",
				Statements: []Statement{SQL("app", `REVOKE X FROM "u"`).WithRole("ro\n-- x"), SQL("", "R").WithRole("g")},
			}}},
			want: "-- [revoke] r\n-- (on database \"app\", as role \"ro\\n-- x\")\nREVOKE X FROM \"u\";\n-- (as role \"g\")\nR;\n\n" +
				"-- Plan: 0 to create, 0 to change, 1 to revoke, 0 to drop (2 statements).\n",
		},
		{
			name: "no changes",
			plan: &Plan{},
			want: "-- No changes. The server matches the configuration.\n",
		},
		{
			name: "no changes with a warning",
			plan: &Plan{Warnings: []string{"password not compared"}},
			want: "-- warning: password not compared\n\n-- No changes to apply. See the 1 warning above for differences that are not changed and items that were not compared.\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var sb strings.Builder
			if err := tt.plan.Render(&sb, false); err != nil {
				t.Fatal(err)
			}
			if !strings.HasSuffix(sb.String(), tt.want) {
				t.Errorf("Render() =\n%s\nwant suffix\n%s", sb.String(), tt.want)
			}
			if !tt.plan.Empty() && strings.Contains(sb.String(), "No changes") {
				t.Errorf("Render() claims no changes:\n%s", sb.String())
			}
		})
	}
}

func TestWriteWarnings(t *testing.T) {
	t.Parallel()
	var sb strings.Builder
	if err := (&Plan{Warnings: []string{"a", "b"}}).WriteWarnings(&sb); err != nil {
		t.Fatal(err)
	}
	if got, want := sb.String(), "warning: a\nwarning: b\n"; got != want {
		t.Errorf("WriteWarnings() = %q, want %q", got, want)
	}
}

// Names read from the server may contain control characters; output
// shows them escaped so they cannot redraw the terminal or forge lines.
func TestOutputEscapesControlCharacters(t *testing.T) {
	t.Parallel()
	const evil = "x\x1b[2K\r\n-- No changes.\u202e\x07"
	const shown = `x\x1b[2K\r\n-- No changes.\u202e\a`
	p := &Plan{
		Warnings: []string{"role " + evil},
		Changes: []Change{{Action: ActionDrop, Resource: "role " + evil, Statements: []Statement{
			SQL("", `DROP ROLE "`+evil+`" PASSWORD `, Secret("'"+evil+"'")).WithNote("note " + evil),
		}}},
	}
	tests := []struct {
		write func(*strings.Builder) error
		name  string
		want  []string
	}{
		{
			name:  "Render",
			write: func(sb *strings.Builder) error { return p.Render(sb, true) },
			want: []string{
				"-- warning: role " + shown + "\n",
				"-- [drop] role " + shown + "\n",
				"-- note " + shown + "\n",
				`DROP ROLE "` + shown + `" PASSWORD '` + shown + "';\n",
				"-- DESTRUCTIVE: this plan drops 1 object: role " + shown + "\n",
			},
		},
		{
			name:  "WriteWarnings",
			write: func(sb *strings.Builder) error { return p.WriteWarnings(sb) },
			want:  []string{"warning: role " + shown + "\n"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var sb strings.Builder
			if err := tt.write(&sb); err != nil {
				t.Fatal(err)
			}
			out := sb.String()
			if strings.ContainsAny(out, "\x1b\r\a\u202e") || strings.Contains(out, "\n-- No changes") {
				t.Errorf("output contains raw control characters: %q", out)
			}
			for _, w := range tt.want {
				if !strings.Contains(out, w) {
					t.Errorf("output = %q, want substring %q", out, w)
				}
			}
		})
	}
}

func TestEscape(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want, wantLines string
	}{
		{in: "plain \"text\" ü", want: "plain \"text\" ü", wantLines: "plain \"text\" ü"},
		{in: "a\nb\tc", want: `a\nb\tc`, wantLines: "a\nb\tc"},
		{in: "\x1b[2K\r\x00\x7f\u0085\u202e", want: `\x1b[2K\r\x00\x7f\u0085\u202e`, wantLines: `\x1b[2K\r\x00\x7f\u0085\u202e`},
	}
	for _, tt := range tests {
		if got := Escape(tt.in); got != tt.want {
			t.Errorf("Escape(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if got := EscapeLines(tt.in); got != tt.wantLines {
			t.Errorf("EscapeLines(%q) = %q, want %q", tt.in, got, tt.wantLines)
		}
	}
}

func TestCount(t *testing.T) {
	t.Parallel()
	for n, want := range map[int]string{0: "0 statements", 1: "1 statement", 2: "2 statements"} {
		if got := Count(n, "statement"); got != want {
			t.Errorf("Count(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestStatementHasSecret(t *testing.T) {
	t.Parallel()
	if SQL("", "CREATE ROLE a").HasSecret() {
		t.Error("statement without a secret reports one")
	}
	if !SQL("", "ALTER ROLE a PASSWORD ", Secret("'x'")).HasSecret() {
		t.Error("statement with a secret reports none")
	}
}
