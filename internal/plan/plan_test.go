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
