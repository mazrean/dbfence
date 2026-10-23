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

func TestRender(t *testing.T) {
	t.Parallel()
	p := &Plan{
		Warnings: []string{`unmanaged role "x"`},
		Changes: []Change{{
			Action: ActionCreate, Resource: `schema "api"`,
			Statements: []Statement{SQL("app", `CREATE SCHEMA "api"`)},
		}},
	}
	var sb strings.Builder
	if err := p.Render(&sb, false); err != nil {
		t.Fatal(err)
	}
	want := "-- warning: unmanaged role \"x\"\n\n-- [create] schema \"api\"\n-- (on database \"app\")\nCREATE SCHEMA \"api\";\n\n"
	if sb.String() != want {
		t.Errorf("Render() =\n%s\nwant\n%s", sb.String(), want)
	}

	var empty strings.Builder
	if err := (&Plan{}).Render(&empty, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(empty.String(), "No changes") {
		t.Errorf("empty plan output = %q", empty.String())
	}
}

func TestStatementRedact(t *testing.T) {
	t.Parallel()
	s := SQL("", "ALTER USER 'a'@'%' IDENTIFIED BY ", Secret("'p''w'"))
	msg := "Error 1064: You have an error in your SQL syntax near 'p''w'' and p''w"
	got := s.Redact(msg)
	if strings.Contains(got, "p''w") {
		t.Errorf("Redact() leaked the secret: %s", got)
	}
}
