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

func TestStatementRedact(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("SECRET0123456789", 6)
	tests := []struct {
		name, secret, msg, want string
		leak                    []string
	}{
		{
			name:   "full literal and unescaped value",
			secret: "'p''w'",
			msg:    "Error 1064: You have an error in your SQL syntax near 'p''w'' and 'p'w'",
			want:   "Error 1064: You have an error in your SQL syntax near '<redacted>'' and '<redacted>'",
		},
		{
			name:   "postgres syntax error token",
			secret: "'hunter2'",
			msg:    `ERROR: syntax error at or near "'hunter2'" (SQLSTATE 42601)`,
			want:   `ERROR: syntax error at or near "'<redacted>'" (SQLSTATE 42601)`,
		},
		{
			name:   "mysql near fragment truncated at 80 characters",
			secret: "'" + long + "'",
			msg:    "Error 1064 (42000): You have an error in your SQL syntax; near '-pam BY '" + long[:70] + "' at line 1",
			want:   "Error 1064 (42000): You have an error in your SQL syntax; near '-pam BY '<redacted>' at line 1",
			leak:   []string{long[:minRedactPrefix]},
		},
		{
			name:   "truncated at the end of the text",
			secret: "'" + long + "'",
			msg:    "failed near '" + long[:10],
			want:   "failed near '<redacted>",
		},
		{
			name:   "truncation inside a doubled quote",
			secret: "'abcd''efgh'",
			msg:    "near 'abcd'' at line 1",
			want:   "near '<redacted>' at line 1",
		},
		{
			name:   "backslash-escaped value",
			secret: `'a\\b''c'`,
			msg:    `near 'a\b'c' x`,
			want:   `near '<redacted>' x`,
		},
		{
			name:   "short password does not garble unrelated text",
			secret: "'e'",
			msg:    `ERROR: role "reader" already exists (SQLSTATE 42710)`,
			want:   `ERROR: role "reader" already exists (SQLSTATE 42710)`,
		},
		{
			name:   "short password inside a host name",
			secret: "'x'",
			msg:    "Error 1396 (HY000): Operation CREATE USER failed for 'casey'@'app.example.com'",
			want:   "Error 1396 (HY000): Operation CREATE USER failed for 'casey'@'app.example.com'",
		},
		{
			name:   "short password as a double-quoted identifier",
			secret: "'app'",
			msg:    `ERROR: role "app" already exists`,
			want:   `ERROR: role "app" already exists`,
		},
		{
			name:   "short prefix is kept",
			secret: "'" + long + "'",
			msg:    "near 'SEC' at line 1",
			want:   "near 'SEC' at line 1",
		},
		{
			name:   "prefix not ending the quoted fragment is kept",
			secret: "'" + long + "'",
			msg:    "near 'SECRETS are fine' at line 1",
			want:   "near 'SECRETS are fine' at line 1",
		},
		{
			name:   "empty secret",
			secret: "''",
			msg:    "near '' at line 1",
			want:   "near '' at line 1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := SQL("", "ALTER USER 'a'@'%' IDENTIFIED BY ", Secret(tt.secret))
			got := s.Redact(tt.msg)
			if got != tt.want {
				t.Errorf("Redact() =\n%s\nwant\n%s", got, tt.want)
			}
			for _, l := range tt.leak {
				if strings.Contains(got, l) {
					t.Errorf("Redact() leaked %q: %s", l, got)
				}
			}
		})
	}
}
