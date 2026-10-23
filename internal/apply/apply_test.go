package apply

import (
	"context"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/plan"
)

type recorder struct {
	err    error
	cancel func()
	ran    []string
	failAt int
}

func (r *recorder) Exec(_ context.Context, s plan.Statement) error {
	query := s.SQL()
	ran := s.Database + "|" + query
	if s.AsRole != "" {
		ran = s.Database + "|as " + s.AsRole + "|" + query
	}
	r.ran = append(r.ran, ran)
	if len(r.ran) != r.failAt {
		return nil
	}
	if r.cancel != nil {
		r.cancel()
	}
	if r.err != nil {
		return r.err
	}
	return Rejected(errors.New("syntax error near " + query))
}

func testPlan() *plan.Plan {
	return &plan.Plan{Changes: []plan.Change{
		{Action: plan.ActionCreate, Resource: `role "a"`, Statements: []plan.Statement{
			plan.SQL("", `CREATE ROLE "a" WITH PASSWORD `, plan.Secret("'hunter2'")),
		}},
		{Action: plan.ActionCreate, Resource: `schema "s"`, Statements: []plan.Statement{
			plan.SQL("app", `CREATE SCHEMA "s"`),
		}},
	}}
}

func TestRun(t *testing.T) {
	t.Parallel()
	r := &recorder{}
	var out strings.Builder
	if err := Run(t.Context(), r, testPlan(), &out, false); err != nil {
		t.Fatal(err)
	}
	want := []string{`|CREATE ROLE "a" WITH PASSWORD 'hunter2'`, `app|CREATE SCHEMA "s"`}
	if strings.Join(r.ran, "\n") != strings.Join(want, "\n") {
		t.Errorf("executed %q, want %q", r.ran, want)
	}
	wantOut := "[1/2] CREATE ROLE \"a\" WITH PASSWORD '<redacted>'\n[2/2] (on database \"app\") CREATE SCHEMA \"s\"\n"
	if out.String() != wantOut {
		t.Errorf("output =\n%s\nwant\n%s", out.String(), wantOut)
	}
}

func TestRunErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err        error
		wantIs     error
		cause      error
		name       string
		wantSuffix string
		want       []string
		failAt     int
		cancelCtx  bool
	}{
		{
			name: "server error on the connection", failAt: 1,
			want: []string{`create role "a": statement 1/2 failed: `, "(0 of 2 statements applied; run plan"},
		},
		{
			name: "server error on a database", failAt: 2,
			want: []string{`create schema "s": statement 2/2 (on database "app") failed: `, "(1 of 2 statements applied;"},
		},
		{
			name: "interrupted", failAt: 2, cancelCtx: true, err: context.Canceled, wantIs: context.Canceled,
			want: []string{`interrupted during statement 2/2 (on database "app"), whose outcome is unknown (1 statement confirmed applied;`},
		},
		{
			name: "interrupted by a signal names it once", failAt: 1, cancelCtx: true, err: context.Canceled,
			cause:      errors.New("interrupt signal received"),
			wantSuffix: "run plan to see the remaining changes): interrupt signal received",
		},
		{
			name: "interrupted keeps a driver error that says more", failAt: 1, cancelCtx: true, err: errors.New("read tcp: use of closed connection"),
			wantIs:     context.Canceled,
			wantSuffix: "run plan to see the remaining changes): read tcp: use of closed connection: context canceled",
		},
		{
			name: "connection closed after sending", failAt: 2, err: io.EOF,
			want:       []string{`interrupted during statement 2/2 (on database "app"), whose outcome is unknown (1 statement confirmed applied;`},
			wantSuffix: "run plan to see the remaining changes): EOF",
		},
		{
			name: "rejected before sending", failAt: 2, err: Rejected(errors.New(`connect to database "app": refused`)),
			want: []string{`statement 2/2 (on database "app") failed: connect to database "app": refused (1 of 2 statements applied;`},
		},
		{
			name: "connection lost", failAt: 1, wantSuffix: "run plan to see the remaining changes): driver: bad connection", err: driver.ErrBadConn, wantIs: driver.ErrBadConn,
			want: []string{"interrupted during statement 1/2, whose outcome is unknown (0 statements confirmed applied;"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			r := &recorder{failAt: tt.failAt, err: tt.err}
			if tt.cancelCtx {
				r.cancel = func() { cancel(tt.cause) }
			}
			var out strings.Builder
			err := Run(ctx, r, testPlan(), &out, false)
			if err == nil {
				t.Fatal("Run() succeeded")
			}
			if strings.Contains(err.Error(), "hunter2") {
				t.Errorf("error leaked the secret: %v", err)
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("err = %v, want substring %q", err, w)
				}
			}
			if tt.wantSuffix != "" && !strings.HasSuffix(err.Error(), tt.wantSuffix) {
				t.Errorf("err = %v, want suffix %q", err, tt.wantSuffix)
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("err = %v, want errors.Is %v", err, tt.wantIs)
			}
			if len(r.ran) != tt.failAt {
				t.Errorf("continued after failure: %q", r.ran)
			}
		})
	}
}

func TestRunPrintsNotesBeforeTheStatement(t *testing.T) {
	t.Parallel()
	revoke := `REVOKE CONNECT ON DATABASE "app" FROM "a" CASCADE`
	p := &plan.Plan{Changes: []plan.Change{{Action: plan.ActionRevoke, Resource: `CONNECT on database "app" from "a"`, Statements: []plan.Statement{
		plan.SQL("app", revoke).WithNote("two").WithNote("CASCADE: one"),
		plan.SQL("", "GRANT X"),
	}}}}
	var out strings.Builder
	r := &recorder{}
	if err := Run(t.Context(), r, p, &out, false); err != nil {
		t.Fatal(err)
	}
	want := "-- CASCADE: one\n-- two\n[1/2] (on database \"app\") " + revoke + "\n[2/2] GRANT X\n"
	if out.String() != want {
		t.Errorf("output =\n%s\nwant\n%s", out.String(), want)
	}
	// Notes are never sent to the server.
	if got := strings.Join(r.ran, "\n"); got != "app|"+revoke+"\n|GRANT X" {
		t.Errorf("ran =\n%s", got)
	}
}

// A statement run as another role reaches the Executor as one statement
// with AsRole set, and output and errors name the role.
func TestRunAsRole(t *testing.T) {
	t.Parallel()
	revoke := `REVOKE USAGE ON SCHEMA "api" FROM "app"`
	p := &plan.Plan{Changes: []plan.Change{{Action: plan.ActionRevoke, Resource: `USAGE on schema "api" from "app"`, Statements: []plan.Statement{
		plan.SQL("app", revoke).WithRole("ro"),
		plan.SQL("", "GRANT X").WithRole("g"),
	}}}}
	tests := []struct {
		name    string
		wantErr string
		wantRan []string
		failAt  int
	}{
		{name: "success", wantRan: []string{"app|as ro|" + revoke, "|as g|GRANT X"}},
		{
			name: "failure names the role", failAt: 1, wantRan: []string{"app|as ro|" + revoke},
			wantErr: `statement 1/2 (on database "app", as role "ro") failed: `,
		},
		{
			name: "failure without a database", failAt: 2, wantRan: []string{"app|as ro|" + revoke, "|as g|GRANT X"},
			wantErr: `statement 2/2 (as role "g") failed: `,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &recorder{failAt: tt.failAt}
			var out strings.Builder
			err := Run(t.Context(), r, p, &out, false)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatal(err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("err = %v, want substring %q", err, tt.wantErr)
			}
			if got, want := strings.Join(r.ran, "\n"), strings.Join(tt.wantRan, "\n"); got != want {
				t.Errorf("ran =\n%s\nwant\n%s", got, want)
			}
			if !strings.HasPrefix(out.String(), "[1/2] (on database \"app\", as role \"ro\") "+revoke+"\n") {
				t.Errorf("output =\n%s", out.String())
			}
		})
	}
}

func TestWithholdQuoted(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("SECRET0123456789", 6)
	tests := []struct {
		name, msg, want string
		leak            []string
	}{
		{
			name: "mysql near fragment",
			msg:  "Error 1064 (42000): You have an error in your SQL syntax; near 'p''w'' and 'p'w'",
			want: "Error 1064 (42000): You have an error in your SQL syntax; near <withheld>" + withheldNote,
			leak: []string{"p''w", "p'w"},
		},
		{
			name: "inner quote after four characters",
			msg:  "Error 1064 (42000): You have an error in your SQL syntax; near 'abcd'efgh' at line 1",
			leak: []string{"abcd", "efgh"},
		},
		{
			name: "secret starting with quotes",
			msg:  "Error 1064 (42000): You have an error in your SQL syntax; near ''''''abcdef'' at line 1",
			leak: []string{"abcdef"},
		},
		{
			name: "postgres escape string",
			msg:  `ERROR: syntax error at or near "E'back\\slash'" (SQLSTATE 42601)`,
			want: "ERROR: syntax error at or near <withheld>" + withheldNote,
			leak: []string{"back", "slash", "42601"},
		},
		{
			name: "truncated at 80 characters",
			msg:  "Error 1064 (42000): You have an error in your SQL syntax; near '-pam BY '" + long[:70] + "' at line 1",
			leak: []string{"SECR"},
		},
		{name: "truncated at the end of the text", msg: "failed near '" + long[:10], leak: []string{"SECR"}},
		{name: "backslash-escaped value", msg: `near 'a\'b'c' x`, leak: []string{"a\\'b", "c' x"}},
		{
			name: "multi-line secret",
			msg:  "Error 1064 (42000): You have an error in your SQL syntax; near 'IDENTIFIED BY 'first\nSECONDLINE' xyz' at line 1",
			want: "Error 1064 (42000): You have an error in your SQL syntax; near <withheld>" + withheldNote,
			leak: []string{"first", "SECONDLINE", "xyz"},
		},
		{
			name: "multi-line secret over a detail line",
			msg:  "ERROR: syntax error at or near \"'pre\nTOPSECRET'\" (SQLSTATE 42601)\nDETAIL: near 'x'",
			want: "ERROR: syntax error at or near <withheld>" + withheldNote,
			leak: []string{"pre", "TOPSECRET", "DETAIL"},
		},
		{
			name: "quote on a detail line",
			msg:  "ERROR: password is too short (SQLSTATE 22023)\nDETAIL: near 'hunter2'",
			want: "ERROR: password is too short (SQLSTATE 22023)\nDETAIL: near <withheld>" + withheldNote,
			leak: []string{"hunter2"},
		},
		{
			name: "mysql policy rejection is kept",
			msg:  "Error 1819 (HY000): Your password does not satisfy the current policy requirements",
			want: "Error 1819 (HY000): Your password does not satisfy the current policy requirements",
		},
		{name: "postgres policy rejection is kept", msg: "ERROR: password is too short (SQLSTATE 22023)", want: "ERROR: password is too short (SQLSTATE 22023)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := withholdQuoted(tt.msg)
			if tt.want != "" && got != tt.want {
				t.Errorf("withholdQuoted() =\n%s\nwant\n%s", got, tt.want)
			}
			for _, l := range tt.leak {
				if strings.Contains(strings.TrimSuffix(got, withheldNote), l) {
					t.Errorf("withholdQuoted() leaked %q: %s", l, got)
				}
			}
		})
	}
}

func TestRunWithholdsErrorsOfSecretStatements(t *testing.T) {
	t.Parallel()
	echo := Rejected(errors.New(`Error 1064 (42000): You have an error in your SQL syntax; near 'hunter2' at line 1`))
	tests := []struct {
		name        string
		want, deny  string
		failAt      int
		showSecrets bool
	}{
		{name: "secret statement", failAt: 1, want: "near <withheld>", deny: "hunter2"},
		{name: "secret statement with --show-secrets", failAt: 1, showSecrets: true, want: "near 'hunter2'"},
		{name: "statement without a secret is shown in full", failAt: 2, want: "near 'hunter2'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &recorder{failAt: tt.failAt, err: echo}
			err := Run(t.Context(), r, testPlan(), io.Discard, tt.showSecrets)
			if err == nil || !strings.Contains(err.Error(), tt.want) || (tt.deny != "" && strings.Contains(err.Error(), tt.deny)) {
				t.Errorf("err = %v, want %q without %q", err, tt.want, tt.deny)
			}
		})
	}
}

func TestRunEscapesControlCharacters(t *testing.T) {
	t.Parallel()
	p := &plan.Plan{Changes: []plan.Change{{Action: plan.ActionDrop, Resource: "r", Statements: []plan.Statement{
		plan.SQL("", "DROP ROLE \"x\x1b[2K\r\n-- ok\"").WithNote("note \x1b[8m"),
	}}}}
	var out strings.Builder
	r := &recorder{}
	if err := Run(t.Context(), r, p, &out, false); err != nil {
		t.Fatal(err)
	}
	if want := "-- note \\x1b[8m\n[1/1] DROP ROLE \"x\\x1b[2K\\r\\n-- ok\"\n"; out.String() != want {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
	if want := "|DROP ROLE \"x\x1b[2K\r\n-- ok\""; len(r.ran) != 1 || r.ran[0] != want {
		t.Errorf("ran = %q, want %q", r.ran, want)
	}
}
