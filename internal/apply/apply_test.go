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

func (r *recorder) Exec(_ context.Context, database, query string) error {
	r.ran = append(r.ran, database+"|"+query)
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

func TestRunPrintsCommentsBeforeTheStatement(t *testing.T) {
	t.Parallel()
	p := &plan.Plan{Changes: []plan.Change{{Action: plan.ActionRevoke, Resource: `CONNECT on database "app" from "a"`, Statements: []plan.Statement{
		plan.SQL("app", "-- CASCADE: one\n-- two\nREVOKE CONNECT ON DATABASE \"app\" FROM \"a\" CASCADE"),
		plan.SQL("", "-- only a comment"),
	}}}}
	var out strings.Builder
	if err := Run(t.Context(), &recorder{}, p, &out, false); err != nil {
		t.Fatal(err)
	}
	want := "-- CASCADE: one\n-- two\n[1/2] (on database \"app\") REVOKE CONNECT ON DATABASE \"app\" FROM \"a\" CASCADE\n[2/2] -- only a comment\n"
	if out.String() != want {
		t.Errorf("output =\n%s\nwant\n%s", out.String(), want)
	}
}
