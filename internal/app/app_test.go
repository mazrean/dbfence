package app_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mazrean/dbfence/internal/app"
	"github.com/mazrean/dbfence/internal/driver/postgres"
	"github.com/mazrean/dbfence/internal/funcs"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
)

type fakeDriver struct {
	postgres.Dialect
	// unsafe, when set, replaces the statements CreateRole plans.
	unsafe []plan.Statement
	// after holds statements CreateRole plans after the real ones, by
	// role name.
	after    map[string][]plan.Statement
	executed []string
	extra    []model.RoleState
	// memberOf is what the connected user is a member of.
	memberOf []model.RoleID
}

// CreateRole implements diff.Dialect, planning unsafe when set, to stand
// in for a bug in the diff logic.
func (f *fakeDriver) CreateRole(r model.Role) []plan.Statement {
	if f.unsafe != nil {
		return f.unsafe
	}
	return append(f.Dialect.CreateRole(r), f.after[r.ID.Name]...)
}

func (f *fakeDriver) Inspect(context.Context, *model.Desired) (*model.Current, error) {
	roles := append([]model.RoleState{{ID: model.RoleID{Name: "postgres"}, MemberOf: f.memberOf}}, f.extra...)
	return &model.Current{CurrentUser: model.RoleID{Name: "postgres"}, Roles: roles}, nil
}

func (f *fakeDriver) Exec(_ context.Context, s plan.Statement) error {
	f.executed = append(f.executed, s.SQL())
	return nil
}

func (f *fakeDriver) Close() error { return nil }

type fakeOpener struct{ d *fakeDriver }

func (o fakeOpener) Open(context.Context, model.Connection) (app.Driver, error) { return o.d, nil }

func newApp(t *testing.T, stdin string) (*app.App, *fakeDriver, *strings.Builder, string) {
	t.Helper()
	return newAppWith(t, stdin, "user \"app\" {\n  password = \"hunter2\"\n}\n")
}

// newAppWith is newApp with the blocks of src after the connection block.
func newAppWith(t *testing.T, stdin, src string) (*app.App, *fakeDriver, *strings.Builder, string) {
	t.Helper()
	dir := t.TempDir()
	src = "connection \"postgres\" {\n  host = \"h\"\n  user = \"u\"\n}\n" + src
	if err := os.WriteFile(filepath.Join(dir, "dbfence.hcl"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &fakeDriver{}
	out := &strings.Builder{}
	a := app.New(funcs.NewRegistry(t.Context()), fakeOpener{d}, &app.IO{In: strings.NewReader(stdin), Out: out, Err: out})
	return a, d, out, dir
}

func TestPlanDoesNotExecute(t *testing.T) {
	t.Parallel()
	a, d, out, dir := newApp(t, "")
	p, err := a.Plan(t.Context(), app.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if p.Empty() || len(d.executed) != 0 {
		t.Errorf("plan empty=%v executed=%v", p.Empty(), d.executed)
	}
	if !strings.Contains(out.String(), `CREATE ROLE "app" WITH LOGIN PASSWORD '<redacted>'`) || strings.Contains(out.String(), "hunter2") {
		t.Errorf("plan output:\n%s", out)
	}
}

func TestApplyConfirmation(t *testing.T) {
	t.Parallel()
	const prompt = "Only 'yes' is accepted: "
	tests := []struct {
		wantErr     error
		name, stdin string
		wantMsg     string
		wantOut     string
		wantExec    int
	}{
		{name: "yes", stdin: "yes\n", wantExec: 1, wantOut: prompt + "\n[1/1] "},
		{name: "yes without newline", stdin: "yes", wantExec: 1, wantOut: prompt + "\n[1/1] "},
		{name: "no", stdin: "no\n", wantErr: app.ErrAborted, wantMsg: `apply cancelled: the answer was not "yes"`, wantOut: prompt + "\n"},
		{name: "y is not enough", stdin: "y\n", wantErr: app.ErrAborted, wantMsg: "apply cancelled"},
		{name: "eof", stdin: "", wantErr: app.ErrAborted, wantMsg: "--auto-approve", wantOut: prompt + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a, d, out, dir := newApp(t, tt.stdin)
			err := a.Apply(t.Context(), app.Options{Dir: dir})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("err = %v, want substring %q", err, tt.wantMsg)
			}
			if !strings.Contains(out.String(), tt.wantOut) {
				t.Errorf("output = %q, want substring %q", out.String(), tt.wantOut)
			}
			if len(d.executed) != tt.wantExec {
				t.Errorf("executed = %v, want %d statements", d.executed, tt.wantExec)
			}
		})
	}
}

func TestApplyPromptInterrupted(t *testing.T) {
	t.Parallel()
	_, d, out, dir := newApp(t, "")
	r, w := io.Pipe()
	t.Cleanup(func() { _ = w.Close() })
	a := app.New(funcs.NewRegistry(t.Context()), fakeOpener{d}, &app.IO{In: r, Out: out, Err: out})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.Apply(ctx, app.Options{Dir: dir}) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, app.ErrAborted) || !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want ErrAborted and context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Apply still blocked on the prompt after cancel")
	}
	if len(d.executed) != 0 {
		t.Errorf("executed = %v", d.executed)
	}
}

func TestPlanWritesWarningsToStderr(t *testing.T) {
	t.Parallel()
	_, d, _, dir := newApp(t, "")
	d.extra = []model.RoleState{{ID: model.RoleID{Name: "legacy"}}}
	var out, errOut strings.Builder
	a := app.New(funcs.NewRegistry(t.Context()), fakeOpener{d}, &app.IO{In: strings.NewReader(""), Out: &out, Err: &errOut})
	if _, err := a.Plan(t.Context(), app.Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	const warn = `unmanaged role "legacy"`
	if !strings.Contains(out.String(), "-- warning: "+warn) {
		t.Errorf("stdout = %q", out.String())
	}
	if !strings.HasPrefix(errOut.String(), "warning: "+warn) {
		t.Errorf("stderr = %q", errOut.String())
	}
	if !strings.Contains(out.String(), "-- Plan: 1 to create, 0 to change, 0 to drop (1 statement).") {
		t.Errorf("stdout has no summary: %q", out.String())
	}
}

func TestUnsafePlanIsRefused(t *testing.T) {
	t.Parallel()
	postgresUser := model.RoleID{Name: "postgres"}
	tests := []struct {
		name   string
		want   string
		unsafe plan.Statement
	}{
		{
			name:   "drop of the connected user",
			unsafe: plan.New("", plan.KindDropRole, plan.RoleTarget(postgresUser), plan.Keyword("DROP ROLE postgres")),
			want:   `drops the connected user "postgres"`,
		},
		{
			name: "login disabled on the connected user",
			unsafe: plan.New("", plan.KindAlterRole, plan.RoleTarget(postgresUser), plan.Keyword("ALTER ROLE postgres NOLOGIN")).
				WithRoleChange(plan.RoleChange{DisablesLogin: true}),
			want: `disables login of the connected user "postgres"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for _, cmd := range []string{"plan", "apply"} {
				a, d, out, dir := newApp(t, "yes\n")
				d.unsafe = []plan.Statement{tt.unsafe}
				var err error
				if cmd == "plan" {
					_, err = a.Plan(t.Context(), app.Options{Dir: dir})
				} else {
					err = a.Apply(t.Context(), app.Options{Dir: dir})
				}
				if !errors.Is(err, app.ErrUnsafePlan) {
					t.Fatalf("%s: err = %v, want ErrUnsafePlan", cmd, err)
				}
				msg := err.Error()
				if !strings.HasPrefix(msg, "internal safety check failed: ") || !strings.Contains(msg, tt.want) ||
					!strings.HasSuffix(msg, "(this is a bug in dbfence; please report it)") {
					t.Errorf("%s: err = %q", cmd, msg)
				}
				if strings.Contains(out.String(), "Apply these changes?") || len(d.executed) != 0 {
					t.Errorf("%s: prompted or executed %v; output:\n%s", cmd, d.executed, out)
				}
			}
		})
	}
}
