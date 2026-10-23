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
)

type fakeDriver struct {
	executed []string
	extra    []model.RoleState
	postgres.Dialect
}

func (f *fakeDriver) Inspect(context.Context, *model.Desired) (*model.Current, error) {
	roles := append([]model.RoleState{{ID: model.RoleID{Name: "postgres"}}}, f.extra...)
	return &model.Current{CurrentUser: model.RoleID{Name: "postgres"}, Roles: roles}, nil
}

func (f *fakeDriver) Exec(_ context.Context, _, q string) error {
	f.executed = append(f.executed, q)
	return nil
}

func (f *fakeDriver) Close() error { return nil }

type fakeOpener struct{ d *fakeDriver }

func (o fakeOpener) Open(context.Context, model.Engine, string) (app.Driver, error) { return o.d, nil }

func newApp(t *testing.T, stdin string) (*app.App, *fakeDriver, *strings.Builder, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dbfence.hcl")
	src := "connection {\n  engine = \"postgres\"\n  dsn = \"x\"\n}\nuser \"app\" {\n  password = \"hunter2\"\n}\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &fakeDriver{}
	out := &strings.Builder{}
	a := app.New(funcs.NewRegistry(t.Context()), fakeOpener{d}, &app.IO{In: strings.NewReader(stdin), Out: out, Err: out})
	return a, d, out, path
}

func TestPlanDoesNotExecute(t *testing.T) {
	t.Parallel()
	a, d, out, path := newApp(t, "")
	p, err := a.Plan(t.Context(), app.Options{Path: path})
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
			a, d, out, path := newApp(t, tt.stdin)
			err := a.Apply(t.Context(), app.Options{Path: path})
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
	_, d, out, path := newApp(t, "")
	r, w := io.Pipe()
	t.Cleanup(func() { _ = w.Close() })
	a := app.New(funcs.NewRegistry(t.Context()), fakeOpener{d}, &app.IO{In: r, Out: out, Err: out})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.Apply(ctx, app.Options{Path: path}) }()
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
	_, d, _, path := newApp(t, "")
	d.extra = []model.RoleState{{ID: model.RoleID{Name: "legacy"}}}
	var out, errOut strings.Builder
	a := app.New(funcs.NewRegistry(t.Context()), fakeOpener{d}, &app.IO{In: strings.NewReader(""), Out: &out, Err: &errOut})
	if _, err := a.Plan(t.Context(), app.Options{Path: path}); err != nil {
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
