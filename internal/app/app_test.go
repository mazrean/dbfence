package app_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/app"
	"github.com/mazrean/dbfence/internal/driver/postgres"
	"github.com/mazrean/dbfence/internal/funcs"
	"github.com/mazrean/dbfence/internal/model"
)

type fakeDriver struct {
	postgres.Dialect
	executed []string
}

func (f *fakeDriver) Inspect(context.Context, *model.Desired) (*model.Current, error) {
	return &model.Current{CurrentUser: model.RoleID{Name: "postgres"}, Roles: []model.RoleState{{ID: model.RoleID{Name: "postgres"}}}}, nil
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
	tests := []struct {
		wantErr     error
		name, stdin string
		wantExec    int
	}{
		{name: "yes", stdin: "yes\n", wantExec: 1},
		{name: "no", stdin: "no\n", wantErr: app.ErrAborted},
		{name: "y is not enough", stdin: "y\n", wantErr: app.ErrAborted},
		{name: "eof", stdin: "", wantErr: app.ErrAborted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a, d, _, path := newApp(t, tt.stdin)
			err := a.Apply(t.Context(), app.Options{Path: path})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if len(d.executed) != tt.wantExec {
				t.Errorf("executed = %v, want %d statements", d.executed, tt.wantExec)
			}
		})
	}
}
