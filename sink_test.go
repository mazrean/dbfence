package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/app"
	"github.com/mazrean/dbfence/internal/driver/postgres"
	"github.com/mazrean/dbfence/internal/funcs"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
	"github.com/mazrean/dbfence/internal/secret"
)

// runTest runs args with stdout and stderr behind the program's output
// sink, redacting the secrets of secret.Default as the binary does.
func runTest(t *testing.T, args []string, opener app.Opener, stdout, stderr *bytes.Buffer) int {
	t.Helper()
	out := secret.NewWriter(stdout, secret.Default())
	errOut := secret.NewWriter(stderr, secret.Default())
	a := app.New(funcs.NewRegistry(t.Context()), opener, &app.IO{In: strings.NewReader(""), Out: out, Err: errOut})
	return run(t.Context(), args, a, out, errOut)
}

type emptyServer struct{ postgres.Dialect }

func (emptyServer) Inspect(context.Context, *model.Desired) (*model.Current, error) {
	return &model.Current{CurrentUser: model.RoleID{Name: "postgres"}, Roles: []model.RoleState{{ID: model.RoleID{Name: "postgres"}}}}, nil
}

func (emptyServer) Exec(context.Context, plan.Statement) error { return nil }

func (emptyServer) Close() error { return nil }

type emptyServerOpener struct{}

func (emptyServerOpener) Open(context.Context, model.Connection) (app.Driver, error) {
	return emptyServer{}, nil
}

// TestRunRedactsSecrets checks that output redacts a password wherever it
// appears, here as a role name, unless --show-secrets is given.
func TestRunRedactsSecrets(t *testing.T) {
	t.Parallel()
	const pw = "cli-sink-secret-pw"
	dir := writeConfig(t, "connection \"postgres\" {\n  host = \"h\"\n  user = \"u\"\n}\nuser \""+pw+"\" {\n  password = \""+pw+"\"\n}\n")
	tests := []struct {
		name  string
		want  string
		args  []string
		leaks bool
	}{
		{name: "plan redacts", args: []string{"-C", dir, "plan"}, want: `CREATE ROLE "<redacted>" WITH LOGIN PASSWORD '<redacted>'`},
		{name: "show secrets bypasses the sink", args: []string{"-C", dir, "plan", "--show-secrets"}, want: `CREATE ROLE "` + pw + `" WITH LOGIN PASSWORD '` + pw + `'`, leaks: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := runTest(t, tt.args, emptyServerOpener{}, &stdout, &stderr); code != exitOK {
				t.Fatalf("exit code = %d\nstderr: %s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), tt.want) {
				t.Errorf("stdout = %q, want substring %q", stdout.String(), tt.want)
			}
			if !tt.leaks && strings.Contains(stdout.String()+stderr.String(), pw) {
				t.Errorf("output leaks the password:\n%s%s", stdout.String(), stderr.String())
			}
		})
	}
}
