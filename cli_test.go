package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/app"
	"github.com/mazrean/dbfence/internal/funcs"
)

func TestRun(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	valid := filepath.Join(dir, "valid.hcl")
	src := "connection {\n  engine = \"postgres\"\n  dsn = \"postgres://localhost/x\"\n}\nrole \"r\" {}\n"
	if err := os.WriteFile(valid, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		wantOut    string
		wantErrOut string
		args       []string
		wantCode   int
	}{
		{name: "no command", args: nil, wantCode: exitError, wantOut: "", wantErrOut: "expected one of"},
		{name: "help", args: []string{"--help"}, wantCode: exitOK, wantOut: "Usage: dbfence <command>", wantErrOut: ""},
		{name: "version", args: []string{"--version"}, wantCode: exitOK, wantOut: getVersion(), wantErrOut: ""},
		{name: "unknown command", args: []string{"destroy"}, wantCode: exitError, wantOut: "", wantErrOut: "unexpected argument destroy"},
		{name: "plan help lists flags", args: []string{"plan", "--help"}, wantCode: exitOK, wantOut: "--detailed-exitcode", wantErrOut: ""},
		{name: "apply unknown flag", args: []string{"apply", "--detailed-exitcode"}, wantCode: exitError, wantOut: "", wantErrOut: "unknown flag --detailed-exitcode"},
		{name: "validate ok", args: []string{"validate", "-f", valid}, wantCode: exitOK, wantOut: "The configuration is valid (postgres: 0 databases, 1 roles", wantErrOut: ""},
		{name: "validate missing file", args: []string{"validate", "-f", filepath.Join(dir, "none.hcl")}, wantCode: exitError, wantOut: "", wantErrOut: "no such file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			a := app.New(funcs.NewRegistry(t.Context()), app.NewOpener(), &app.IO{In: strings.NewReader(""), Out: &stdout, Err: &stderr})
			code := run(t.Context(), tt.args, a, &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), tt.wantOut) {
				t.Errorf("stdout = %q, want substring %q", stdout.String(), tt.wantOut)
			}
			if !strings.Contains(stderr.String(), tt.wantErrOut) {
				t.Errorf("stderr = %q, want substring %q", stderr.String(), tt.wantErrOut)
			}
		})
	}
}
