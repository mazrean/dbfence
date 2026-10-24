package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/app"
)

func TestRun(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	valid := filepath.Join(dir, "valid.hcl")
	src := "connection {\n  engine = \"postgres\"\n  dsn = \"postgres://localhost/x\"\n}\nrole \"r\" {}\n"
	if err := os.WriteFile(valid, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	unknownAttr := filepath.Join(dir, "unknown.hcl")
	if err := os.WriteFile(unknownAttr, []byte(strings.Replace(src, "role \"r\" {}", "role \"r\" {\n  bogus = true\n}", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	escAttr := filepath.Join(dir, "esc.hcl")
	if err := os.WriteFile(escAttr, []byte(strings.Replace(src, "role \"r\" {}", "role \"r\" {\n  bogus = true # \x1b[2K\n}", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		wantOut    string
		wantErrOut string
		args       []string
		wantCode   int
	}{
		{name: "no command", args: nil, wantCode: exitError, wantOut: "", wantErrOut: "Run \"dbfence --help\" for more information.\n\ndbfence: error: expected one of"},
		{name: "unknown flag prints a usage hint", args: []string{"plan", "--foo"}, wantCode: exitError, wantOut: "", wantErrOut: "Usage: dbfence plan [flags]"},
		{name: "help", args: []string{"--help"}, wantCode: exitOK, wantOut: "Usage: dbfence <command>", wantErrOut: ""},
		{name: "version", args: []string{"--version"}, wantCode: exitOK, wantOut: getVersion(), wantErrOut: ""},
		{name: "unknown command", args: []string{"destroy"}, wantCode: exitError, wantOut: "", wantErrOut: "unexpected argument destroy"},
		{name: "plan help lists flags", args: []string{"plan", "--help"}, wantCode: exitOK, wantOut: "--detailed-exitcode", wantErrOut: ""},
		{name: "apply unknown flag", args: []string{"apply", "--detailed-exitcode"}, wantCode: exitError, wantOut: "", wantErrOut: "unknown flag --detailed-exitcode"},
		{name: "validate ok", args: []string{"validate", "-f", valid}, wantCode: exitOK, wantOut: "The configuration is valid (postgres: 0 databases, 1 role, 0 schemas, 0 privileges).\n", wantErrOut: ""},
		{name: "validate unknown attribute renders the diagnostic unindented", args: []string{"validate", "-f", unknownAttr}, wantCode: exitError, wantOut: "", wantErrOut: "dbfence: error: Unsupported argument\n\n  on " + unknownAttr + " line 6, in role \"r\":\n   6:   bogus = true\n\nAn argument named \"bogus\" is not expected here.\n"},
		{name: "error escapes control characters but keeps lines", args: []string{"validate", "-f", escAttr}, wantCode: exitError, wantOut: "", wantErrOut: "   6:   bogus = true # \\x1b[2K\n"},
		{name: "validate missing file", args: []string{"validate", "-f", filepath.Join(dir, "none.hcl")}, wantCode: exitError, wantOut: "", wantErrOut: "not found (set -f/--file or DBFENCE_FILE)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			code := runTest(t, tt.args, app.NewOpener(), &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), tt.wantOut) {
				t.Errorf("stdout = %q, want substring %q", stdout.String(), tt.wantOut)
			}
			if tt.wantOut == "" && stdout.Len() > 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
			if strings.ContainsAny(stderr.String(), "\x1b\r") {
				t.Errorf("stderr = %q, contains raw control characters", stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.wantErrOut) {
				t.Errorf("stderr = %q, want substring %q", stderr.String(), tt.wantErrOut)
			}
		})
	}
}

func TestRunEmptyFileFallsBackToDefault(t *testing.T) {
	dir := t.TempDir()
	src := "connection {\n  engine = \"postgres\"\n  dsn = \"postgres://localhost/x\"\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "dbfence.hcl"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	t.Setenv("DBFENCE_FILE", "")
	tests := []struct {
		name string
		args []string
	}{
		{name: "empty DBFENCE_FILE", args: []string{"validate"}},
		{name: "empty -f", args: []string{"validate", "-f", ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := runTest(t, tt.args, app.NewOpener(), &stdout, &stderr); code != exitOK {
				t.Errorf("exit code = %d, want 0\nstderr: %s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), "The configuration is valid") {
				t.Errorf("stdout = %q", stdout.String())
			}
		})
	}
}
