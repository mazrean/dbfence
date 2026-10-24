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
	src := "connection {\n  engine = \"postgres\"\n  host = \"h\"\n  user = \"u\"\n}\nrole \"r\" {}\n"
	valid := writeConfig(t, src)
	unknownAttr := writeConfig(t, strings.Replace(src, "role \"r\" {}", "role \"r\" {\n  bogus = true\n}", 1))
	escAttr := writeConfig(t, strings.Replace(src, "role \"r\" {}", "role \"r\" {\n  bogus = true # \x1b[2K\n}", 1))
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
		{name: "validate ok", args: []string{"-C", valid, "validate"}, wantCode: exitOK, wantOut: "The configuration is valid (postgres: 0 databases, 1 role, 0 schemas, 0 privileges).\n", wantErrOut: ""},
		{name: "validate unknown attribute renders the diagnostic unindented", args: []string{"-C", unknownAttr, "validate"}, wantCode: exitError, wantOut: "", wantErrOut: "dbfence: error: Unsupported argument\n\n  on " + filepath.Join(unknownAttr, "dbfence.hcl") + " line 7, in role \"r\":\n   7:   bogus = true\n\nAn argument named \"bogus\" is not expected here.\n"},
		{name: "error escapes control characters but keeps lines", args: []string{"-C", escAttr, "validate"}, wantCode: exitError, wantOut: "", wantErrOut: "   7:   bogus = true # \\x1b[2K\n"},
		{name: "validate missing directory", args: []string{"--chdir", filepath.Join(valid, "none"), "validate"}, wantCode: exitError, wantOut: "", wantErrOut: "read configuration directory (set -C/--chdir or DBFENCE_CHDIR): open "},
		{name: "validate directory without *.hcl", args: []string{"validate", "-C", t.TempDir()}, wantCode: exitError, wantOut: "", wantErrOut: "no *.hcl files in "},
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

// writeConfig writes src as dbfence.hcl into a new directory.
func writeConfig(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dbfence.hcl"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRunLoadsEveryHCLFileInTheWorkingDirectory(t *testing.T) {
	dir := writeConfig(t, "connection {\n  engine = \"postgres\"\n  host = \"h\"\n  user = \"u\"\n}\n")
	for name, src := range map[string]string{
		"roles.hcl":     "role \"r\" {}\n",
		"roles.hcl.bak": "bogus\n",
		"sub/all.hcl":   "bogus\n",
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
	t.Setenv("DBFENCE_CHDIR", "")
	tests := []struct {
		name string
		args []string
	}{
		{name: "empty DBFENCE_CHDIR", args: []string{"validate"}},
		{name: "empty -C", args: []string{"validate", "-C", ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := runTest(t, tt.args, app.NewOpener(), &stdout, &stderr); code != exitOK {
				t.Errorf("exit code = %d, want 0\nstderr: %s", code, stderr.String())
			}
			if want := "The configuration is valid (postgres: 0 databases, 1 role, 0 schemas, 0 privileges).\n"; stdout.String() != want {
				t.Errorf("stdout = %q, want %q", stdout.String(), want)
			}
		})
	}
}
