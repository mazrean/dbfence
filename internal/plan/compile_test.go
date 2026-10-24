package plan

import (
	"os/exec"
	"strings"
	"testing"
)

// A runtime string cannot be passed as SQL text: the programs under
// testdata/nonconst try and must fail to compile. (Converting one to
// Keyword compiles; the sqlfragment lint rule in tools/lint rejects it.)
func TestRuntimeStringIsNotSQL(t *testing.T) {
	t.Parallel()
	goCmd, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go command not found")
	}
	tests := []struct {
		dir, want string
	}{
		{dir: "string", want: "does not implement plan.Fragment"},
		{dir: "field", want: "field text"},
		{dir: "secret", want: "cannot use os.Args[1]"},
	}
	for _, tt := range tests {
		t.Run(tt.dir, func(t *testing.T) {
			t.Parallel()
			out, err := exec.CommandContext(t.Context(), goCmd, "vet", "./testdata/nonconst/"+tt.dir).CombinedOutput()
			if err == nil {
				t.Fatalf("testdata/nonconst/%s compiled", tt.dir)
			}
			if !strings.Contains(string(out), tt.want) {
				t.Errorf("go vet output = %s, want %q", out, tt.want)
			}
		})
	}
}
