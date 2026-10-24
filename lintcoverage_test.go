package main

import (
	"context"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// TestLintCoversBuiltPackages checks that every package of this module
// compiled into dbfence is matched by ./..., which skips directories named
// testdata or starting with _ or ., so that "go tool lint ./..." checks it.
func TestLintCoversBuiltPackages(t *testing.T) {
	t.Parallel()
	listed := goList(t, "-f", "{{.ImportPath}}", "./...")
	deps := goList(t, "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", ".")
	const module = "github.com/mazrean/dbfence"
	for _, dep := range deps {
		if dep != module && !strings.HasPrefix(dep, module+"/") {
			continue
		}
		if !slices.Contains(listed, dep) {
			t.Errorf("package %s is built into dbfence but not matched by ./..., so lint skips it", dep)
		}
	}
}

func goList(t *testing.T, args ...string) []string {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "go", append([]string{"list"}, args...)...).Output()
	if err != nil {
		t.Fatalf("go list %v: %v", args, err)
	}
	return strings.Fields(string(out))
}
