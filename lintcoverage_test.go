package main

import (
	"context"
	"os"
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
	listed := goList(t, nil, "-f", "{{.ImportPath}}", "./...")
	deps := goList(t, nil, "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", ".")
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

// TestNoBuildConstrainedFiles checks that every build of dbfence compiles
// the same files: lint runs once, for the host, and sees only the files of
// that build. A file excluded by a build constraint or a _GOOS/_GOARCH
// name suffix, for some target or with or without cgo, is listed as
// ignored in one of these configurations.
func TestNoBuildConstrainedFiles(t *testing.T) {
	t.Parallel()
	for _, cgo := range []string{"0", "1"} {
		ignored := goList(t, []string{"CGO_ENABLED=" + cgo}, "-f",
			"{{range .IgnoredGoFiles}}{{$.Dir}}/{{.}} {{end}}{{range .IgnoredOtherFiles}}{{$.Dir}}/{{.}} {{end}}", "./...")
		for _, f := range ignored {
			t.Errorf("%s is excluded from the CGO_ENABLED=%s host build, so lint, which checks one build, may not see it in another; remove its build constraint", f, cgo)
		}
	}
}

func goList(t *testing.T, env []string, args ...string) []string {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "go", append([]string{"list"}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list %v: %v", args, err)
	}
	return strings.Fields(string(out))
}
