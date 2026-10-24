// Package outputsink defines an analyzer that keeps all dbfence output on
// the redacting output sink (internal/secret.Writer, wired in
// internal/di/di.go). Writing to os.Stdout or os.Stderr directly, or with
// fmt.Print, fmt.Printf, fmt.Println, print or println, would bypass the
// redaction of secrets and the escaping of control characters.
package outputsink

import (
	"go/ast"
	"go/types"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// Allowed are the files, by slash-separated path suffix, that may use the
// process output streams: the file that wraps them in the sink.
var Allowed = []string{"internal/di/di.go"}

// Analyzer reports uses of the process output streams outside Allowed.
var Analyzer = &analysis.Analyzer{
	Name: "outputsink",
	Doc:  "reports output that bypasses the redacting output sink (os.Stdout, os.Stderr, fmt.Print*, print, println) outside test files and internal/di/di.go",
	Run:  run,
}

func run(pass *analysis.Pass) (any, error) {
	for _, f := range pass.Files {
		name := filepath.ToSlash(pass.Fset.File(f.Pos()).Name())
		if strings.HasSuffix(name, "_test.go") || slices.ContainsFunc(Allowed, func(a string) bool {
			return name == a || strings.HasSuffix(name, "/"+a)
		}) {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if what := bypass(pass.TypesInfo.Uses[id]); what != "" {
				pass.Reportf(id.Pos(), "%s bypasses the redacting output sink; write to the app.IO streams instead", what)
			}
			return true
		})
	}
	return nil, nil
}

// bypass names obj when it writes to the process output streams.
func bypass(obj types.Object) string {
	switch obj := obj.(type) {
	case *types.Var:
		if obj.Pkg() != nil && obj.Pkg().Path() == "os" && (obj.Name() == "Stdout" || obj.Name() == "Stderr") {
			return "os." + obj.Name()
		}
	case *types.Func:
		if obj.Pkg() != nil && obj.Pkg().Path() == "fmt" && slices.Contains([]string{"Print", "Printf", "Println"}, obj.Name()) {
			return "fmt." + obj.Name()
		}
	case *types.Builtin:
		if obj.Name() == "print" || obj.Name() == "println" {
			return obj.Name()
		}
	}
	return ""
}
