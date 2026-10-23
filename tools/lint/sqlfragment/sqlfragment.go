// Package sqlfragment defines an analyzer that keeps runtime strings out
// of SQL text. Statements in internal/plan are built only from typed
// fragments: SQL text is a plan.Keyword, which must be a constant, and the
// fragments that wrap runtime values (plan.QuotedIdent, plan.EscapedLiteral,
// plan.NewToken) may be produced only by the engine Dialects under
// internal/driver, which quote, escape or validate the value first.
package sqlfragment

import (
	"go/ast"
	"go/types"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// PlanPath is the import path of the package that defines the fragments.
const PlanPath = "github.com/mazrean/dbfence/internal/plan"

// Constructors wrap a runtime value that the caller has already quoted,
// escaped or validated.
var Constructors = []string{"QuotedIdent", "EscapedLiteral", "NewToken"}

// Analyzer reports non-constant conversions to plan.Keyword and uses of
// the fragment constructors outside internal/driver, internal/plan and
// test files.
var Analyzer = &analysis.Analyzer{
	Name: "sqlfragment",
	Doc: "reports conversions of non-constant values to plan.Keyword (SQL text must be a constant) and uses of " +
		"plan.QuotedIdent, plan.EscapedLiteral and plan.NewToken outside internal/driver, internal/plan and test files",
	Run: run,
}

func run(pass *analysis.Pass) (any, error) {
	trusted := pass.Pkg.Path() == PlanPath || strings.Contains(pass.Pkg.Path()+"/", "/internal/driver/")
	for _, f := range pass.Files {
		test := strings.HasSuffix(filepath.ToSlash(pass.Fset.File(f.Pos()).Name()), "_test.go")
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				checkConversion(pass, n)
			case *ast.Ident:
				checkInstance(pass, n)
				if trusted || test {
					return true
				}
				if fn, ok := pass.TypesInfo.Uses[n].(*types.Func); ok && isPlan(fn) && slices.Contains(Constructors, fn.Name()) {
					pass.Reportf(n.Pos(), "plan.%s may be used only by the engine Dialects under internal/driver; quote, escape or validate the value there", fn.Name())
				}
			}
			return true
		})
	}
	return nil, nil
}

// checkConversion reports call when it converts a non-constant value
// that is not already a Keyword to plan.Keyword.
func checkConversion(pass *analysis.Pass, call *ast.CallExpr) {
	tv, ok := pass.TypesInfo.Types[call.Fun]
	if !ok || !tv.IsType() || !isKeyword(tv.Type) || len(call.Args) != 1 {
		return
	}
	arg := pass.TypesInfo.Types[call.Args[0]]
	if arg.Value != nil || isKeyword(arg.Type) {
		return
	}
	pass.Reportf(call.Pos(), "plan.Keyword converts a non-constant value to SQL text; use a constant, or quote the value with the engine Dialect")
}

// checkInstance reports id when it instantiates a generic function with
// plan.Keyword for a type parameter whose constraint has type terms (such
// as ~string), since the function may then convert a string to it.
func checkInstance(pass *analysis.Pass, id *ast.Ident) {
	inst, ok := pass.TypesInfo.Instances[id]
	if !ok {
		return
	}
	fn, ok := pass.TypesInfo.Uses[id].(*types.Func)
	if !ok {
		return
	}
	sig, ok := fn.Origin().Type().(*types.Signature)
	if !ok {
		return
	}
	tparams := sig.TypeParams()
	for i := range inst.TypeArgs.Len() {
		if i < tparams.Len() && isKeyword(inst.TypeArgs.At(i)) && hasTypeTerms(tparams.At(i).Constraint()) {
			pass.Reportf(id.Pos(), "plan.Keyword instantiates a type parameter that admits string conversions; SQL text must be a constant")
		}
	}
}

// hasTypeTerms reports whether the constraint t lists types, directly or
// through embedded interfaces.
func hasTypeTerms(t types.Type) bool {
	iface, ok := t.Underlying().(*types.Interface)
	if !ok {
		return true
	}
	for i := range iface.NumEmbeddeds() {
		switch e := iface.EmbeddedType(i).(type) {
		case *types.Union:
			return true
		default:
			if _, ok := e.Underlying().(*types.Interface); !ok || hasTypeTerms(e) {
				return true
			}
		}
	}
	return false
}

func isKeyword(t types.Type) bool {
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj().Name() == "Keyword" && isPlan(named.Obj())
}

func isPlan(obj types.Object) bool { return obj.Pkg() != nil && obj.Pkg().Path() == PlanPath }
