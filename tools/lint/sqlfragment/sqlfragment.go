// Package sqlfragment defines an analyzer that keeps runtime strings out
// of SQL text. Statements in internal/plan are built only from typed
// fragments: SQL text is a plan.Keyword, which must be a constant, and the
// fragments that wrap runtime values (plan.QuotedIdent, plan.EscapedLiteral,
// plan.NewToken) may be produced only by the engine Dialects under
// internal/driver, which quote, escape or validate the value first.
//
// A Keyword can also be filled without a visible conversion: through a
// pointer (*(*plan.Keyword)(&s), json.Unmarshal(b, &k), fmt.Sscan(s, &k)),
// through a generic function or type whose code converts to its type
// parameter, or through unsafe, reflect and gob. Outside internal/plan and
// test files the analyzer therefore also reports pointers to values that
// contain a Keyword, instantiations of generics defined outside
// internal/plan with a type argument that contains a Keyword, and imports
// of unsafe, reflect and encoding/gob (which decodes registered types into
// interface fields such as plan.Fragment). Values carried only through an
// interface are not tracked further.
package sqlfragment

import (
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// PlanPath is the import path of the package that defines the fragments.
const PlanPath = "github.com/mazrean/dbfence/internal/plan"

// Constructors wrap a runtime value that the caller has already quoted,
// escaped or validated.
var Constructors = []string{"QuotedIdent", "EscapedLiteral", "NewToken"}

// Forbidden are the packages that can build a Keyword from a runtime
// string without a conversion the analyzer sees.
var Forbidden = []string{"encoding/gob", "reflect", "unsafe"}

// Analyzer reports non-constant conversions to plan.Keyword, other ways to
// fill a Keyword from a runtime value, and uses of the fragment
// constructors outside internal/driver, internal/plan and test files.
var Analyzer = &analysis.Analyzer{
	Name: "sqlfragment",
	Doc: "reports conversions of non-constant values to plan.Keyword or to types that contain it (SQL text must be a constant); " +
		"outside internal/plan and test files, pointers to values that contain plan.Keyword, generic instantiations with such type " +
		"arguments and imports of encoding/gob, reflect and unsafe; and uses of plan.QuotedIdent, plan.EscapedLiteral and plan.NewToken outside " +
		"internal/driver, internal/plan and test files",
	Run: run,
}

func run(pass *analysis.Pass) (any, error) {
	inPlan := pass.Pkg.Path() == PlanPath
	trusted := inPlan || strings.Contains(pass.Pkg.Path()+"/", "/internal/driver/")
	for _, f := range pass.Files {
		test := strings.HasSuffix(filepath.ToSlash(pass.Fset.File(f.Pos()).Name()), "_test.go")
		strict := !inPlan && !test
		if strict {
			checkImports(pass, f)
		}
		convFuns := map[ast.Expr]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				if checkConversion(pass, n) {
					convFuns[ast.Unparen(n.Fun)] = true
				}
				if strict {
					checkNew(pass, n)
				}
			case *ast.UnaryExpr:
				if strict && n.Op == token.AND && containsKeyword(pass.TypesInfo.TypeOf(n.X)) {
					pass.Reportf(n.Pos(), "taking the address of a value that contains plan.Keyword lets code fill SQL text without a conversion; pass the value instead")
				}
			case *ast.StarExpr:
				if strict && !convFuns[n] {
					checkPointerType(pass, n)
				}
			case *ast.Ident:
				checkInstance(pass, n, strict)
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

// checkImports reports imports of encoding/gob, reflect and unsafe, which
// can build a Keyword from a string (gob decoding a registered Keyword into
// an interface, reflect.Value.SetString or Convert, unsafe.Pointer).
func checkImports(pass *analysis.Pass, f *ast.File) {
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err == nil && slices.Contains(Forbidden, path) {
			pass.Reportf(imp.Pos(), "package %s can build plan.Keyword from a runtime string; only internal/plan and tests may import it", path)
		}
	}
}

// checkConversion reports call when it converts a value to plan.Keyword or
// to a type that contains it, unless the value is a constant converted to
// Keyword or already has the same Keyword-containing structure, and when
// it converts a value that contains a Keyword to unsafe.Pointer. It returns
// whether call converts to a type that contains a Keyword.
func checkConversion(pass *analysis.Pass, call *ast.CallExpr) bool {
	tv, ok := pass.TypesInfo.Types[call.Fun]
	if !ok || !tv.IsType() || len(call.Args) != 1 {
		return false
	}
	arg := pass.TypesInfo.Types[call.Args[0]]
	if isUnsafePointer(tv.Type) {
		if containsKeyword(arg.Type) {
			pass.Reportf(call.Pos(), "unsafe.Pointer of a value that contains plan.Keyword lets code fill SQL text without a conversion")
		}
		return false
	}
	if !containsKeyword(tv.Type) {
		return false
	}
	switch {
	case isKeyword(tv.Type) && (arg.Value != nil || isKeyword(arg.Type)):
	case containsKeyword(arg.Type) && types.Identical(arg.Type.Underlying(), tv.Type.Underlying()):
	case isKeyword(tv.Type):
		pass.Reportf(call.Pos(), "plan.Keyword converts a non-constant value to SQL text; use a constant, or quote the value with the engine Dialect")
	default:
		pass.Reportf(call.Pos(), "conversion to %s, which contains plan.Keyword, turns a runtime value into SQL text; use constants, or quote the value with the engine Dialect",
			types.TypeString(tv.Type, qualifier(pass.Pkg)))
	}
	return true
}

// checkNew reports new(T) and new(v) whose result points to a value that
// contains a Keyword.
func checkNew(pass *analysis.Pass, call *ast.CallExpr) {
	id, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return
	}
	if b, ok := pass.TypesInfo.Uses[id].(*types.Builtin); !ok || b.Name() != "new" {
		return
	}
	if p, ok := pass.TypesInfo.TypeOf(call).(*types.Pointer); ok && containsKeyword(p.Elem()) {
		pass.Reportf(call.Pos(), "new of a type that contains plan.Keyword yields a pointer through which code can fill SQL text without a conversion")
	}
}

// checkPointerType reports the type expression *T when T contains a
// Keyword.
func checkPointerType(pass *analysis.Pass, star *ast.StarExpr) {
	tv, ok := pass.TypesInfo.Types[star]
	if !ok || !tv.IsType() {
		return
	}
	if p, ok := tv.Type.(*types.Pointer); ok && containsKeyword(p.Elem()) {
		pass.Reportf(star.Pos(), "pointer to a type that contains plan.Keyword lets code fill SQL text without a conversion; use values")
	}
}

// checkInstance reports id when it instantiates a generic function or
// type with plan.Keyword, or a type that contains it, as a type argument.
// Outside internal/plan and test files (strict) every such instantiation
// of a generic defined outside internal/plan is reported, since the
// generic code may fill the value by conversion or reflection; elsewhere
// only type parameters whose constraint has type terms (such as ~string)
// are, since the code may then convert a string to them.
func checkInstance(pass *analysis.Pass, id *ast.Ident, strict bool) {
	inst, ok := pass.TypesInfo.Instances[id]
	if !ok {
		return
	}
	var (
		tparams *types.TypeParamList
		origin  types.Object
	)
	switch obj := pass.TypesInfo.Uses[id].(type) {
	case *types.Func:
		sig, ok := obj.Origin().Type().(*types.Signature)
		if !ok {
			return
		}
		tparams, origin = sig.TypeParams(), obj.Origin()
	case *types.TypeName:
		named, ok := types.Unalias(obj.Type()).(*types.Named)
		if !ok {
			return
		}
		tparams, origin = named.Origin().TypeParams(), named.Origin().Obj()
	default:
		return
	}
	for i := range inst.TypeArgs.Len() {
		arg := inst.TypeArgs.At(i)
		switch {
		case strict && !isPlan(origin) && containsKeyword(arg):
			pass.Reportf(id.Pos(), "%s instantiates a generic with a type argument that contains plan.Keyword; the generic code could fill SQL text from a runtime value",
				types.TypeString(arg, qualifier(pass.Pkg)))
			return
		case !strict && i < tparams.Len() && isKeyword(arg) && hasTypeTerms(tparams.At(i).Constraint()):
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

// containsKeyword reports whether t is plan.Keyword or is built from it:
// a pointer, slice, array, map, channel, struct, function or named type
// (including its type arguments) with a Keyword somewhere inside.
// Interfaces and type parameters do not count.
func containsKeyword(t types.Type) bool {
	return contains(t, map[types.Type]bool{})
}

func contains(t types.Type, seen map[types.Type]bool) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if seen[t] {
		return false
	}
	seen[t] = true
	switch t := t.(type) {
	case *types.Named:
		if isKeyword(t) {
			return true
		}
		if args := t.TypeArgs(); args != nil {
			for i := range args.Len() {
				if contains(args.At(i), seen) {
					return true
				}
			}
		}
		return contains(t.Underlying(), seen)
	case *types.Pointer:
		return contains(t.Elem(), seen)
	case *types.Slice:
		return contains(t.Elem(), seen)
	case *types.Array:
		return contains(t.Elem(), seen)
	case *types.Chan:
		return contains(t.Elem(), seen)
	case *types.Map:
		return contains(t.Key(), seen) || contains(t.Elem(), seen)
	case *types.Struct:
		for i := range t.NumFields() {
			if contains(t.Field(i).Type(), seen) {
				return true
			}
		}
	case *types.Signature:
		return contains(t.Params(), seen) || contains(t.Results(), seen)
	case *types.Tuple:
		for i := range t.Len() {
			if contains(t.At(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}

// qualifier names types of other packages by package name, as in source.
func qualifier(pkg *types.Package) types.Qualifier {
	return func(p *types.Package) string {
		if p == pkg {
			return ""
		}
		return p.Name()
	}
}

func isUnsafePointer(t types.Type) bool {
	b, ok := types.Unalias(t).(*types.Basic)
	return ok && b.Kind() == types.UnsafePointer
}

func isKeyword(t types.Type) bool {
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj().Name() == "Keyword" && isPlan(named.Obj())
}

func isPlan(obj types.Object) bool { return obj.Pkg() != nil && obj.Pkg().Path() == PlanPath }
