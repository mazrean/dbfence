package funcs

import (
	"errors"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// Sensitive is the cty mark carried by values that come from a secret
// source (env, aws_secretsmanager, gcp_secretmanager, tfstate) and by
// every value computed from them. cty and HCL propagate it through
// operators, templates, attribute access and function calls.
var Sensitive = sensitiveMark{}

type sensitiveMark struct{}

func (sensitiveMark) GoString() string { return "funcs.Sensitive" }

// markSensitive wraps fn so that its results carry Sensitive.
func markSensitive(fn function.Function) function.Function {
	return function.New(&function.Spec{
		Description: fn.Description(),
		Params:      fn.Params(),
		VarParam:    fn.VarParam(),
		Type:        fn.ReturnTypeForValues,
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			v, err := fn.Call(args)
			if err != nil {
				return cty.NilVal, err
			}
			return v.Mark(Sensitive), nil
		},
	})
}

// guard wraps fn so that it never reports an error about a sensitive
// argument in detail. Functions quote their arguments in errors (tonumber
// prints the string, jsondecode the offending character), and which ones
// do is not under dbfence's control, so whenever an argument is marked
// Sensitive the error is replaced by a fixed message. fn itself only sees
// unmarked arguments, and their marks are put back on its result.
func guard(fn function.Function) function.Function {
	params := fn.Params()
	for i := range params {
		params[i].AllowMarked = true
	}
	var varParam *function.Parameter
	if vp := fn.VarParam(); vp != nil {
		p := *vp
		p.AllowMarked = true
		varParam = &p
	}
	return function.New(&function.Spec{
		Description: fn.Description(),
		Params:      params,
		VarParam:    varParam,
		Type: func(args []cty.Value) (cty.Type, error) {
			plain, marks := unmarkAll(args)
			ty, err := fn.ReturnTypeForValues(plain)
			return ty, sanitize(err, marks)
		},
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			plain, marks := unmarkAll(args)
			v, err := fn.Call(plain)
			if err != nil {
				return cty.NilVal, sanitize(err, marks)
			}
			return v.WithMarks(marks), nil
		},
	})
}

// unmarkAll removes the marks of args, including nested ones, and returns
// their union.
func unmarkAll(args []cty.Value) ([]cty.Value, cty.ValueMarks) {
	out := make([]cty.Value, len(args))
	marks := make(cty.ValueMarks)
	for i, a := range args {
		v, m := a.UnmarkDeep()
		out[i] = v
		for k := range m {
			marks[k] = struct{}{}
		}
	}
	return out, marks
}

// secretErrorMessage replaces errors about sensitive arguments.
const secretErrorMessage = "the error is not shown because the arguments include a secret value"

// sanitize replaces err when an argument was sensitive, keeping the
// argument position so that HCL still points at the right expression.
func sanitize(err error, marks cty.ValueMarks) error {
	if err == nil || !marks.Has(Sensitive) {
		return err
	}
	if argErr, ok := errors.AsType[function.ArgError](err); ok {
		return function.NewArgErrorf(argErr.Index, "%s", secretErrorMessage)
	}
	return errors.New(secretErrorMessage)
}

// guardAll applies guard to every function of fns.
func guardAll(fns map[string]function.Function) map[string]function.Function {
	out := make(map[string]function.Function, len(fns))
	for name, fn := range fns {
		out[name] = guard(fn)
	}
	return out
}
