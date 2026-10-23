package funcs

import (
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// withFixedError wraps fn so that the errors it reports while running
// (and, with typeErrors, while checking argument types) are replaced by
// msg. Some stdlib functions quote their argument in errors (tonumber
// prints the string, jsondecode the offending character), which would
// leak secrets such as aws_secretsmanager(...) results into the output.
func withFixedError(fn function.Function, msg string, typeErrors bool) function.Function {
	return function.New(&function.Spec{
		Description: fn.Description(),
		Params:      fn.Params(),
		VarParam:    fn.VarParam(),
		Type: func(args []cty.Value) (cty.Type, error) {
			ty, err := fn.ReturnTypeForValues(args)
			if err != nil && typeErrors {
				return cty.NilType, function.NewArgErrorf(0, "%s", msg)
			}
			return ty, err
		},
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			v, err := fn.Call(args)
			if err != nil {
				return cty.NilVal, function.NewArgErrorf(0, "%s", msg)
			}
			return v, nil
		},
	})
}
