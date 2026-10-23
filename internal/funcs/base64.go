package funcs

import (
	"encoding/base64"
	"fmt"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

var base64DecodeFunc = function.New(&function.Spec{
	Description: "Decodes a base64 string.",
	Params:      []function.Parameter{{Name: "str", Type: cty.String}},
	Type:        function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		b, err := base64.StdEncoding.DecodeString(args[0].AsString())
		if err != nil {
			return cty.NilVal, fmt.Errorf("base64decode: %w", err)
		}
		return cty.StringVal(string(b)), nil
	},
})

var base64EncodeFunc = function.New(&function.Spec{
	Description: "Encodes a string as base64.",
	Params:      []function.Parameter{{Name: "str", Type: cty.String}},
	Type:        function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		return cty.StringVal(base64.StdEncoding.EncodeToString([]byte(args[0].AsString()))), nil
	},
})
