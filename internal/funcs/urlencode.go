package funcs

import (
	"net/url"
	"strings"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// urlencodeFunc percent-encodes a string so it can be embedded in any URL
// component, including the userinfo of a DSN. It is url.QueryEscape with
// spaces as "%20" rather than "+", because "+" is literal outside a query.
var urlencodeFunc = function.New(&function.Spec{
	Description: "Percent-encodes a string for use in a URL, including the user and password parts.",
	Params:      []function.Parameter{{Name: "str", Type: cty.String}},
	Type:        function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		return cty.StringVal(urlencode(args[0].AsString())), nil
	},
})

func urlencode(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}
