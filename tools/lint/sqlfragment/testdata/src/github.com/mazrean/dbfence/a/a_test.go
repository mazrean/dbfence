package a

import (
	"reflect"

	"github.com/mazrean/dbfence/internal/plan"
)

// Tests may build fragments, but SQL text stays constant.
func helper(name string) plan.Statement {
	return plan.SQL("", plan.Keyword(name), plan.QuotedIdent(name)) // want `plan.Keyword converts a non-constant value to SQL text`
}

func testConv[T ~string](s string) T { return T(s) }

func testPick[T comparable](a, _ T) T { return a }

// Tests may take pointers, use reflect and instantiate generics, but a
// generic that admits string conversions and pointer conversions are
// still reported.
func helpers(name string, k plan.Keyword) {
	_ = &k
	_ = reflect.DeepEqual(k, k)
	_ = testPick(k, k)
	_ = testConv[plan.Keyword](name)  // want `plan.Keyword instantiates a type parameter that admits string conversions`
	_ = *(*plan.Keyword)(&name)       // want `conversion to \*plan.Keyword, which contains plan.Keyword`
	_ = []plan.Keyword([]plan.Keyword{k})
}
