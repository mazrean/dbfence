package a

import (
	"fmt"

	"github.com/mazrean/dbfence/internal/plan"
)

const create = "CREATE ROLE "

type word string

const typed word = "DROP ROLE "

type stringish interface{ ~string }

func conv[T ~string](s string) T { return T(s) }

func same[T stringish](v T) T { return v }

func pick[T comparable](a, b T) T {
	if a == b {
		return a
	}
	return b
}

func f(name string, w word, k plan.Keyword) {
	// A runtime string cannot become SQL text.
	_ = plan.SQL("", plan.Keyword(name))                    // want `plan.Keyword converts a non-constant value to SQL text`
	_ = plan.SQL("", plan.Keyword("DROP ROLE "+name))       // want `plan.Keyword converts a non-constant value to SQL text`
	_ = plan.SQL("", plan.Keyword(fmt.Sprintf("%s", name))) // want `plan.Keyword converts a non-constant value to SQL text`
	_ = plan.SQL("", plan.Keyword(w))                       // want `plan.Keyword converts a non-constant value to SQL text`
	_ = plan.SQL("", (plan.Keyword)(name))                  // want `plan.Keyword converts a non-constant value to SQL text`
	_ = plan.SQL("", plan.Keyword(string([]byte{'x'})))     // want `plan.Keyword converts a non-constant value to SQL text`
	_ = plan.SQL("", plan.QuotedIdent(`"`+name+`"`))        // want `plan.QuotedIdent may be used only by the engine Dialects`
	_ = plan.SQL("", plan.EscapedLiteral("'"+name+"'"))     // want `plan.EscapedLiteral may be used only by the engine Dialects`
	_ = plan.SQL("", plan.NewToken(name))                   // want `plan.NewToken may be used only by the engine Dialects`
	quote := plan.QuotedIdent                               // want `plan.QuotedIdent may be used only by the engine Dialects`
	_ = quote

	// Outside internal/plan any generic may fill a Keyword type argument.
	_ = plan.SQL("", conv[plan.Keyword](name)) // want `plan.Keyword instantiates a generic with a type argument that contains plan.Keyword`
	_ = same(k)                                // want `plan.Keyword instantiates a generic with a type argument that contains plan.Keyword`
	_ = pick[plan.Keyword](k, "CASCADE")       // want `plan.Keyword instantiates a generic with a type argument that contains plan.Keyword`
	_ = pick(name, "CASCADE")
	_ = plan.Join(", ", k, plan.Keyword("CASCADE"))

	// Constants, Keyword values and numbers are fine.
	_ = plan.SQL("", plan.Keyword("GRANT "), plan.Keyword(create), plan.Keyword(typed))
	_ = plan.SQL("", k, plan.Keyword(k), plan.Number(len(name)))
	_ = plan.SQL("", k+" CASCADE") // want `concatenating plan.Keyword at runtime`
}
