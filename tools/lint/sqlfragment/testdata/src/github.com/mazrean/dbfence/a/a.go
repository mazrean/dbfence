package a

import (
	"fmt"

	"github.com/mazrean/dbfence/internal/plan"
)

const create = "CREATE ROLE "

type word string

const typed word = "DROP ROLE "

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

	// Constants, Keyword values and numbers are fine.
	_ = plan.SQL("", plan.Keyword("GRANT "), plan.Keyword(create), plan.Keyword(typed))
	_ = plan.SQL("", k, plan.Keyword(k), k+" CASCADE", plan.Number(len(name)))
}
