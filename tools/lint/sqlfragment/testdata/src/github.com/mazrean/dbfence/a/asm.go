package a

import "github.com/mazrean/dbfence/internal/plan"

// asmConv is implemented in asm.s; its body is not Go code the analyzer can
// check.
func asmConv(s string) plan.Keyword // want `function asmConv has no Go body`

// asmFill writes to a package variable from assembly; its signature does
// not mention plan.Keyword.
func asmFill(s string) // want `function asmFill has no Go body`

var asmFilled plan.Keyword

func asm(s string) plan.Statement {
	asmFill(s)
	_ = plan.SQL("", asmFilled)
	return plan.SQL("", asmConv(s))
}
