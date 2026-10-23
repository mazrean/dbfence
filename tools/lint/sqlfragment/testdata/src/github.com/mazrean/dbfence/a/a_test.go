package a

import "github.com/mazrean/dbfence/internal/plan"

// Tests may build fragments, but SQL text stays constant.
func helper(name string) plan.Statement {
	return plan.SQL("", plan.Keyword(name), plan.QuotedIdent(name)) // want `plan.Keyword converts a non-constant value to SQL text`
}
