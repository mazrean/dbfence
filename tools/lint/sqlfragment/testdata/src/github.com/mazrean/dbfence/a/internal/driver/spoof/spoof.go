// Package spoof has an internal/driver segment in its path without being
// under github.com/mazrean/dbfence/internal/driver/.
package spoof

import "github.com/mazrean/dbfence/internal/plan"

func Drop(name string) plan.Statement {
	return plan.SQL("", plan.Keyword("DROP ROLE "), plan.QuotedIdent(name)) // want `plan.QuotedIdent may be used only by the engine Dialects`
}
