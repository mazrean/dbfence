// Package x stands for an engine Dialect, which may build fragments from
// values it has quoted, escaped or validated.
package x

import (
	"strings"

	"github.com/mazrean/dbfence/internal/plan"
)

func Ident(s string) plan.Ident {
	return plan.QuotedIdent(`"` + strings.ReplaceAll(s, `"`, `""`) + `"`)
}

func Literal(s string) plan.Literal {
	return plan.EscapedLiteral("'" + strings.ReplaceAll(s, "'", "''") + "'")
}

func Token(s string) plan.Token { return plan.NewToken(s) }

func Drop(name string) plan.Statement {
	// Even a Dialect cannot turn a runtime string into SQL text.
	_ = plan.Keyword(name) // want `plan.Keyword converts a non-constant value to SQL text`
	return plan.SQL("", plan.Keyword("DROP ROLE "), Ident(name))
}
