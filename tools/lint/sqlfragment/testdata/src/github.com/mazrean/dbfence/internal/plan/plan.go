// Package plan is a stub of internal/plan with the fragment API the
// analyzer checks.
package plan

type Fragment interface{ render() }

type keyword string

type Keyword keyword

func (Keyword) render() {}

type Ident struct{ text string }

func (Ident) render() {}

func QuotedIdent(quoted string) Ident { return Ident{text: quoted} }

type Literal struct{ text string }

func (Literal) render() {}

func EscapedLiteral(escaped string) Literal { return Literal{text: escaped} }

type Token struct{ text string }

func (Token) render() {}

func NewToken(word string) Token { return Token{text: word} }

type Number int

func (Number) render() {}

type Statement struct{ parts []Fragment }

func SQL(_ string, parts ...Fragment) Statement { return Statement{parts: parts} }

// The plan package itself may use the constructors, but SQL text stays
// constant there too.
func internalUse(s string) (Keyword, Ident) {
	return Keyword(s), QuotedIdent(s) // want `plan.Keyword converts a non-constant value to SQL text`
}
