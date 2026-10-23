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

type Seq []Fragment

func (Seq) render() {}

// Join is a generic of the plan package, which other packages may
// instantiate with Keyword.
func Join[F Fragment](sep Keyword, items ...F) Seq {
	var out Seq
	for i, f := range items {
		if i > 0 {
			out = append(out, sep)
		}
		out = append(out, f)
	}
	return out
}

// The plan package may use pointers to Keyword and reflect, but a
// pointer conversion is still a conversion.
func pointers(s string) *Keyword {
	k := Keyword("x")
	_ = &k
	return (*Keyword)(&s) // want `conversion to \*Keyword, which contains plan.Keyword`
}

// The plan package itself may use the constructors, but SQL text stays
// constant there too.
func internalUse(s string) (Keyword, Ident) {
	return Keyword(s), QuotedIdent(s) // want `plan.Keyword converts a non-constant value to SQL text`
}
