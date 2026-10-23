package plan

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Fragment is a piece of SQL text. The set of fragments is closed: SQL
// text comes only from constants (Keyword), from Dialect quoting (Ident,
// Literal), from validated words (Token), from numbers (Number) and from
// escaped secrets (Secret), so a runtime string never becomes executable
// SQL without going through the engine Dialect.
type Fragment interface {
	render(sb *strings.Builder, showSecrets bool)
}

// keyword is the unexported underlying type of Keyword.
type keyword string

// Keyword is SQL text written as a constant in the source, such as
// "CREATE ROLE " or " WITH GRANT OPTION". Untyped constants convert to it
// implicitly; the sqlfragment lint rule rejects an explicit conversion of
// anything that is not a constant. Because a decoder (json.Unmarshal,
// fmt.Sscan), a generic function or reflect can fill a Keyword from data
// without a conversion, outside this package and tests the rule also
// rejects pointers to values that contain a Keyword, generics defined
// elsewhere instantiated with such types, and imports of reflect, unsafe
// and encoding/gob.
type Keyword keyword

func (k Keyword) render(sb *strings.Builder, _ bool) { sb.WriteString(string(k)) }

// Ident is an identifier quoted by an engine Dialect.
type Ident struct{ text string }

// QuotedIdent wraps quoted, an identifier the caller has already quoted.
// Only Dialect code under internal/driver calls it (sqlfragment lint).
func QuotedIdent(quoted string) Ident { return Ident{text: quoted} }

// String returns the quoted identifier, for messages.
func (i Ident) String() string { return i.text }

func (i Ident) render(sb *strings.Builder, _ bool) { sb.WriteString(i.text) }

// Literal is a string literal escaped by an engine Dialect.
type Literal struct{ text string }

// EscapedLiteral wraps escaped, a literal the caller has already quoted
// and escaped. Only Dialect code under internal/driver calls it
// (sqlfragment lint).
func EscapedLiteral(escaped string) Literal { return Literal{text: escaped} }

func (l Literal) render(sb *strings.Builder, _ bool) { sb.WriteString(l.text) }

// Token is a validated word, such as a privilege name, an authentication
// plugin or a character set: letters, digits and underscores, words
// separated by single spaces.
type Token struct{ text string }

// NewToken returns word as a Token. The caller validates word first, for
// example against the privileges the engine knows; NewToken panics when
// word is not made of plain words, so that a value the caller failed to
// validate never reaches the SQL. Only Dialect code under internal/driver
// calls it (sqlfragment lint).
func NewToken(word string) Token {
	if !IsWords(word) {
		panic(fmt.Sprintf("plan.NewToken: %q is not a plain word", word))
	}
	return Token{text: word}
}

// IsWords reports whether s is one or more words of letters, digits and
// underscores, separated by single spaces.
func IsWords(s string) bool {
	for w := range strings.SplitSeq(s, " ") {
		if w == "" || strings.ContainsFunc(w, func(r rune) bool {
			return r != '_' && (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z')
		}) {
			return false
		}
	}
	return true
}

func (t Token) render(sb *strings.Builder, _ bool) { sb.WriteString(t.text) }

// Number is an integer, such as a connection limit.
type Number int

func (n Number) render(sb *strings.Builder, _ bool) { sb.WriteString(strconv.Itoa(int(n))) }

// Secret is an escaped literal that is redacted in output, such as a
// password.
type Secret struct{ lit Literal }

// NewSecret marks lit as a secret.
func NewSecret(lit Literal) Secret { return Secret{lit: lit} }

func (s Secret) render(sb *strings.Builder, showSecrets bool) {
	if showSecrets {
		sb.WriteString(s.lit.text)
		return
	}
	sb.WriteString("'<redacted>'")
}

// Seq is a sequence of fragments rendered one after another.
type Seq []Fragment

func (s Seq) render(sb *strings.Builder, showSecrets bool) {
	for _, f := range s {
		f.render(sb, showSecrets)
	}
}

// Join returns items separated by sep, such as a list of privileges
// separated by ", ".
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

// hasSecret reports whether f contains a Secret.
func hasSecret(f Fragment) bool {
	switch f := f.(type) {
	case Secret:
		return true
	case Seq:
		return slices.ContainsFunc(f, hasSecret)
	}
	return false
}
