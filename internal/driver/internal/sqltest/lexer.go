// Package sqltest checks rendered SQL in the driver tests: a small lexer
// that knows only quoted identifiers and string literals, enough to tell
// whether a statement could end early, chain another one or open a
// comment outside of them.
package sqltest

import (
	"errors"
	"fmt"
)

// Syntax describes the quoting rules of an engine as the Dialects use it.
type Syntax struct {
	// IdentQuote quotes identifiers: '"' (PostgreSQL) or '`' (MySQL).
	IdentQuote byte
	// BackslashLiterals is set when a backslash escapes the next byte in
	// every string literal (MySQL without NO_BACKSLASH_ESCAPES).
	BackslashLiterals bool
	// EscapeStrings is set when E'...' literals take backslash escapes
	// (PostgreSQL).
	EscapeStrings bool
	// HashComments is set when '#' starts a comment (MySQL).
	HashComments bool
}

// PostgreSQL is the syntax of the PostgreSQL Dialect.
var PostgreSQL = Syntax{IdentQuote: '"', EscapeStrings: true}

// MySQL returns the syntax of the MySQL Dialect.
func MySQL(noBackslashEscapes bool) Syntax {
	return Syntax{IdentQuote: '`', BackslashLiterals: !noBackslashEscapes, HashComments: true}
}

// CheckSingle reports an error unless sql is exactly one statement: every
// quoted identifier and literal is closed, and outside of them there is
// no ';', no comment ("--", "/*", and '#' on MySQL), no other quote
// character, no '$' (PostgreSQL dollar quoting) and no NUL.
func CheckSingle(sql string, sx Syntax) error {
	if sql == "" {
		return errors.New("empty statement")
	}
	for i := 0; i < len(sql); {
		c := sql[i]
		next := byte(0)
		if i+1 < len(sql) {
			next = sql[i+1]
		}
		switch {
		case c == '\'':
			escapes := sx.BackslashLiterals || (sx.EscapeStrings && escapePrefix(sql, i))
			end, ok := skipQuoted(sql, i, '\'', escapes)
			if !ok {
				return fmt.Errorf("unterminated literal at byte %d", i)
			}
			i = end
			continue
		case c == sx.IdentQuote:
			end, ok := skipQuoted(sql, i, c, false)
			if !ok {
				return fmt.Errorf("unterminated identifier at byte %d", i)
			}
			i = end
			continue
		case c == ';':
			return fmt.Errorf("';' outside quotes at byte %d", i)
		case c == '-' && next == '-', c == '/' && next == '*':
			return fmt.Errorf("comment %q outside quotes at byte %d", string([]byte{c, next}), i)
		case c == '#' && sx.HashComments:
			return fmt.Errorf("comment '#' outside quotes at byte %d", i)
		case c == '"' || c == '`':
			return fmt.Errorf("stray quote %q at byte %d", c, i)
		case c == '$' && !sx.HashComments:
			return fmt.Errorf("'$' outside quotes at byte %d", i)
		case c == 0:
			return fmt.Errorf("NUL outside quotes at byte %d", i)
		}
		i++
	}
	return nil
}

// escapePrefix reports whether the literal at i is an E'...' string.
func escapePrefix(sql string, i int) bool {
	if i == 0 || (sql[i-1] != 'E' && sql[i-1] != 'e') {
		return false
	}
	return i == 1 || !isIdentByte(sql[i-2])
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || ('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || c >= 0x80
}

// skipQuoted returns the index after the quoted token starting at i. A
// doubled quote stands for itself; with backslash, a backslash escapes
// the next byte.
func skipQuoted(sql string, i int, quote byte, backslash bool) (int, bool) {
	for j := i + 1; j < len(sql); j++ {
		switch {
		case backslash && sql[j] == '\\':
			j++
		case sql[j] != quote:
		case j+1 < len(sql) && sql[j+1] == quote:
			j++
		default:
			return j + 1, true
		}
	}
	return 0, false
}
