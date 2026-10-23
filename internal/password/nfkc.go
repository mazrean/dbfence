package password

import (
	"slices"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// nfkc normalizes s to NFKC as PostgreSQL's unicode_normalize does.
//
// norm.NFKC cannot be used on its own: it produces the Stream-Safe Text
// Format (UAX #15), inserting U+034F COMBINING GRAPHEME JOINER after 30
// consecutive non-starters, which PostgreSQL does not. So the three steps
// of normalization are done here over the whole string: full compatibility
// decomposition of each code point, canonical ordering, and canonical
// composition. norm is only asked about single code points and pairs,
// which are far below the stream-safe limit.
func nfkc(s string) string {
	// Full compatibility decomposition. A single code point decomposes
	// into at most 18 code points, so norm adds no U+034F here.
	var runes []rune
	for _, r := range s {
		runes = append(runes, []rune(norm.NFKD.String(string(r)))...)
	}

	// Canonical ordering: stable sort of every run of non-starters by
	// canonical combining class.
	for i := 0; i < len(runes); {
		if ccc(runes[i]) == 0 {
			i++
			continue
		}
		j := i
		for j < len(runes) && ccc(runes[j]) != 0 {
			j++
		}
		slices.SortStableFunc(runes[i:j], func(a, b rune) int { return int(ccc(a)) - int(ccc(b)) })
		i = j
	}

	// Canonical composition: a character combines with the last starter
	// unless a character in between is a starter or has a combining class
	// not lower than its own (it is blocked).
	out := make([]rune, 0, len(runes))
	starter := -1
	for _, r := range runes {
		c := ccc(r)
		if starter >= 0 {
			adjacent := starter == len(out)-1
			last := ccc(out[len(out)-1])
			if adjacent || (last != 0 && last < c) {
				if comp, ok := compose(out[starter], r); ok {
					out[starter] = comp
					continue
				}
			}
		}
		if c == 0 {
			starter = len(out)
		}
		out = append(out, r)
	}
	return string(out)
}

func ccc(r rune) uint8 {
	return norm.NFC.PropertiesString(string(r)).CCC()
}

// compose returns the primary composite of the pair a, b, if any.
func compose(a, b rune) (rune, bool) {
	s := norm.NFC.String(string([]rune{a, b}))
	r, size := utf8.DecodeRuneInString(s)
	if size != len(s) {
		return 0, false
	}
	return r, true
}
