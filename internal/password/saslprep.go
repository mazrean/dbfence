package password

import (
	"slices"
	"unicode/utf8"
)

// runeRange is an inclusive range of code points.
type runeRange struct{ lo, hi rune }

func inTable(table []runeRange, r rune) bool {
	_, found := slices.BinarySearchFunc(table, r, func(rr runeRange, r rune) int {
		switch {
		case rr.hi < r:
			return -1
		case rr.lo > r:
			return 1
		default:
			return 0
		}
	})
	return found
}

// saslPrep normalizes password with RFC 4013 SASLprep exactly as
// PostgreSQL's pg_saslprep (src/common/saslprep.c) does before deriving a
// SCRAM verifier. Whenever pg_saslprep rejects the input (invalid UTF-8,
// empty after mapping, prohibited or unassigned output, bidi violation),
// PostgreSQL hashes the raw password, so the raw password is returned.
func saslPrep(password string) string {
	if isASCII(password) || !utf8.ValidString(password) {
		return password
	}

	// 1) Map: non-ASCII spaces to U+0020, B.1 characters to nothing.
	mapped := make([]rune, 0, len(password))
	for _, r := range password {
		switch {
		case inTable(nonASCIISpaceRanges, r):
			mapped = append(mapped, ' ')
		case inTable(mappedToNothingRanges, r):
		default:
			mapped = append(mapped, r)
		}
	}
	if len(mapped) == 0 {
		return password
	}

	// 2) Normalize with NFKC.
	out := []rune(nfkc(string(mapped)))

	// 3) Prohibit, including code points unassigned in Unicode 3.2.
	randAL := false
	for _, r := range out {
		if inTable(prohibitedRanges, r) || inTable(unassignedRanges, r) {
			return password
		}
		randAL = randAL || inTable(randALCatRanges, r)
	}

	// 4) Bidi (RFC 3454 section 6): a string with RandALCat characters
	// must not contain LCat characters and must start and end with
	// RandALCat characters.
	if randAL {
		if !inTable(randALCatRanges, out[0]) || !inTable(randALCatRanges, out[len(out)-1]) {
			return password
		}
		for _, r := range out {
			if inTable(lCatRanges, r) {
				return password
			}
		}
	}
	return string(out)
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
