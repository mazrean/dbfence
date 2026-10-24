package password

import (
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"
)

func TestSASLPrep(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, want string
	}{
		{"ascii unchanged", "Pa ss\x01word", "Pa ss\x01word"},
		{"nfc already", "p\u00E4ssw\u00F6rd", "p\u00E4ssw\u00F6rd"},
		{"decomposed composes", "a\u0308", "\u00E4"},
		{"ligature", "\uFB01x", "fix"},
		{"fullwidth", "\uFF21\uFF22\uFF23", "ABC"},
		{"roman numeral", "\u2168", "IX"},
		{"halfwidth katakana", "\uFF71\uFF72\uFF73123", "\u30A2\u30A4\u30A6123"},
		{"circled digit", "\u2460pw", "1pw"},
		{"soft hyphen mapped to nothing", "a\u00ADb", "ab"},
		{"zero width space is a C.1.2 space", "a\u200Bb", "a b"},
		{"nbsp to space", "a\u00A0b", "a b"},
		{"ideographic space to space", "a\u3000b", "a b"},
		{"empty after mapping keeps raw", "\u00AD", "\u00AD"},
		{"prohibited control keeps raw", "\u00E9\u0001", "\u00E9\u0001"},
		{"private use keeps raw", "\u00E9\uE000", "\u00E9\uE000"},
		{"unassigned in Unicode 3.2 keeps raw", "\U0001F511\u00A0x", "\U0001F511\u00A0x"},
		{"bidi trailing digit keeps raw", "\u05D01", "\u05D01"},
		{"bidi mixed with LCat keeps raw", "a\u05D0", "a\u05D0"},
		{"bidi valid", "\u05D01\u05D1", "\u05D01\u05D1"},
		{"invalid utf-8 keeps raw", "\xffa\u00AD", "\xffa\u00AD"},
		{"long combining run gets no U+034F", "a" + strings.Repeat("\u0301", 40), "\u00E1" + strings.Repeat("\u0301", 39)},
		{"canonical reordering across a long run", "a" + strings.Repeat("\u0301\u0316", 20), "\u00E1" + strings.Repeat("\u0316", 20) + strings.Repeat("\u0301", 19)},
		{"reorder then compose", "e\u0301\u0327", "\u0229\u0301"},
		{"hangul jamo compose", "\u1100\u1161\u11A8", "\uAC01"},
		// pg_saslprep checks the mapped input, not the NFKC output.
		{"unassigned before NFKC keeps raw", "a\u1D2C", "a\u1D2C"},
		{"unassigned before NFKC alone keeps raw", "\u03F9", "\u03F9"},
		{"C.8 before NFKC keeps raw", "a\u0340", "a\u0340"},
		{"C.8 tone mark before NFKC keeps raw", "e\u0341", "e\u0341"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := saslPrep(tt.in); got != tt.want {
				t.Errorf("saslPrep(%+q) = %+q, want %+q", tt.in, got, tt.want)
			}
		})
	}
}

// TestMatchPostgresServerVerifiers checks verifiers created by PostgreSQL 17
// with CREATE ROLE ... PASSWORD under password_encryption = scram-sha-256.
func TestMatchPostgresServerVerifiers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, password, verifier string
	}{
		{"kata", "\uFF71\uFF72\uFF73123", "SCRAM-SHA-256$4096:5aSHF4LSqxz/98kL3VMDkg==$G+/GLNYBodOF1ZQcR7pnwvsO8O9HQujzdsp2k+FLcOE=:NmF5K1PZra4Maf466O89Ny2MPEg+N4bN0dH8ywAaVbA="},
		{"fi", "\uFB01le", "SCRAM-SHA-256$4096:XHreGxDow7BYkl1AA8OG/g==$/XbgJyP5gTtvc8OXZrWClPtSN1LhfRjnA1I0fstPB4A=:Diplev/Nbxv7yBmn92NMYOjm4sHV7ain/GDcSFRXHx4="},
		{"shy", "a\u00ADb", "SCRAM-SHA-256$4096:Loll53Jchp+J0rzDSebFjQ==$IYxbnxiiZ5b9SijgxLzMk9vmJEjQsROqcEasCNLnMrQ=:15BNbItWg688MYcZdfpk5jcIbJetu4IGdVJX2OwT2Jc="},
		{"zwsp", "a\u200Bb", "SCRAM-SHA-256$4096:eCV4x7Sl8+tktkBrt3zHDA==$wim3BsxYQH2cnUGdvQOy4VT2VFNvm/rHoHely799aOM=:QdoM3KvpJIKHTQqaa/9haMfStvC8NpSFYdVR18LAr9s="},
		{"circ", "\u2460pw", "SCRAM-SHA-256$4096:ceRC/9lN5sMCjQLa/f34kA==$gFft+fk59AB7YDABLHZa6KuEKl/yXWBhs86XOZBhjmA=:KjdQX0XBdAb1iKF3ivt0FIK8PX3isoI7S6K95IdYKIc="},
		{"emoji_nbsp", "\U0001F511\u00A0x", "SCRAM-SHA-256$4096:onEL36mzItF7RVEAXWwj7A==$ek9ZowcGVCdWiAIqM4/rGOOU7GwUcG/eNpmLOuFudRg=:OyXAr6iUv3jXP/fOm/cN/ln4wra3e5rMZNVZXGs/XiE="},
		{"nbsp", "a\u00A0b", "SCRAM-SHA-256$4096:Or9CsEUqiKY6Elqau1f30A==$caAHmWIq/204jj88MBHAob57VvZNrPxoW9OGbKtNpaI=:0Nx/T5z26to1FhJ2LI2qFZ1ydxlC1+O3XEtFHMCvlLE="},
		{"lone_shy", "\u00AD", "SCRAM-SHA-256$4096:XDK1jlVRAzUJ/aJZoUeOPA==$Fe/5WuGp6RxBCcZtwEQcCXIRL6zhSX1Iy6hBUVdba2o=:pRunnR4nJ0NUfjU85CJ9KZeNHHbbgxUvwcaQaPINUi8="},
		{"bidi_bad", "\u05D01", "SCRAM-SHA-256$4096:CB2GqgRLYNB3l7icL7Q87Q==$eymh5cGbFwXtUigQa3Ahi/TyxmE4OOSvoqnF+8Xc1kA=:hbnsUWUzomqor+baiHYpWvoLq2h1nwgDdMittanBb84="},
		{"bidi_ok", "\u05D01\u05D1", "SCRAM-SHA-256$4096:EmP3fKGR22NZ66E2sQ7DUA==$k275YJsgKFNbWt0Hr8m/1N0ZeEvabI7XeVCar1vt/QY=:s7itZlIC1jHTEjmSjESIrN1P7YQm4m8Qc4vsn45OZ5Y="},
		{"fullwidth", "\uFF21\uFF22\uFF23", "SCRAM-SHA-256$4096:hVrMMCRfbsmjKeiJO5B7cA==$bVbgkf3p1OpovgfV8hRTE0GymDA+Ha8HXo/RB0QIogU=:ViLbPN9ZenbZHybk4BJ5LLpa0nQYA/oONvEnDxw8WrA="},
		{"roman", "\u2168", "SCRAM-SHA-256$4096:syoxXzlY05PRy7eabcSdGA==$rcxBFk6Mc1ak6XIJSyIO7SCWcQiVXBxU7Nx2g8+wGog=:O+g+wBbZy2v84fjVa8SlpYrX+9/S2o5C/2HzsYoFCEI="},
		{"ctrl", "\u00E9\u0001", "SCRAM-SHA-256$4096:hcjjL7EPlZqlpLfPkzUD2g==$P/0zh7trrPjUWhEHGYK7Fbsw1rYExgZY3Gl6hi+lq/w=:dIMFBRODqnhBhUOK+j0xMo47nw5Lefa/x5wD2z0iU2k="},
		{"umlaut", "p\u00E4ssw\u00F6rd", "SCRAM-SHA-256$4096:A77UJjay2pYkKZix8Cc2VQ==$k/+52ZjJdKgbNNSzbQtmA86CHwHYABzdi1NoLOqT1h0=:PblBvtLw/I6+dGiZP36D06Jfw1IzDp2W7rge0Idoe+o="},
		{"decomp", "a\u0308", "SCRAM-SHA-256$4096:OBsz/yNbK8m0ineXyRY7Uw==$5/nsSxPbpMNANNQNkwr4I1LWHp07+DOwqC4zTJ/QBHI=:b+oL/C8imkfdclgObF/FDFczTr3kqiAIbu9JzELVb4o="},
		{"emoji", "\U0001F511key", "SCRAM-SHA-256$4096:BmBKZ5iEuD5NrmOIN5gmgQ==$vLh4S/4O5fRLiGgWt/z70Qs6m0MGlK/0y2okEzmNlOo=:sSOBsH4MnCoql3TbxVFKv0ogHumHdf+x0H5x7+TZr1I="},
		// More than 30 non-starters: norm.NFKC alone would insert U+034F
		// (Stream-Safe Text Format), which PostgreSQL does not.
		{"acc40", "a" + strings.Repeat("\u0301", 40), "SCRAM-SHA-256$4096:TqFE0Epp6fXh8ahKeDVFZA==$nct34nWxnteHZsBkxOpXtmHXMVzjxEosNqgK/Kgrs24=:a/6njZqckm3gWh9dgNuFTeSU9r8TNOci2/3f+BVSIK0="},
		{"mixed40", "a" + strings.Repeat("\u0301\u0316", 20), "SCRAM-SHA-256$4096:BPaSPyKZ2GTLmYPmMQ2R9Q==$3rbEKHD7ywDq6JgRkPHjGQrhwQWdfsu/lHnL2bQuCC4=:6U39es5XCQY4hzR7B019jE9QCE41kYKJxvBjMFU7fwQ="},
		{"hangul", "\u1100\u1161\u11A8", "SCRAM-SHA-256$4096:JMdH/6MxjJIv/+x36kVt3Q==$pNgt9eukUgud4efBaf2v246O1vtT0+YR1wzY9HjYSw0=:hdtm5Rzuly0Xov9Rj2r13t7+pNEAy1ePSaHJvuzC1ds="},
		{"reorder", "e\u0301\u0327", "SCRAM-SHA-256$4096:fxCDyUYYrPp0Q5wNl1clyg==$PHezyXpmR2lgB2ZPzgB6CKipKee4A7MEiwd7JJP9Gtg=:gOztu6D+fMGq6h1M7hJMe6f/Y2WB5MBoo8I7QqJzYQk="},
		{"mixed_l_r", "a\u05D0", "SCRAM-SHA-256$4096:SKGVGQDfOU9F0br6i2vizQ==$EBbBNUov+zzu7uROEBinp60Tif+J8o9Bk4AN+q9pNjI=:XozYz262PIkwJ2Px2XYtLM7n+4w9lJzjccqZD8etxBo="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ok, err := MatchPostgres(tt.verifier, tt.name, tt.password)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Errorf("MatchPostgres(%+q) = false, want true", tt.password)
			}
		})
	}
}

// TestMatchPostgresChecksMappedInput builds a verifier from the NFKC form
// of a password that pg_saslprep rejects before normalizing. PostgreSQL
// hashes the raw password, so the NFKC form must not match it.
func TestMatchPostgresChecksMappedInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, stored, declared string
	}{
		{"unassigned modifier letter", "aA", "a\u1D2C"},
		{"unassigned lunate sigma", "\u03A3", "\u03F9"},
		{"C.8 grave tone mark", "a\u0300", "a\u0340"},
	}
	salt := []byte("0123456789abcdef")
	enc := base64.StdEncoding.EncodeToString
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			key, err := SCRAMStoredKey(tt.stored, salt, 4096)
			if err != nil {
				t.Fatal(err)
			}
			verifier := "SCRAM-SHA-256$4096:" + enc(salt) + "$" + enc(key) + ":" + enc(make([]byte, 32))
			ok, err := MatchPostgres(verifier, "u", tt.declared)
			if err != nil {
				t.Fatal(err)
			}
			if ok {
				t.Errorf("MatchPostgres(verifier of %+q, %+q) = true, want false", tt.stored, tt.declared)
			}
		})
	}
}

// TestNFKCMatchesNorm checks nfkc against norm.NFKC on strings short
// enough that the stream-safe format does not apply.
func TestNFKCMatchesNorm(t *testing.T) {
	t.Parallel()
	pieces := []string{
		"a", "e", "A", "́", "̧", "̖", "̈", "ͅ", "ְ", "ᄀ", "ᅡ", "ᆨ",
		"가", "Å", "Å", "ﬁ", "Ⅸ", "ｶﾞ", "ཱི", "̈́", "ẛ̣", "゙",
	}
	for i := range 20000 {
		var sb strings.Builder
		n := 1 + i%9
		for j := range n {
			sb.WriteString(pieces[(i*7+j*13+i/len(pieces)*j)%len(pieces)])
		}
		in := sb.String()
		if got, want := nfkc(in), norm.NFKC.String(in); got != want {
			t.Fatalf("nfkc(%+q) = %+q, want %+q", in, got, want)
		}
	}
}
