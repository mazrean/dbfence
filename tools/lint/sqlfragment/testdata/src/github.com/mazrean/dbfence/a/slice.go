package a

import (
	"strings"

	"github.com/mazrean/dbfence/internal/plan"
)

// alphabet is a constant Keyword holding every printable ASCII byte.
const alphabet plan.Keyword = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"

// joined is a constant expression, which stays allowed.
const joined = alphabet + "x" + plan.Keyword("y")

// fromRuntime rebuilds s as a Keyword from slices of the constant.
func fromRuntime(s string) plan.Keyword {
	var out plan.Keyword
	for i := range len(s) {
		j := strings.IndexByte(string(alphabet), s[i])
		out += alphabet[j : j+1] // want `concatenating plan.Keyword at runtime` `slicing plan.Keyword cuts SQL text`
	}
	return out
}

func pieces(k, k2 plan.Keyword, ks []plan.Keyword, m map[bool]plan.Keyword, on bool) {
	_ = plan.SQL("", fromRuntime("x"))
	_ = k + k2          // want `concatenating plan.Keyword at runtime`
	_ = k + " "         // want `concatenating plan.Keyword at runtime`
	_ = alphabet[1:]    // want `slicing plan.Keyword cuts SQL text`
	_ = alphabet[:3][0] // want `indexing plan.Keyword takes SQL text apart` `slicing plan.Keyword cuts SQL text`
	_ = k[0]            // want `indexing plan.Keyword takes SQL text apart`

	// Whole constants picked at runtime and kept as separate fragments
	// are fine.
	_ = joined
	_ = ks[0]
	_ = ks[1:]
	_ = m[on]
	_ = plan.Seq{k, plan.Keyword(" "), k2}
	s := "a"
	s += "b"
	_ = s[1:] + s
}
