// Command secret must not compile: a Secret holds an escaped Literal, not
// a raw string.
package main

import (
	"os"

	"github.com/mazrean/dbfence/internal/plan"
)

func main() {
	_ = plan.SQL("", plan.Keyword("ALTER ROLE r PASSWORD "), plan.NewSecret(os.Args[1]))
}
