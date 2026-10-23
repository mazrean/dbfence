// Command field must not compile: an Ident cannot be filled with a runtime
// string outside the plan package.
package main

import (
	"os"

	"github.com/mazrean/dbfence/internal/plan"
)

func main() {
	_ = plan.SQL("", plan.Keyword("DROP ROLE "), plan.Ident{text: os.Args[1]})
}
