// Command string must not compile: a runtime string is not a Fragment.
package main

import (
	"os"

	"github.com/mazrean/dbfence/internal/plan"
)

func main() {
	_ = plan.SQL("", plan.Keyword("DROP ROLE "), os.Args[1])
}
