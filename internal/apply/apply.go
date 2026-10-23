// Package apply executes a plan.
package apply

import (
	"context"
	"fmt"
	"io"

	"github.com/mazrean/dbfence/internal/plan"
)

// Executor runs a single statement on a database.
type Executor interface {
	Exec(ctx context.Context, database, query string) error
}

// Run executes every statement in order, stopping at the first error.
// Statements are not wrapped in a transaction because CREATE DATABASE
// and similar commands cannot run inside one.
func Run(ctx context.Context, ex Executor, p *plan.Plan, w io.Writer, showSecrets bool) error {
	total := len(p.Statements())
	n := 0
	for _, c := range p.Changes {
		for _, s := range c.Statements {
			n++
			if _, err := fmt.Fprintf(w, "[%d/%d] %s\n", n, total, s.Display(showSecrets)); err != nil {
				return err
			}
			if err := ex.Exec(ctx, s.Database, s.SQL()); err != nil {
				// Server errors may quote the statement; never let them carry secrets.
				return fmt.Errorf("%s %s: %s (%d of %d statements applied)", c.Action, c.Resource, s.Redact(err.Error()), n-1, total)
			}
		}
	}
	return nil
}
