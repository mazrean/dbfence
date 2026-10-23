// Package apply executes a plan.
package apply

import (
	"context"
	"database/sql/driver"
	"errors"
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
			if _, err := fmt.Fprintf(w, "[%d/%d] %s%s\n", n, total, onDatabase(s.Database, "", " "), s.Display(showSecrets)); err != nil {
				return err
			}
			if err := ex.Exec(ctx, s.Database, s.SQL()); err != nil {
				return failure(ctx, c, s, n, total, err)
			}
		}
	}
	return nil
}

// failure describes the failed statement n of total. Server errors may
// quote the statement, so the error text is redacted and not wrapped.
func failure(ctx context.Context, c plan.Change, s plan.Statement, n, total int, err error) error {
	at := fmt.Sprintf("statement %d/%d%s", n, total, onDatabase(s.Database, " ", ""))
	msg := s.Redact(err.Error())
	if cause := ctx.Err(); cause != nil || errors.Is(err, driver.ErrBadConn) {
		// The server may still complete the statement: drivers cancel by
		// closing the connection or by sending a cancel request.
		if cause == nil {
			cause = driver.ErrBadConn
		}
		return fmt.Errorf("%s %s: interrupted during %s, whose outcome is unknown (%s confirmed applied; run plan to see the remaining changes): %s: %w",
			c.Action, c.Resource, at, plan.Count(n-1, "statement"), msg, cause)
	}
	return fmt.Errorf("%s %s: %s failed: %s (%d of %s applied; run plan to see the remaining changes)",
		c.Action, c.Resource, at, msg, n-1, plan.Count(total, "statement"))
}

// onDatabase returns `(on database "x")` between before and after, or ""
// for the configured connection.
func onDatabase(database, before, after string) string {
	if database == "" {
		return ""
	}
	return fmt.Sprintf("%s(on database %q)%s", before, database, after)
}
