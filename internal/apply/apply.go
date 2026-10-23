// Package apply executes a plan.
package apply

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/mazrean/dbfence/internal/plan"
)

// Executor runs a single statement on a database. Errors with which the
// server refused the statement, or that occurred before it was sent, are
// marked with Rejected; any other error leaves its outcome unknown.
type Executor interface {
	Exec(ctx context.Context, database, query string) error
}

// Rejected marks err as known not to have applied its statement: the
// server answered with an error, or the statement was never sent. It
// returns nil for a nil err.
func Rejected(err error) error {
	if err == nil {
		return nil
	}
	return rejection{err}
}

type rejection struct{ error }

func (r rejection) Unwrap() error { return r.error }

func isRejected(err error) bool {
	var r rejection
	return errors.As(err, &r)
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
			// Comments explaining the statement, such as a CASCADE, go on
			// their own lines before the progress line.
			comments, stmt := splitComments(s.Display(showSecrets))
			if _, err := fmt.Fprintf(w, "%s[%d/%d] %s%s\n", comments, n, total, onDatabase(s.Database, "", " "), stmt); err != nil {
				return err
			}
			if err := ex.Exec(ctx, s.Database, s.SQL()); err != nil {
				return failure(ctx, c, s, n, total, err, showSecrets)
			}
		}
	}
	return nil
}

// failure describes the failed statement n of total. Server errors may
// quote the statement, so the error text is not wrapped, and for a
// statement with a secret it is withheld from the first quote on.
func failure(ctx context.Context, c plan.Change, s plan.Statement, n, total int, err error, showSecrets bool) error {
	at := fmt.Sprintf("statement %d/%d%s", n, total, onDatabase(s.Database, " ", ""))
	msg := err.Error()
	if s.HasSecret() && !showSecrets {
		msg = withholdQuoted(msg)
	}
	if ctx.Err() != nil || !isRejected(err) {
		// The server may still complete the statement: drivers cancel by
		// closing the connection or by sending a cancel request, and a
		// connection lost after the server committed the statement but
		// before it answered (io.EOF, a network error) hides the result.
		head := fmt.Sprintf("%s %s: interrupted during %s, whose outcome is unknown (%s confirmed applied; run plan to see the remaining changes)",
			c.Action, c.Resource, at, plan.Count(n-1, "statement"))
		switch {
		case ctx.Err() != nil && isCancellation(ctx, err):
			// The driver error only repeats the cancellation. The cause
			// names the signal, as the confirmation prompt does.
			return fmt.Errorf("%s: %w", head, context.Cause(ctx))
		case ctx.Err() != nil:
			return fmt.Errorf("%s: %s: %w", head, msg, context.Cause(ctx))
		case errors.Is(err, driver.ErrBadConn):
			return fmt.Errorf("%s: %w", head, driver.ErrBadConn)
		default:
			return fmt.Errorf("%s: %s", head, msg)
		}
	}
	return fmt.Errorf("%s %s: %s failed: %s (%d of %s applied; run plan to see the remaining changes)",
		c.Action, c.Resource, at, msg, n-1, plan.Count(total, "statement"))
}

// withheldNote ends a message whose quoted parts were withheld.
const withheldNote = " [the rest of the message is withheld because the statement contains a password; rerun with --show-secrets to see it]"

// withholdQuoted cuts each line of a server message at its first single or
// double quote. Servers quote parts of the failed statement in their
// messages (MySQL: near '...'; PostgreSQL: at or near "..."), escaped,
// unescaped or truncated in ways that matching the secret against the
// text cannot follow. Cutting at the first quote does not depend on the
// secret or its quoting, so nothing quoted can get through, while
// messages without quotes, such as password policy rejections, are kept.
func withholdQuoted(msg string) string {
	lines := strings.Split(msg, "\n")
	withheld := false
	for i, l := range lines {
		if j := strings.IndexAny(l, `'"`); j >= 0 {
			lines[i] = l[:j] + "<withheld>"
			withheld = true
		}
	}
	out := strings.Join(lines, "\n")
	if withheld {
		out += withheldNote
	}
	return out
}

// splitComments splits the leading "--" comment lines off text. comments
// keeps their line breaks.
func splitComments(text string) (comments, rest string) {
	rest = text
	for strings.HasPrefix(rest, "--") {
		line, after, ok := strings.Cut(rest, "\n")
		if !ok {
			break
		}
		comments += line + "\n"
		rest = after
	}
	return comments, rest
}

// isCancellation reports whether err only says that ctx was cancelled or
// that the connection broke, which the error already states.
func isCancellation(ctx context.Context, err error) bool {
	if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
		return true
	}
	return errors.Is(err, driver.ErrBadConn)
}

// onDatabase returns `(on database "x")` between before and after, or ""
// for the configured connection.
func onDatabase(database, before, after string) string {
	if database == "" {
		return ""
	}
	return fmt.Sprintf("%s(on database %q)%s", before, database, after)
}
