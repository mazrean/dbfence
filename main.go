// Command dbfence declaratively manages databases, roles, schemas and
// privileges of MySQL and PostgreSQL servers.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/mazrean/dbfence/internal/di"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() {
		// The first signal cancels ctx; restore the default handling so
		// a second Ctrl-C kills the process even if something blocks.
		<-ctx.Done()
		stop()
	}()
	code := run(ctx, os.Args[1:], di.InitializeApp(ctx), os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
