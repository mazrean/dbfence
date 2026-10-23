//go:generate go tool kessoku $GOFILE

// Package di wires the dbfence application with kessoku.
package di

import (
	"context"
	"os"

	"github.com/mazrean/dbfence/internal/app"
	"github.com/mazrean/dbfence/internal/funcs"
	"github.com/mazrean/kessoku"
)

// NewFuncRegistry returns the HCL function registry backed by real clients.
func NewFuncRegistry(ctx context.Context) *funcs.Registry {
	return funcs.NewRegistry(ctx)
}

// NewIO returns the process standard streams.
func NewIO() *app.IO {
	return &app.IO{In: os.Stdin, Out: os.Stdout, Err: os.Stderr}
}

var _ = kessoku.Inject[*app.App](
	"InitializeApp",
	kessoku.Async(kessoku.Provide(NewFuncRegistry)),
	kessoku.Provide(app.NewOpener),
	kessoku.Provide(NewIO),
	kessoku.Provide(app.New),
)
