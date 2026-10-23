//go:generate go tool kessoku $GOFILE

// Package di wires the dbfence application with kessoku.
//
// It is the only place that touches the process output streams: all
// output goes through the secret.Writer streams of Output, which escape
// control characters and redact registered secrets.
package di

import (
	"context"
	"os"

	"github.com/mazrean/dbfence/internal/app"
	"github.com/mazrean/dbfence/internal/funcs"
	"github.com/mazrean/dbfence/internal/secret"
	"github.com/mazrean/kessoku"
)

// NewFuncRegistry returns the HCL function registry backed by real clients.
func NewFuncRegistry(ctx context.Context) *funcs.Registry {
	return funcs.NewRegistry(ctx)
}

// Output is the program's output sink: standard output and standard
// error, redacting the secrets of secret.Default.
type Output struct {
	Out *secret.Writer
	Err *secret.Writer
}

// NewOutput wraps the process standard output and error.
func NewOutput() *Output {
	return &Output{
		Out: secret.NewWriter(os.Stdout, secret.Default()),
		Err: secret.NewWriter(os.Stderr, secret.Default()),
	}
}

// NewIO returns the standard input and the streams of o.
func NewIO(o *Output) *app.IO {
	return &app.IO{In: os.Stdin, Out: o.Out, Err: o.Err}
}

// Program is the application with its output sink.
type Program struct {
	App    *app.App
	Output *Output
}

// NewProgram returns a Program.
func NewProgram(a *app.App, o *Output) *Program {
	return &Program{App: a, Output: o}
}

var _ = kessoku.Inject[*Program](
	"InitializeProgram",
	kessoku.Async(kessoku.Provide(NewFuncRegistry)),
	kessoku.Provide(app.NewOpener),
	kessoku.Provide(NewOutput),
	kessoku.Provide(NewIO),
	kessoku.Provide(app.New),
	kessoku.Provide(NewProgram),
)
