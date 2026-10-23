package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/alecthomas/kong"
	"github.com/mazrean/dbfence/internal/app"
)

// Exit codes.
const (
	exitOK      = 0
	exitError   = 1
	exitChanges = 2
)

// errChanges signals plan --detailed-exitcode found changes.
var errChanges = errors.New("changes present")

type cli struct {
	Validate validateCmd      `cmd:"" help:"Load and validate the configuration."`
	Plan     planCmd          `cmd:"" help:"Show the SQL that apply would execute (dry run)."`
	Apply    applyCmd         `cmd:"" help:"Execute the plan."`
	Version  kong.VersionFlag `help:"Print the version and exit."`
}

type configFlags struct {
	File string `short:"f" default:"dbfence.hcl" env:"DBFENCE_FILE" help:"Configuration file or directory of *.hcl files."`
}

type diffFlags struct {
	Prune         bool `help:"Drop databases, schemas and roles that are not declared."`
	ForcePassword bool `help:"Set declared passwords even if they cannot be verified or already match."`
	ShowSecrets   bool `help:"Print passwords in SQL output instead of '<redacted>'."`
}

func (f diffFlags) options(file string) app.Options {
	return app.Options{Path: file, Prune: f.Prune, ForcePassword: f.ForcePassword, ShowSecrets: f.ShowSecrets}
}

type planCmd struct {
	configFlags
	diffFlags
	DetailedExitcode bool `help:"Exit with 2 when there are changes."`
}

func (c *planCmd) Run(ctx context.Context, a *app.App) error {
	p, err := a.Plan(ctx, c.options(c.File))
	if err != nil {
		return err
	}
	if c.DetailedExitcode && !p.Empty() {
		return errChanges
	}
	return nil
}

type applyCmd struct {
	configFlags
	diffFlags
	AutoApprove bool `help:"Skip the confirmation prompt."`
}

func (c *applyCmd) Run(ctx context.Context, a *app.App) error {
	o := c.options(c.File)
	o.AutoApprove = c.AutoApprove
	return a.Apply(ctx, o)
}

type validateCmd struct {
	configFlags
}

func (c *validateCmd) Run(ctx context.Context, a *app.App) error {
	return a.Validate(ctx, app.Options{Path: c.File})
}

// run parses args and executes the selected command.
func run(ctx context.Context, args []string, a *app.App, stdout, stderr io.Writer) int {
	exitCode := -1
	var c cli
	parser, err := kong.New(&c,
		kong.Name("dbfence"),
		kong.Description("Declarative management of databases, roles, schemas and privileges for MySQL and PostgreSQL."),
		kong.UsageOnError(),
		kong.Vars{"version": getVersion()},
		kong.Writers(stdout, stderr),
		kong.Exit(func(code int) { exitCode = code }),
		kong.BindTo(ctx, (*context.Context)(nil)),
		kong.Bind(a),
	)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}
	kctx, err := parser.Parse(args)
	if exitCode >= 0 {
		// --help or --version.
		return exitCode
	}
	if err != nil {
		parser.Errorf("%v", err)
		if exitCode < 0 {
			exitCode = exitError
		}
		return exitCode
	}
	switch err := kctx.Run(); {
	case err == nil:
		return exitOK
	case errors.Is(err, errChanges):
		return exitChanges
	default:
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}
}
