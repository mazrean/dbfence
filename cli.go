package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/alecthomas/kong"
	"github.com/mazrean/dbfence/internal/app"
	"github.com/mazrean/dbfence/internal/secret"
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

const defaultFile = "dbfence.hcl"

type configFlags struct {
	File string `short:"f" default:"dbfence.hcl" env:"DBFENCE_FILE" help:"Configuration file or directory of *.hcl files."`
}

// path returns the configuration path. An empty -f or DBFENCE_FILE falls
// back to the default, and a missing path is reported with a hint.
func (f configFlags) path() (string, error) {
	p := f.File
	if p == "" {
		p = defaultFile
	}
	if _, err := os.Stat(p); errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("configuration %q not found (set -f/--file or DBFENCE_FILE): %w", p, fs.ErrNotExist)
	}
	return p, nil
}

type diffFlags struct {
	Prune         bool `help:"Drop databases, schemas and roles that are not declared."`
	ForcePassword bool `help:"Set declared passwords even if they cannot be verified or already match."`
	ShowSecrets   bool `help:"Turn off all redaction: print passwords in SQL instead of '<redacted>', and known secrets in every message on stdout and stderr."`
}

func (f diffFlags) options(file configFlags) (app.Options, error) {
	p, err := file.path()
	if err != nil {
		return app.Options{}, err
	}
	return app.Options{Path: p, Prune: f.Prune, ForcePassword: f.ForcePassword, ShowSecrets: f.ShowSecrets}, nil
}

type planCmd struct {
	configFlags
	diffFlags
	DetailedExitcode bool `help:"Exit with 2 when there are changes. Warnings alone (unmanaged objects without --prune, passwords not compared) exit with 0."`
}

func (c *planCmd) Run(ctx context.Context, a *app.App) error {
	o, err := c.options(c.configFlags)
	if err != nil {
		return err
	}
	p, err := a.Plan(ctx, o)
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
	o, err := c.options(c.configFlags)
	if err != nil {
		return err
	}
	o.AutoApprove = c.AutoApprove
	return a.Apply(ctx, o)
}

type validateCmd struct {
	configFlags
}

func (c *validateCmd) Run(ctx context.Context, a *app.App) error {
	p, err := c.path()
	if err != nil {
		return err
	}
	return a.Validate(ctx, app.Options{Path: p})
}

// run parses args and executes the selected command. All output goes to
// stdout and stderr, the program's redacting output sink (see
// secret.Writer), which run flushes before it returns.
func run(ctx context.Context, args []string, a *app.App, stdout, stderr *secret.Writer) int {
	defer func() {
		_ = stdout.Flush()
		_ = stderr.Flush()
	}()
	exitCode := -1
	var c cli
	parser, err := kong.New(&c,
		kong.Name("dbfence"),
		kong.Description("Declarative management of databases, roles, schemas and privileges for MySQL and PostgreSQL."),
		kong.ShortUsageOnError(),
		kong.Vars{"version": getVersion()},
		kong.Writers(stdout, stderr),
		kong.Exit(func(code int) { exitCode = code }),
		kong.BindTo(ctx, (*context.Context)(nil)),
		kong.Bind(a),
	)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "dbfence: error: %v\n", err)
		return exitError
	}
	kctx, err := parser.Parse(args)
	if exitCode >= 0 {
		// --help or --version.
		return exitCode
	}
	if err != nil {
		// Print the usage hint with the error on stderr; stdout may be
		// redirected to a plan file.
		parser.Stdout = stderr
		parser.FatalIfErrorf(err)
		return exitError
	}
	// --show-secrets turns off all redaction: the SQL prints passwords and
	// the sink no longer redacts known secrets from any output.
	show := c.Plan.ShowSecrets || c.Apply.ShowSecrets
	stdout.ShowSecrets(show)
	stderr.ShowSecrets(show)
	switch err := kctx.Run(); {
	case err == nil:
		return exitOK
	case errors.Is(err, errChanges):
		return exitChanges
	default:
		// Written directly: kong's Errorf indents every line after the
		// first, which garbles multi-line HCL diagnostics. Server errors
		// and diagnostics may quote names or source text with control
		// characters, which the sink escapes.
		_, _ = fmt.Fprintf(stderr, "dbfence: error: %s\n", err)
		return exitError
	}
}
