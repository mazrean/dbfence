// Package app implements the dbfence commands.
package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/mazrean/dbfence/internal/apply"
	"github.com/mazrean/dbfence/internal/config"
	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/driver/mysql"
	"github.com/mazrean/dbfence/internal/driver/postgres"
	"github.com/mazrean/dbfence/internal/funcs"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
)

// Driver inspects a server, renders SQL for it, and executes statements.
type Driver interface {
	diff.Dialect
	// Inspect reads the current state. Schemas and schema privileges are
	// read for the databases declared in desired that already exist.
	Inspect(ctx context.Context, desired *model.Desired) (*model.Current, error)
	// Exec runs query on database ("" is the configured connection).
	Exec(ctx context.Context, database, query string) error
	Close() error
}

// Opener connects to a server.
type Opener interface {
	Open(ctx context.Context, engine model.Engine, dsn string) (Driver, error)
}

// DefaultOpener opens the built-in drivers.
type DefaultOpener struct{}

// NewOpener returns the built-in Opener.
func NewOpener() Opener { return DefaultOpener{} }

// Open implements Opener.
func (DefaultOpener) Open(ctx context.Context, engine model.Engine, dsn string) (Driver, error) {
	switch engine {
	case model.EnginePostgres:
		return postgres.Open(ctx, dsn)
	case model.EngineMySQL:
		return mysql.Open(ctx, dsn)
	default:
		return nil, fmt.Errorf("unsupported engine %q", engine)
	}
}

// IO holds the standard streams.
type IO struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
}

// App runs commands.
type App struct {
	funcs  *funcs.Registry
	opener Opener
	io     *IO
}

// New returns an App.
func New(fr *funcs.Registry, opener Opener, streams *IO) *App {
	return &App{funcs: fr, opener: opener, io: streams}
}

// Options are command line options.
type Options struct {
	Path          string
	Prune         bool
	ForcePassword bool
	ShowSecrets   bool
	AutoApprove   bool
}

// ErrAborted is returned when apply is not confirmed.
var ErrAborted = errors.New("apply aborted")

// Validate loads the configuration, evaluating every function.
func (a *App) Validate(_ context.Context, o Options) error {
	cfg, err := config.Load(o.Path, a.funcs.Functions())
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(a.io.Out, "The configuration is valid (%s: %d databases, %d roles, %d schemas, %d privileges).\n",
		cfg.Engine, len(cfg.Desired.Databases), len(cfg.Desired.Roles), len(cfg.Desired.Schemas), len(cfg.Desired.Privileges))
	return err
}

// Plan prints the statements apply would execute and returns the plan.
func (a *App) Plan(ctx context.Context, o Options) (*plan.Plan, error) {
	p, drv, err := a.compute(ctx, o)
	if err != nil {
		return nil, err
	}
	defer closeQuietly(drv)
	return p, p.Render(a.io.Out, o.ShowSecrets)
}

// Apply prints the plan, asks for confirmation, and executes it.
func (a *App) Apply(ctx context.Context, o Options) error {
	p, drv, err := a.compute(ctx, o)
	if err != nil {
		return err
	}
	defer closeQuietly(drv)
	if err = p.Render(a.io.Out, o.ShowSecrets); err != nil {
		return err
	}
	if p.Empty() {
		return nil
	}
	if !o.AutoApprove {
		if _, err = fmt.Fprint(a.io.Out, "Apply these changes? Only 'yes' is accepted: "); err != nil {
			return err
		}
		line, readErr := bufio.NewReader(a.io.In).ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if strings.TrimSpace(line) != "yes" {
			return ErrAborted
		}
	}
	if err = apply.Run(ctx, drv, p, a.io.Out, o.ShowSecrets); err != nil {
		return err
	}
	_, err = fmt.Fprintf(a.io.Out, "Applied %d statements.\n", len(p.Statements()))
	return err
}

func closeQuietly(c io.Closer) { _ = c.Close() }

func (a *App) compute(ctx context.Context, o Options) (*plan.Plan, Driver, error) {
	cfg, err := config.Load(o.Path, a.funcs.Functions())
	if err != nil {
		return nil, nil, err
	}
	drv, err := a.opener.Open(ctx, cfg.Engine, cfg.DSN)
	if err != nil {
		return nil, nil, err
	}
	cur, err := drv.Inspect(ctx, cfg.Desired)
	if err != nil {
		_ = drv.Close()
		return nil, nil, fmt.Errorf("inspect: %w", err)
	}
	p, err := diff.Compute(cfg.Desired, cur, drv, diff.Options{Prune: o.Prune, ForcePassword: o.ForcePassword})
	if err != nil {
		_ = drv.Close()
		return nil, nil, err
	}
	return p, drv, nil
}
