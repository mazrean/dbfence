// Package app implements the dbfence commands.
package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mazrean/dbfence/internal/apply"
	"github.com/mazrean/dbfence/internal/auth"
	"github.com/mazrean/dbfence/internal/config"
	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/driver/mysql"
	"github.com/mazrean/dbfence/internal/driver/postgres"
	"github.com/mazrean/dbfence/internal/funcs"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
	"github.com/mazrean/dbfence/internal/policy"
)

// Driver inspects a server, renders SQL for it, and executes statements.
type Driver interface {
	diff.Dialect
	// Inspect reads the current state. Schemas and schema privileges are
	// read for the databases declared in desired that already exist.
	Inspect(ctx context.Context, desired *model.Desired) (*model.Current, error)
	// Exec runs one statement on s.Database ("" is the configured
	// connection), as s.AsRole when set; see apply.Executor.
	Exec(ctx context.Context, s plan.Statement) error
	Close() error
}

// Opener connects to a server.
type Opener interface {
	Open(ctx context.Context, conn model.Connection) (Driver, error)
}

// DefaultOpener opens the built-in drivers.
type DefaultOpener struct{}

// NewOpener returns the built-in Opener.
func NewOpener() Opener { return DefaultOpener{} }

// Open implements Opener.
func (DefaultOpener) Open(ctx context.Context, conn model.Connection) (Driver, error) {
	switch conn.Engine {
	case model.EnginePostgres:
		return postgres.Open(ctx, conn, auth.New(conn))
	case model.EngineMySQL:
		return mysql.Open(ctx, conn, auth.New(conn))
	default:
		return nil, fmt.Errorf("unsupported engine %q", conn.Engine)
	}
}

// IO holds the standard streams. Out and Err are the redacting
// secret.Writer streams of the process; an Out with a Flush method is
// flushed before the confirmation prompt is read.
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
	Dir string
	// Targets are resource addresses (user.app, database.app, ...); when
	// set, only their changes are planned (see plan.Plan.Select).
	Targets       []string
	Prune         bool
	ForcePassword bool
	ShowSecrets   bool
	AutoApprove   bool
}

// ErrAborted is returned when apply is not confirmed.
var ErrAborted = errors.New("apply cancelled")

// ErrUnsafePlan is returned when the plan fails the independent safety
// check (see policy.Verify). It means a bug in dbfence.
var ErrUnsafePlan = errors.New("internal safety check failed")

// ErrUnsafeTarget is returned when the plan passes the safety check but
// the part of it that --target selects does not.
var ErrUnsafeTarget = errors.New("the plan selected by --target fails the safety check")

// targetWarning is printed with every plan computed with --target.
const targetWarning = "--target is in effect: only the changes of the selected objects, and the creation of the objects they need, are planned, so the server may still differ from the configuration; run plan without --target to see the rest"

// Validate loads the configuration, evaluating every function.
func (a *App) Validate(_ context.Context, o Options) error {
	cfg, err := config.Load(o.Dir, a.funcs.Functions())
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(a.io.Out, "The configuration is valid (%s: %s, %s, %s, %s).\n", cfg.Connection.Engine,
		plan.Count(len(cfg.Desired.Databases), "database"), plan.Count(len(cfg.Desired.Roles), "role"),
		plan.Count(len(cfg.Desired.Schemas), "schema"), plan.Count(len(cfg.Desired.Privileges), "privilege"))
	return err
}

// Plan prints the statements apply would execute and returns the plan.
func (a *App) Plan(ctx context.Context, o Options) (*plan.Plan, error) {
	p, drv, err := a.compute(ctx, o)
	if err != nil {
		return nil, err
	}
	defer closeQuietly(drv)
	if err = a.render(p, o); err != nil {
		return nil, err
	}
	if err = p.verdict(); err != nil {
		return nil, err
	}
	return p.Plan, nil
}

// render prints the plan to stdout and its warnings to stderr as well, so
// they stay visible when stdout is redirected.
func (a *App) render(p *checkedPlan, o Options) error {
	if err := p.Render(a.io.Out, o.ShowSecrets); err != nil {
		return err
	}
	return p.WriteWarnings(a.io.Err)
}

// Apply prints the plan, asks for confirmation, and executes it.
func (a *App) Apply(ctx context.Context, o Options) error {
	p, drv, err := a.compute(ctx, o)
	if err != nil {
		return err
	}
	defer closeQuietly(drv)
	if err = a.render(p, o); err != nil {
		return err
	}
	if err = p.verdict(); err != nil {
		return err
	}
	if p.Empty() {
		return nil
	}
	if !o.AutoApprove {
		if err = a.confirm(ctx); err != nil {
			return err
		}
	}
	if err = apply.Run(ctx, drv, p.Plan, a.io.Out, o.ShowSecrets); err != nil {
		return err
	}
	_, err = fmt.Fprintf(a.io.Out, "Applied %s.\n", plan.Count(len(p.Statements()), "statement"))
	return err
}

// confirm asks for confirmation and returns nil only when the answer is
// "yes". It returns as soon as ctx is cancelled (Ctrl-C), even while the
// read is still blocked.
func (a *App) confirm(ctx context.Context) error {
	if _, err := fmt.Fprint(a.io.Out, "Apply these changes? Only 'yes' is accepted: "); err != nil {
		return err
	}
	// The prompt has no line break: a line-buffered stream (secret.Writer)
	// shows it only once flushed.
	if f, ok := a.io.Out.(interface{ Flush() error }); ok {
		if err := f.Flush(); err != nil {
			return err
		}
	}
	type answer struct {
		err  error
		line string
	}
	ch := make(chan answer, 1)
	go func() {
		line, err := bufio.NewReader(a.io.In).ReadString('\n')
		ch <- answer{line: line, err: err}
	}()
	var ans answer
	select {
	case <-ctx.Done():
		_, _ = fmt.Fprintln(a.io.Out)
		return fmt.Errorf("%w: interrupted: %w", ErrAborted, context.Cause(ctx))
	case ans = <-ch:
	}
	// Without a terminal echo (piped stdin or EOF) the cursor is still
	// on the prompt line.
	if !strings.HasSuffix(ans.line, "\n") || !isTerminal(a.io.In) {
		if _, err := fmt.Fprintln(a.io.Out); err != nil {
			return err
		}
	}
	switch {
	case ans.err != nil && !errors.Is(ans.err, io.EOF):
		return fmt.Errorf("read confirmation: %w", ans.err)
	case ans.err != nil && strings.TrimSpace(ans.line) == "":
		return fmt.Errorf("%w: no confirmation received (stdin closed); pass --auto-approve to apply non-interactively", ErrAborted)
	case strings.TrimSpace(ans.line) != "yes":
		return fmt.Errorf("%w: the answer was not \"yes\"", ErrAborted)
	}
	return nil
}

// isTerminal reports whether r is a character device, whose input the
// terminal echoes.
func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func closeQuietly(c io.Closer) { _ = c.Close() }

// checkedPlan is a plan with the result of the safety check run on it.
type checkedPlan struct {
	*plan.Plan
	violations []policy.Violation
	// selected are the violations of the plan --target selects from a
	// plan without violations.
	selected []policy.Violation
	// targeted is set when Plan is a --target selection.
	targeted bool
}

// verdict returns ErrUnsafePlan or ErrUnsafeTarget listing the
// violations, or nil.
func (p *checkedPlan) verdict() error {
	switch {
	case len(p.violations) > 0:
		msg := "(this is a bug in dbfence; please report it)"
		if p.targeted {
			msg = "(this is a bug in dbfence; please report it with the plan printed without --target)"
		}
		return fmt.Errorf("%w: %s %s", ErrUnsafePlan, violations(p.violations), msg)
	case len(p.selected) > 0:
		return fmt.Errorf("%w: %s; select more objects or run without --target", ErrUnsafeTarget, violations(p.selected))
	}
	return nil
}

func violations(vs []policy.Violation) string {
	msgs := make([]string, len(vs))
	for i, v := range vs {
		msgs[i] = v.String()
	}
	return strings.Join(msgs, "; ")
}

// compute inspects the server, diffs it against the configuration and
// runs the independent safety check on the plan.
func (a *App) compute(ctx context.Context, o Options) (*checkedPlan, Driver, error) {
	if len(o.Targets) > 0 && o.Prune {
		// Undeclared objects have no address, so nothing could be pruned.
		return nil, nil, errors.New("--prune cannot be combined with --target")
	}
	cfg, err := config.Load(o.Dir, a.funcs.Functions())
	if err != nil {
		return nil, nil, err
	}
	addrs := make([]model.Address, len(o.Targets))
	for i, t := range o.Targets {
		if addrs[i], err = cfg.Address(t); err != nil {
			return nil, nil, fmt.Errorf("--target: %w", err)
		}
	}
	drv, err := a.opener.Open(ctx, cfg.Connection)
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
	popts := policy.Options{System: drv, Prune: o.Prune}
	checked := &checkedPlan{Plan: p, violations: policy.Verify(p, cur, cfg.Desired, popts)}
	if len(addrs) > 0 {
		// The selected plan is the one executed, so it is checked too.
		checked.Plan, checked.targeted = p.Select(addrs), true
		checked.Warnings = append([]string{targetWarning}, checked.Warnings...)
		if len(checked.violations) == 0 {
			checked.selected = policy.Verify(checked.Plan, cur, cfg.Desired, popts)
		}
	}
	return checked, drv, nil
}
