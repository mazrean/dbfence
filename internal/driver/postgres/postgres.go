// Package postgres implements the dbfence driver for PostgreSQL.
package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/mazrean/dbfence/internal/apply"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/password"
	"github.com/mazrean/dbfence/internal/plan"
	"github.com/mazrean/dbfence/internal/secret"
)

// sqlstateInsufficientPrivilege is returned when pg_authid is not readable.
const sqlstateInsufficientPrivilege = "42501"

// Driver is a PostgreSQL driver. Statements on other databases use a
// separate connection with the database name replaced.
type Driver struct {
	Dialect
	cfg   *pgx.ConnConfig
	db    *sql.DB
	conns map[string]*sql.DB
	// st is the state captured by the last Inspect. Driver methods that
	// override Dialect use it to render grantor-aware statements.
	st      *state
	notices noticeLog
	mu      sync.Mutex
}

// defaultConnectTimeout bounds connection attempts when the DSN does not
// set connect_timeout.
const defaultConnectTimeout = 10 * time.Second

// Open connects to dsn.
func Open(ctx context.Context, dsn string) (*Driver, error) {
	cfg, err := parseConfig(dsn)
	if err != nil {
		return nil, err
	}
	d := &Driver{cfg: cfg, conns: map[string]*sql.DB{}}
	// Per-database connections copy the handler.
	cfg.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) { d.notices.add(n) }
	d.db = stdlib.OpenDB(*cfg)
	if err = d.db.PingContext(ctx); err != nil {
		_ = d.db.Close()
		return nil, fmt.Errorf("connect to postgres: %w", dedupLines(err))
	}
	if err = d.db.QueryRowContext(ctx, "SELECT current_setting('password_encryption')").Scan(&d.PasswordEncryption); err != nil {
		_ = d.db.Close()
		return nil, fmt.Errorf("read password_encryption: %w", err)
	}
	return d, nil
}

// dedupLinesError drops repeated timeouts from the text of a connect
// error. pgx lists one line per attempt, and with sslmode=prefer the TLS
// and plain attempts to a host share one connect_timeout: once the first
// times out, the second fails at once with the same timeout.
type dedupLinesError struct{ err error }

func (e *dedupLinesError) Error() string {
	const timeout = "context deadline exceeded"
	var out, timedOut []string
	for l := range strings.SplitSeq(e.err.Error(), "\n") {
		host, _, _ := strings.Cut(l, "): ")
		switch {
		case slices.Contains(out, l):
			continue
		case strings.HasSuffix(l, timeout) && slices.Contains(timedOut, host):
			continue
		case strings.HasSuffix(l, timeout):
			timedOut = append(timedOut, host)
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func (e *dedupLinesError) Unwrap() error { return e.err }

func dedupLines(err error) error {
	if !strings.Contains(err.Error(), "\n") {
		return err
	}
	return &dedupLinesError{err: err}
}

// noticeLog collects the server notices of the running statement.
type noticeLog struct {
	list []*pgconn.Notice
	mu   sync.Mutex
}

func (l *noticeLog) add(n *pgconn.Notice) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.list = append(l.list, n)
}

func (l *noticeLog) take() []*pgconn.Notice {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.list
	l.list = nil
	return out
}

// noEffectWarnings are the SQLSTATEs of warnings PostgreSQL returns when a
// GRANT or REVOKE did nothing (warning, privilege_not_granted,
// privilege_not_revoked). Ignoring them makes a plan that never converges
// look applied.
var noEffectWarnings = []string{"01000", "01007", "01006"}

// noticeError returns an error for the first warning saying that the
// statement had no effect.
func noticeError(notices []*pgconn.Notice) error {
	for _, n := range notices {
		if n.SeverityUnlocalized == "WARNING" && slices.Contains(noEffectWarnings, n.Code) {
			return fmt.Errorf("statement did not take full effect: %w", withDetail((*pgconn.PgError)(n)))
		}
	}
	return nil
}

// parseConfig parses dsn and applies the session settings dbfence relies
// on. Per-database connections copy the result.
func parseConfig(dsn string) (*pgx.ConnConfig, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, parseError(err)
	}
	// Output redacts the password wherever it appears.
	secret.Register(cfg.Password)
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = defaultConnectTimeout
	}
	// Literals are rendered for standard_conforming_strings = on; a startup
	// parameter overrides role and database defaults.
	cfg.RuntimeParams["standard_conforming_strings"] = "on"
	// Quoting assumes UTF-8: in a client encoding such as SJIS or BIG5 a
	// quote or backslash byte can be the second byte of a multibyte
	// character. Pinning it also keeps a DSN, role or database default
	// from changing it.
	cfg.RuntimeParams["client_encoding"] = "UTF8"
	return cfg, nil
}

// parseError describes a DSN parse failure without the DSN, which may
// contain a password that pgx cannot reliably mask.
func parseError(err error) error {
	const prefix = "parse postgres dsn: invalid connection string"
	var pce *pgconn.ParseConfigError
	if !errors.As(err, &pce) {
		return errors.New(prefix)
	}
	// Error renders "cannot parse `<dsn>`: <msg>[ (<cause>)]"; with the DSN
	// blanked only the static message and the cause remain.
	bare := *pce
	bare.ConnString = ""
	msg := strings.TrimPrefix(bare.Error(), "cannot parse ``: ")
	cause := errors.Unwrap(pce)
	if cause != nil {
		msg = strings.TrimSuffix(msg, " ("+cause.Error()+")")
	}
	// URL errors quote the whole URL; only their inner error is safe.
	// Other causes (keyword/value parsing) may quote parts of the input.
	if urlErr := (*url.Error)(nil); errors.As(cause, &urlErr) {
		msg += ": " + urlErr.Err.Error()
	}
	return fmt.Errorf("%s: %s", prefix, msg)
}

func (d *Driver) conn(ctx context.Context, database string) (*sql.DB, error) {
	if database == "" || database == d.cfg.Database {
		return d.db, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if c, ok := d.conns[database]; ok {
		return c, nil
	}
	cfg := d.cfg.Copy()
	cfg.Database = database
	c := stdlib.OpenDB(*cfg)
	c.SetMaxOpenConns(1)
	if err := c.PingContext(ctx); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("connect to database %q: %w", database, dedupLines(err))
	}
	d.conns[database] = c
	return c, nil
}

// Exec implements driver.Driver. The statement is sent with the extended
// query protocol, in which the server refuses a query string holding more
// than one command, so a quoting mistake cannot chain another statement.
// A statement with AsRole runs on one pinned connection in a transaction
// of its own, under SET LOCAL ROLE; others run without a transaction,
// since CREATE DATABASE and DROP DATABASE cannot run inside one.
//
// Errors the server answered with, and failures before the statement was
// sent or before its transaction committed, are marked as rejected;
// others, such as a connection lost while the statement ran, leave the
// outcome unknown.
func (d *Driver) Exec(ctx context.Context, s plan.Statement) error {
	c, err := d.conn(ctx, s.Database)
	if err != nil {
		return apply.Rejected(err)
	}
	conn, err := c.Conn(ctx)
	if err != nil {
		return apply.Rejected(fmt.Errorf("get a connection: %w", err))
	}
	defer func() { _ = conn.Close() }()
	d.notices.take()
	err = conn.Raw(func(dc any) error {
		sc, ok := dc.(*stdlib.Conn)
		if !ok {
			return apply.Rejected(fmt.Errorf("unexpected driver connection %T", dc))
		}
		pc := sc.Conn().PgConn()
		if s.AsRole == "" {
			return classify(execOne(ctx, pc, s.SQL()), false)
		}
		return execAs(ctx, pc, s.AsRole, s.SQL())
	})
	if err != nil {
		return err
	}
	return apply.Rejected(noticeError(d.notices.take()))
}

// execOne sends query as a single extended-protocol statement and waits
// for its result.
func execOne(ctx context.Context, pc *pgconn.PgConn, query string) error {
	return pc.ExecParams(ctx, query, nil, nil, nil, nil).Read().Err
}

// execAs runs query as role: BEGIN; SET LOCAL ROLE role; query; COMMIT,
// each sent on its own. SET LOCAL ends with the transaction, so the
// connection returns to the pool as the connected user whatever happens.
func execAs(ctx context.Context, pc *pgconn.PgConn, role, query string) error {
	if err := execOne(ctx, pc, "BEGIN"); err != nil {
		return discardIfInTx(pc, classify(err, true))
	}
	setRole := plan.SQL("", plan.Keyword("SET LOCAL ROLE "), Ident(role)).SQL()
	for _, q := range []string{setRole, query} {
		if err := execOne(ctx, pc, q); err != nil {
			// Nothing was committed: the server rolls the transaction
			// back on ROLLBACK or when the connection is lost.
			rollback(ctx, pc)
			return discardIfInTx(pc, classify(err, true))
		}
	}
	if err := execOne(ctx, pc, "COMMIT"); err != nil {
		// A COMMIT the server answered with an error rolled back; any
		// other failure hides whether it committed.
		return discardIfInTx(pc, classify(err, false))
	}
	return nil
}

// rollbackTimeout bounds the ROLLBACK after a failed statement, which
// runs even when ctx is cancelled, and closing a connection left in it.
const rollbackTimeout = 5 * time.Second

// rollback ends the failed transaction. Its error is not reported:
// discardIfInTx drops a connection that is still inside the transaction.
func rollback(ctx context.Context, pc *pgconn.PgConn) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	_ = execOne(ctx, pc, "ROLLBACK")
}

// classify marks err as rejected when the server answered with it, when
// nothing was sent, or when notApplied is set because nothing can have
// taken effect. Other errors leave the outcome unknown.
func classify(err error, notApplied bool) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsType[*pgconn.PgError](err); ok {
		return apply.Rejected(withDetail(err))
	}
	if notApplied || pgconn.SafeToRetry(err) {
		return apply.Rejected(err)
	}
	return err
}

// discardIfInTx makes database/sql drop the connection when it is closed
// or still inside a transaction, so that no later statement can run in
// what is left of the failed one.
func discardIfInTx(pc *pgconn.PgConn, err error) error {
	if pc.IsClosed() || pc.TxStatus() != 'I' {
		ctx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
		defer cancel()
		_ = pc.Close(ctx)
		return badConn{err}
	}
	return err
}

// badConn marks err as driver.ErrBadConn, which makes database/sql close
// the connection, without changing its text.
type badConn struct{ error }

func (e badConn) Is(target error) bool { return target == driver.ErrBadConn }

func (e badConn) Unwrap() error { return e.error }

// detailError adds the server's DETAIL and HINT, which often name the
// object that blocks a statement, to a PostgreSQL error.
type detailError struct{ pg *pgconn.PgError }

func (e *detailError) Error() string {
	var sb strings.Builder
	sb.WriteString(e.pg.Error())
	if e.pg.Detail != "" {
		sb.WriteString("\nDETAIL: " + e.pg.Detail)
	}
	if e.pg.Hint != "" {
		sb.WriteString("\nHINT: " + e.pg.Hint)
	}
	return sb.String()
}

func (e *detailError) Unwrap() error { return e.pg }

func withDetail(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Detail != "" || pgErr.Hint != "") {
		return &detailError{pg: pgErr}
	}
	return err
}

// closeConn closes the connection to database that conn opened, so that
// it does not keep the plan from dropping that database. A later conn
// opens it again.
func (d *Driver) closeConn(database string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if c, ok := d.conns[database]; ok {
		_ = c.Close()
		delete(d.conns, database)
	}
}

// Close implements driver.Driver.
func (d *Driver) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	errs := []error{d.db.Close()}
	for _, c := range d.conns {
		errs = append(errs, c.Close())
	}
	return errors.Join(errs...)
}

// Dialect renders PostgreSQL SQL. It is usable without a connection.
type Dialect struct {
	// PasswordEncryption is the session's password_encryption: the kind
	// of verifier the server computes for a new password. Empty means
	// scram-sha-256, the default.
	PasswordEncryption string
}

// Ident quotes an identifier.
func Ident(s string) plan.Ident {
	return plan.QuotedIdent(`"` + strings.ReplaceAll(s, `"`, `""`) + `"`)
}

// Grantee renders the grantee of a GRANT or REVOKE: the PUBLIC
// pseudo-role (model.PublicRole) unquoted, any other role as Ident.
func Grantee(name string) plan.Fragment {
	if (model.RoleID{Name: name}).IsPublic() {
		return plan.Keyword("PUBLIC")
	}
	return Ident(name)
}

// Literal quotes a string literal. A string containing a backslash is
// rendered as an escape string, so it means the same whatever the value
// of standard_conforming_strings.
func Literal(s string) plan.Literal {
	q := "'" + strings.ReplaceAll(s, "'", "''") + "'"
	if !strings.Contains(s, `\`) {
		return plan.EscapedLiteral(q)
	}
	return plan.EscapedLiteral("E" + strings.ReplaceAll(q, `\`, `\\`))
}

// privileges renders a privilege list. The names are validated words:
// the configuration accepts only the privileges of the object type, and
// Inspect decodes ACL letters into fixed names.
func privileges(ps []string) plan.Seq {
	toks := make([]plan.Token, len(ps))
	for i, p := range ps {
		toks[i] = plan.NewToken(p)
	}
	return plan.Join(", ", toks...)
}

// IsSystemRole implements diff.Dialect. Besides PostgreSQL's own roles it
// covers the built-in roles of managed services: Amazon RDS / Aurora
// (rdsadmin, rdsrepladmin, rdstopmgr, rds_*), Cloud SQL (cloudsql*),
// Azure (azuresu, azure_*) and AlloyDB (alloydb*).
func (Dialect) IsSystemRole(id model.RoleID) bool {
	n := id.Name
	return slices.Contains([]string{"postgres", "rdsadmin", "rdsrepladmin", "rdstopmgr"}, n) ||
		hasAnyPrefix(n, "pg_", "rds_", "cloudsql", "azure", "alloydb")
}

// IsSystemDatabase implements diff.Dialect.
func (Dialect) IsSystemDatabase(name string) bool {
	return slices.Contains([]string{"postgres", "template0", "template1", "rdsadmin", "cloudsqladmin", "azure_maintenance", "azure_sys", "alloydbadmin"}, name)
}

// IsSystemSchema implements diff.Dialect.
func (Dialect) IsSystemSchema(name string) bool {
	return name == "public" || name == "information_schema" || strings.HasPrefix(name, "pg_")
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	return slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(s, p) })
}

func flag(on bool, yes, no plan.Keyword) plan.Keyword {
	if on {
		return yes
	}
	return no
}

type roleOpt struct {
	want *bool
	yes  plan.Keyword
	no   plan.Keyword
	have bool
}

func roleOpts(r model.Role, cur model.RoleState) []roleOpt {
	return []roleOpt{
		{want: r.Login, have: cur.Login, yes: "LOGIN", no: "NOLOGIN"},
		{want: r.Superuser, have: cur.Superuser, yes: "SUPERUSER", no: "NOSUPERUSER"},
		{want: r.CreateDB, have: cur.CreateDB, yes: "CREATEDB", no: "NOCREATEDB"},
		{want: r.CreateRole, have: cur.CreateRole, yes: "CREATEROLE", no: "NOCREATEROLE"},
		{want: r.Inherit, have: cur.Inherit, yes: "INHERIT", no: "NOINHERIT"},
		{want: r.Replication, have: cur.Replication, yes: "REPLICATION", no: "NOREPLICATION"},
		{want: r.BypassRLS, have: cur.BypassRLS, yes: "BYPASSRLS", no: "NOBYPASSRLS"},
	}
}

// CreateRole implements diff.Dialect.
func (d Dialect) CreateRole(r model.Role) []plan.Statement {
	parts := plan.Seq{plan.Keyword("CREATE ROLE "), Ident(r.ID.Name)}
	opts, change := roleOptions(r, model.RoleState{}, false)
	if len(opts) > 0 || r.Password != nil {
		parts = append(parts, plan.Keyword(" WITH"))
	}
	if len(opts) > 0 {
		parts = append(parts, plan.Keyword(" "), plan.Join(" ", opts...))
	}
	if r.Password != nil {
		parts = append(parts, passwordClause(*r.Password))
		change.SetsPassword = true
	}
	return []plan.Statement{plan.New("", plan.KindCreateRole, plan.RoleTarget(r.ID), parts...).WithRoleChange(change)}
}

// roleOptions renders the declared role options of r, or with
// onlyChanged those that differ from cur, and what they change.
func roleOptions(r model.Role, cur model.RoleState, onlyChanged bool) ([]plan.Fragment, plan.RoleChange) {
	var opts []plan.Fragment
	var change plan.RoleChange
	for _, o := range roleOpts(r, cur) {
		if o.want == nil || (onlyChanged && *o.want == o.have) {
			continue
		}
		opts = append(opts, flag(*o.want, o.yes, o.no))
		switch {
		case *o.want:
		case o.no == "NOLOGIN":
			change.DisablesLogin = true
		case o.no == "NOSUPERUSER":
			change.RemovesSuperuser = true
		case o.no == "NOINHERIT":
			change.DisablesInherit = true
		}
	}
	if r.ConnectionLimit != nil && (!onlyChanged || *r.ConnectionLimit != cur.ConnectionLimit) {
		limit := *r.ConnectionLimit
		opts = append(opts, plan.Seq{plan.Keyword("CONNECTION LIMIT "), plan.Number(limit)})
		change.ConnectionLimit = &limit
	}
	return opts, change
}

// passwordClause renders the PASSWORD option. The plaintext is sent, so
// that the server hashes it with its own settings (password_encryption,
// scram_iterations) and password check modules such as passwordcheck can
// inspect it. PostgreSQL clears an empty password, so "" is rendered as
// NULL.
func passwordClause(pw string) plan.Fragment {
	if pw == "" {
		return plan.Keyword(" PASSWORD NULL")
	}
	return plan.Seq{plan.Keyword(" PASSWORD "), plan.NewSecret(Literal(pw))}
}

// passwordMatches reports whether the stored verifier already holds pw.
// An md5 verifier counts as a mismatch unless the server itself produces
// md5 verifiers, so that setting the password again upgrades it to SCRAM.
func (d Dialect) passwordMatches(verifier, user, pw string) (bool, error) {
	switch {
	case pw == "":
		return verifier == "", nil
	case password.PostgresVerifierKind(verifier) == password.VerifierMD5 && d.PasswordEncryption != string(password.VerifierMD5):
		return false, nil
	default:
		return password.MatchPostgres(verifier, user, pw)
	}
}

// EnsureRole implements diff.Dialect. pg_roles is always readable, so
// this is only a fallback; PostgreSQL has no CREATE ROLE IF NOT EXISTS.
func (d Dialect) EnsureRole(r model.Role) []plan.Statement { return d.CreateRole(r) }

// AlterRole implements diff.Dialect.
func (d Dialect) AlterRole(r model.Role, cur model.RoleState, force bool) ([]plan.Statement, []string) {
	return d.alterRole(r, cur, force, false)
}

// alterRole renders AlterRole. groupedUnreadable suppresses the warning
// about an unreadable verifier, which Inspect then reports once for all
// roles.
func (d Dialect) alterRole(r model.Role, cur model.RoleState, force, groupedUnreadable bool) ([]plan.Statement, []string) {
	var warns []string
	opts, change := roleOptions(r, cur, true)
	setPassword := false
	if r.Password != nil {
		switch {
		case force:
			setPassword = true
		case !cur.PasswordReadable && groupedUnreadable:
		case !cur.PasswordReadable:
			warns = append(warns, fmt.Sprintf("cannot read the password verifier of role %q (superuser required); password not compared, use --force-password to set it", r.ID))
		default:
			ok, err := d.passwordMatches(string(cur.PasswordHash), r.ID.Name, *r.Password)
			switch {
			case err != nil:
				warns = append(warns, fmt.Sprintf("cannot compare the password of role %q: %v; use --force-password to set it", r.ID, err))
			case !ok:
				setPassword = true
			}
		}
	}
	if len(opts) == 0 && !setPassword {
		return nil, warns
	}
	parts := plan.Seq{plan.Keyword("ALTER ROLE "), Ident(r.ID.Name), plan.Keyword(" WITH")}
	if len(opts) > 0 {
		parts = append(parts, plan.Keyword(" "), plan.Join(" ", opts...))
	}
	if setPassword {
		parts = append(parts, passwordClause(*r.Password))
		change.SetsPassword = true
	}
	return []plan.Statement{plan.New("", plan.KindAlterRole, plan.RoleTarget(r.ID), parts...).WithRoleChange(change)}, warns
}

// DropRole implements diff.Dialect. Objects owned by the role are
// reassigned to the connected user in every surviving database except
// those reserved by PostgreSQL or a managed service.
func (Dialect) DropRole(id model.RoleID, databases []string) []plan.Statement {
	var out []plan.Statement
	for _, db := range databases {
		if providerDatabase(db) {
			continue
		}
		target := plan.RoleTarget(id)
		target.Database = db
		out = append(out,
			plan.New(db, plan.KindReassign, target, plan.Keyword("REASSIGN OWNED BY "), Ident(id.Name), plan.Keyword(" TO CURRENT_USER")),
			plan.New(db, plan.KindDropOwned, target, plan.Keyword("DROP OWNED BY "), Ident(id.Name)),
		)
	}
	return append(out, plan.New("", plan.KindDropRole, plan.RoleTarget(id), plan.Keyword("DROP ROLE "), Ident(id.Name)))
}

// GrantMembership implements diff.Dialect.
func (Dialect) GrantMembership(member, role model.RoleID, opts model.MembershipOptions) ([]plan.Statement, []string) {
	return []plan.Statement{newMembership(member.Name, role.Name, opts)}, nil
}

// newMembership renders the GRANT of a membership that does not exist.
func newMembership(member, role string, opts model.MembershipOptions) plan.Statement {
	if opts.Admin != nil && !*opts.Admin {
		// A new grant has no ADMIN OPTION; GRANT cannot express FALSE
		// before PostgreSQL 16.
		opts.Admin = nil
	}
	return grantMembership(member, role, opts, "")
}

// grantMembership renders GRANT role TO member with the declared
// options, followed by GRANTED BY grantor unless grantor is "". ADMIN
// alone uses WITH ADMIN OPTION, which every version accepts; INHERIT and
// SET need the PostgreSQL 16 option list.
func grantMembership(member, role string, opts model.MembershipOptions, grantor string) plan.Statement {
	target := membershipTarget(member, role, grantor).WithOption(opts.Admin != nil && *opts.Admin)
	parts := plan.Seq{plan.Keyword("GRANT "), Ident(role), plan.Keyword(" TO "), Ident(member)}
	switch {
	case opts.Inherit == nil && opts.Set == nil:
		if opts.Admin != nil && *opts.Admin {
			parts = append(parts, plan.Keyword(" WITH ADMIN OPTION"))
		}
	default:
		var list []plan.Seq
		for _, o := range []struct {
			v    *bool
			name plan.Keyword
		}{{opts.Admin, "ADMIN"}, {opts.Inherit, "INHERIT"}, {opts.Set, "SET"}} {
			if o.v != nil {
				list = append(list, plan.Seq{o.name, plan.Keyword(" "), flag(*o.v, "TRUE", "FALSE")})
			}
		}
		parts = append(parts, plan.Keyword(" WITH "), plan.Join(", ", list...))
	}
	parts = append(parts, grantedBy(grantor)...)
	change := plan.RoleChange{
		DisablesInherit: opts.Inherit != nil && !*opts.Inherit,
		DisablesSet:     opts.Set != nil && !*opts.Set,
	}
	return plan.New("", plan.KindGrantMembership, target, parts...).WithRoleChange(change)
}

// revokeMembership renders REVOKE [ADMIN OPTION FOR] role FROM member,
// followed by GRANTED BY grantor unless grantor is "", and CASCADE when
// cascade is set.
func revokeMembership(member, role string, adminOnly bool, grantor string, cascade bool) plan.Statement {
	target := membershipTarget(member, role, grantor).WithOption(adminOnly)
	parts := plan.Seq{plan.Keyword("REVOKE ")}
	if adminOnly {
		parts = append(parts, plan.Keyword("ADMIN OPTION FOR "))
	}
	parts = append(parts, Ident(role), plan.Keyword(" FROM "), Ident(member))
	parts = append(parts, grantedBy(grantor)...)
	if cascade {
		parts = append(parts, plan.Keyword(" CASCADE"))
	}
	return plan.New("", plan.KindRevokeMembership, target, parts...)
}

// membershipTarget is the Target of a grant or revoke of role to member
// whose GRANTED BY names grantor ("" for none).
func membershipTarget(member, role, grantor string) plan.Target {
	t := plan.MembershipTarget(model.RoleID{Name: member}, model.RoleID{Name: role})
	if grantor != "" {
		t.Grantor = model.RoleID{Name: grantor}
	}
	return t
}

// grantedBy renders GRANTED BY grantor, or nothing for "". Only the
// membership builders call it, so that the grantor is in their Target.
func grantedBy(grantor string) plan.Seq {
	if grantor == "" {
		return nil
	}
	return plan.Seq{plan.Keyword(" GRANTED BY "), Ident(grantor)}
}

// AlterMembership implements diff.Dialect. Without inspected grants, the
// options are changed on the grant of the connected user.
func (Dialect) AlterMembership(member, role model.RoleID, want model.MembershipOptions, have model.MembershipState) ([]plan.Statement, []string) {
	var out []plan.Statement
	if want.Admin != nil && !*want.Admin && have.Admin {
		out = append(out, revokeMembership(member.Name, role.Name, true, "", false))
	}
	grant := model.MembershipOptions{Inherit: want.Inherit, Set: want.Set}
	if want.Admin != nil && *want.Admin && !have.Admin {
		grant.Admin = want.Admin
	}
	if grant != (model.MembershipOptions{}) {
		out = append(out, grantMembership(member.Name, role.Name, grant, ""))
	}
	return out, nil
}

// RevokeMembership implements diff.Dialect.
func (Dialect) RevokeMembership(member, role model.RoleID) ([]plan.Statement, []string) {
	return []plan.Statement{revokeMembership(member.Name, role.Name, false, "", false)}, nil
}

// CreateDatabase implements diff.Dialect.
func (Dialect) CreateDatabase(db model.Database) []plan.Statement {
	parts := plan.Seq{plan.Keyword("CREATE DATABASE "), Ident(db.Name)}
	if db.Owner != "" {
		parts = append(parts, plan.Keyword(" OWNER "), Ident(db.Owner))
	}
	if db.Encoding != "" {
		parts = append(parts, plan.Keyword(" ENCODING "), Literal(db.Encoding))
	}
	if db.LcCollate != "" {
		parts = append(parts, plan.Keyword(" LC_COLLATE "), Literal(db.LcCollate))
	}
	if db.LcCtype != "" {
		parts = append(parts, plan.Keyword(" LC_CTYPE "), Literal(db.LcCtype))
	}
	if db.Encoding != "" || db.LcCollate != "" || db.LcCtype != "" {
		parts = append(parts, plan.Keyword(" TEMPLATE template0"))
	}
	return []plan.Statement{plan.New("", plan.KindCreateDatabase, databaseTarget(db.Name).WithOwner(db.Owner), parts...)}
}

func databaseTarget(name string) plan.Target {
	return plan.ObjectTarget(model.Object{Type: model.ObjectDatabase, Database: name})
}

func schemaTarget(s model.Schema) plan.Target {
	return plan.ObjectTarget(model.Object{Type: model.ObjectSchema, Database: s.Database, Schema: s.Name})
}

// encodingAliases maps cleaned encoding names that PostgreSQL accepts
// (src/common/encnames.c) to the cleaned canonical name.
var encodingAliases = map[string]string{
	"abc": "win1258", "alt": "win866", "iso88591": "latin1", "iso88592": "latin2",
	"iso88593": "latin3", "iso88594": "latin4", "iso88599": "latin5", "iso885910": "latin6",
	"iso885913": "latin7", "iso885914": "latin8", "iso885915": "latin9", "iso885916": "latin10",
	"koi8": "koi8r", "mskanji": "sjis", "shiftjis": "sjis", "tcvn": "win1258", "tcvn5712": "win1258",
	"unicode": "utf8", "vscii": "win1258", "win": "win1251", "win932": "sjis", "win936": "gbk",
	"win949": "uhc", "win950": "big5", "windows932": "sjis", "windows936": "gbk",
	"windows949": "uhc", "windows950": "big5",
}

// cleanName lower-cases s and drops non-alphanumerics, like PostgreSQL's
// clean_encoding_name and glibc's codeset normalization.
func cleanName(s string) string {
	var sb strings.Builder
	for _, r := range strings.ToLower(s) {
		if ('a' <= r && r <= 'z') || ('0' <= r && r <= '9') {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func normEncoding(s string) string {
	n := cleanName(s)
	if a, ok := encodingAliases[n]; ok {
		return a
	}
	if w, ok := strings.CutPrefix(n, "windows"); ok {
		return "win" + w
	}
	return n
}

// normLocale normalizes the codeset of a locale name, so that
// en_US.UTF-8 and en_US.utf8 compare equal.
func normLocale(s string) string {
	name, rest, ok := strings.Cut(s, ".")
	if !ok {
		return strings.ToLower(s)
	}
	codeset, modifier, hasMod := strings.Cut(rest, "@")
	out := strings.ToLower(name) + "." + cleanName(codeset)
	if hasMod {
		out += "@" + strings.ToLower(modifier)
	}
	return out
}

// AlterDatabase implements diff.Dialect.
func (Dialect) AlterDatabase(db, cur model.Database) ([]plan.Statement, []string) {
	var warns []string
	immutable := func(attr, want, have string, eq func(a, b string) bool) {
		if want != "" && !eq(want, have) {
			warns = append(warns, fmt.Sprintf("database %q has %s %q but %q is declared; it cannot be changed after creation", db.Name, attr, have, want))
		}
	}
	immutable("encoding", db.Encoding, cur.Encoding, func(a, b string) bool { return normEncoding(a) == normEncoding(b) })
	sameLocale := func(a, b string) bool { return normLocale(a) == normLocale(b) }
	immutable("lc_collate", db.LcCollate, cur.LcCollate, sameLocale)
	immutable("lc_ctype", db.LcCtype, cur.LcCtype, sameLocale)
	if db.Owner != "" && db.Owner != cur.Owner {
		return []plan.Statement{plan.New("", plan.KindAlterDatabase, databaseTarget(db.Name).WithOwner(db.Owner),
			plan.Keyword("ALTER DATABASE "), Ident(db.Name), plan.Keyword(" OWNER TO "), Ident(db.Owner))}, warns
	}
	return nil, warns
}

// DropDatabase implements diff.Dialect.
func (Dialect) DropDatabase(name string) []plan.Statement {
	return []plan.Statement{plan.New("", plan.KindDropDatabase, databaseTarget(name), plan.Keyword("DROP DATABASE "), Ident(name))}
}

// CreateSchema implements diff.Dialect.
func (Dialect) CreateSchema(s model.Schema) []plan.Statement {
	parts := plan.Seq{plan.Keyword("CREATE SCHEMA "), Ident(s.Name)}
	if s.Owner != "" {
		parts = append(parts, plan.Keyword(" AUTHORIZATION "), Ident(s.Owner))
	}
	return []plan.Statement{plan.New(s.Database, plan.KindCreateSchema, schemaTarget(s).WithOwner(s.Owner), parts...)}
}

// AlterSchema implements diff.Dialect.
func (Dialect) AlterSchema(s, cur model.Schema) []plan.Statement {
	if s.Owner == "" || s.Owner == cur.Owner {
		return nil
	}
	return []plan.Statement{plan.New(s.Database, plan.KindAlterSchema, schemaTarget(s).WithOwner(s.Owner),
		plan.Keyword("ALTER SCHEMA "), Ident(s.Name), plan.Keyword(" OWNER TO "), Ident(s.Owner))}
}

// DropSchema implements diff.Dialect. It fails on non-empty schemas.
func (Dialect) DropSchema(s model.Schema) []plan.Statement {
	return []plan.Statement{dropSchema(s)}
}

// dropSchema renders DROP SCHEMA s followed by tail, such as CASCADE.
func dropSchema(s model.Schema, tail ...plan.Fragment) plan.Statement {
	parts := plan.Seq{plan.Keyword("DROP SCHEMA "), Ident(s.Name)}
	return plan.New(s.Database, plan.KindDropSchema, schemaTarget(s), append(parts, tail...)...)
}

func onObject(obj model.Object) (database string, target plan.Seq) {
	if obj.Type == model.ObjectSchema {
		return obj.Database, plan.Seq{plan.Keyword("SCHEMA "), Ident(obj.Schema)}
	}
	return "", plan.Seq{plan.Keyword("DATABASE "), Ident(obj.Database)}
}

// revokePrivileges renders REVOKE [GRANT OPTION FOR] privs ON obj FROM
// grantee followed by tail, such as CASCADE.
func revokePrivileges(grantee string, obj model.Object, privs []string, optionOnly bool, tail ...plan.Fragment) plan.Statement {
	db, on := onObject(obj)
	parts := plan.Seq{plan.Keyword("REVOKE ")}
	if optionOnly {
		parts = append(parts, plan.Keyword("GRANT OPTION FOR "))
	}
	parts = append(parts, privileges(privs), plan.Keyword(" ON "), on, plan.Keyword(" FROM "), Grantee(grantee))
	target := plan.PrivilegeTarget(model.RoleID{Name: grantee}, obj).WithOption(optionOnly)
	return plan.New(db, plan.KindRevoke, target, append(parts, tail...)...).WithPrivileges(privs)
}

// pg15 is the server_version_num from which the public schema of a new
// database grants only USAGE to PUBLIC.
const pg15 = 150000

// DefaultPublicPrivileges implements diff.PublicDefaulter for PostgreSQL
// 15 and later: a new database grants CONNECT and TEMPORARY to PUBLIC,
// and its public schema, copied from template1, grants USAGE.
func (Dialect) DefaultPublicPrivileges(obj model.Object) []string {
	return defaultPublicPrivileges(obj, pg15)
}

func defaultPublicPrivileges(obj model.Object, version int) []string {
	switch {
	case obj.Type == model.ObjectDatabase:
		return []string{"CONNECT", "TEMPORARY"}
	case obj.Schema != "public":
		return nil
	case version < pg15:
		return []string{"CREATE", "USAGE"}
	}
	return []string{"USAGE"}
}

// Grant implements diff.Dialect.
func (Dialect) Grant(grantee model.RoleID, obj model.Object, privs []string, grantOption bool) []plan.Statement {
	db, on := onObject(obj)
	parts := plan.Seq{plan.Keyword("GRANT "), privileges(privs), plan.Keyword(" ON "), on, plan.Keyword(" TO "), Grantee(grantee.Name)}
	if grantOption {
		parts = append(parts, plan.Keyword(" WITH GRANT OPTION"))
	}
	return []plan.Statement{plan.New(db, plan.KindGrant, plan.PrivilegeTarget(grantee, obj).WithOption(grantOption), parts...).WithPrivileges(privs)}
}

// Revoke implements diff.Dialect.
func (Dialect) Revoke(grantee model.RoleID, obj model.Object, privs []string) ([]plan.Statement, []string) {
	return []plan.Statement{revokePrivileges(grantee.Name, obj, privs, false)}, nil
}

// RevokeGrantOption implements diff.Dialect.
func (Dialect) RevokeGrantOption(grantee model.RoleID, obj model.Object, privs []string) ([]plan.Statement, []string) {
	return []plan.Statement{revokePrivileges(grantee.Name, obj, privs, true)}, nil
}
