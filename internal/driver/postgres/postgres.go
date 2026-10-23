// Package postgres implements the dbfence driver for PostgreSQL.
package postgres

import (
	"context"
	"database/sql"
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
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/password"
	"github.com/mazrean/dbfence/internal/plan"
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
	if err := d.db.PingContext(ctx); err != nil {
		_ = d.db.Close()
		return nil, fmt.Errorf("connect to postgres: %w", dedupLines(err))
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
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = defaultConnectTimeout
	}
	// Literals are rendered for standard_conforming_strings = on; a startup
	// parameter overrides role and database defaults.
	cfg.RuntimeParams["standard_conforming_strings"] = "on"
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

// Exec implements driver.Driver.
func (d *Driver) Exec(ctx context.Context, database, query string) error {
	c, err := d.conn(ctx, database)
	if err != nil {
		return err
	}
	d.notices.take()
	if _, err = c.ExecContext(ctx, query); err != nil {
		return withDetail(err)
	}
	return noticeError(d.notices.take())
}

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
type Dialect struct{}

// Ident quotes an identifier.
func Ident(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// Grantee renders the grantee of a GRANT or REVOKE: the PUBLIC
// pseudo-role (model.PublicRole) unquoted, any other role as Ident.
func Grantee(name string) string {
	if (model.RoleID{Name: name}).IsPublic() {
		return "PUBLIC"
	}
	return Ident(name)
}

// Literal quotes a string literal. A string containing a backslash is
// rendered as an escape string, so it means the same whatever the value
// of standard_conforming_strings.
func Literal(s string) string {
	q := "'" + strings.ReplaceAll(s, "'", "''") + "'"
	if !strings.Contains(s, `\`) {
		return q
	}
	return "E" + strings.ReplaceAll(q, `\`, `\\`)
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

func flag(on bool, yes, no string) string {
	if on {
		return yes
	}
	return no
}

type roleOpt struct {
	want *bool
	yes  string
	no   string
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
func (Dialect) CreateRole(r model.Role) []plan.Statement {
	parts := []any{"CREATE ROLE " + Ident(r.ID.Name)}
	var opts []string
	for _, o := range roleOpts(r, model.RoleState{}) {
		if o.want != nil {
			opts = append(opts, flag(*o.want, o.yes, o.no))
		}
	}
	if r.ConnectionLimit != nil {
		opts = append(opts, fmt.Sprintf("CONNECTION LIMIT %d", *r.ConnectionLimit))
	}
	if len(opts) > 0 || r.Password != nil {
		parts[0] = parts[0].(string) + " WITH"
	}
	if len(opts) > 0 {
		parts[0] = parts[0].(string) + " " + strings.Join(opts, " ")
	}
	if r.Password != nil {
		parts = append(parts, passwordClause(*r.Password)...)
	}
	return []plan.Statement{plan.SQL("", parts...)}
}

// passwordClause renders the PASSWORD option. The password is sent as a
// SCRAM-SHA-256 verifier computed here, so the plaintext never reaches
// the server, its logs or pg_stat_statements, and a declared password
// that looks like a verifier is still hashed. PostgreSQL clears an empty
// password, so "" is rendered as NULL.
func passwordClause(pw string) []any {
	if pw == "" {
		return []any{" PASSWORD NULL"}
	}
	v, err := password.SCRAMVerifier(pw)
	if err != nil {
		// Only reachable when crypto/pbkdf2 rejects its input (FIPS-only
		// mode); the server then hashes the password itself.
		v = pw
	}
	return []any{" PASSWORD ", plan.Secret(Literal(v))}
}

// passwordMatches reports whether the stored verifier already holds pw.
// md5 verifiers never match, so that they are upgraded to SCRAM.
func passwordMatches(verifier, user, pw string) (bool, error) {
	switch {
	case pw == "":
		return verifier == "", nil
	case strings.HasPrefix(verifier, "md5"):
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
func (Dialect) alterRole(r model.Role, cur model.RoleState, force, groupedUnreadable bool) ([]plan.Statement, []string) {
	var opts []string
	var warns []string
	for _, o := range roleOpts(r, cur) {
		if o.want != nil && *o.want != o.have {
			opts = append(opts, flag(*o.want, o.yes, o.no))
		}
	}
	if r.ConnectionLimit != nil && *r.ConnectionLimit != cur.ConnectionLimit {
		opts = append(opts, fmt.Sprintf("CONNECTION LIMIT %d", *r.ConnectionLimit))
	}
	setPassword := false
	if r.Password != nil {
		switch {
		case force:
			setPassword = true
		case !cur.PasswordReadable && groupedUnreadable:
		case !cur.PasswordReadable:
			warns = append(warns, fmt.Sprintf("cannot read the password verifier of role %q (superuser required); password not compared, use --force-password to set it", r.ID))
		default:
			ok, err := passwordMatches(string(cur.PasswordHash), r.ID.Name, *r.Password)
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
	parts := []any{"ALTER ROLE " + Ident(r.ID.Name) + " WITH"}
	if len(opts) > 0 {
		parts[0] = parts[0].(string) + " " + strings.Join(opts, " ")
	}
	if setPassword {
		parts = append(parts, passwordClause(*r.Password)...)
	}
	return []plan.Statement{plan.SQL("", parts...)}, warns
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
		out = append(out,
			plan.SQL(db, "REASSIGN OWNED BY "+Ident(id.Name)+" TO CURRENT_USER"),
			plan.SQL(db, "DROP OWNED BY "+Ident(id.Name)),
		)
	}
	return append(out, plan.SQL("", "DROP ROLE "+Ident(id.Name)))
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
	return plan.SQL("", grantMembership(member, role, opts))
}

// grantMembership renders GRANT role TO member with the declared
// options. ADMIN alone uses WITH ADMIN OPTION, which every version
// accepts; INHERIT and SET need the PostgreSQL 16 option list.
func grantMembership(member, role string, opts model.MembershipOptions) string {
	q := "GRANT " + Ident(role) + " TO " + Ident(member)
	if opts.Inherit == nil && opts.Set == nil {
		if opts.Admin != nil && *opts.Admin {
			q += " WITH ADMIN OPTION"
		}
		return q
	}
	var list []string
	for _, o := range []struct {
		v    *bool
		name string
	}{{opts.Admin, "ADMIN"}, {opts.Inherit, "INHERIT"}, {opts.Set, "SET"}} {
		if o.v != nil {
			list = append(list, o.name+" "+flag(*o.v, "TRUE", "FALSE"))
		}
	}
	return q + " WITH " + strings.Join(list, ", ")
}

// AlterMembership implements diff.Dialect. Without inspected grants, the
// options are changed on the grant of the connected user.
func (Dialect) AlterMembership(member, role model.RoleID, want model.MembershipOptions, have model.MembershipState) ([]plan.Statement, []string) {
	var out []plan.Statement
	if want.Admin != nil && !*want.Admin && have.Admin {
		out = append(out, plan.SQL("", "REVOKE ADMIN OPTION FOR "+Ident(role.Name)+" FROM "+Ident(member.Name)))
	}
	grant := model.MembershipOptions{Inherit: want.Inherit, Set: want.Set}
	if want.Admin != nil && *want.Admin && !have.Admin {
		grant.Admin = want.Admin
	}
	if grant != (model.MembershipOptions{}) {
		out = append(out, plan.SQL("", grantMembership(member.Name, role.Name, grant)))
	}
	return out, nil
}

// RevokeMembership implements diff.Dialect.
func (Dialect) RevokeMembership(member, role model.RoleID) ([]plan.Statement, []string) {
	return []plan.Statement{plan.SQL("", "REVOKE "+Ident(role.Name)+" FROM "+Ident(member.Name))}, nil
}

// CreateDatabase implements diff.Dialect.
func (Dialect) CreateDatabase(db model.Database) []plan.Statement {
	q := "CREATE DATABASE " + Ident(db.Name)
	if db.Owner != "" {
		q += " OWNER " + Ident(db.Owner)
	}
	if db.Encoding != "" {
		q += " ENCODING " + Literal(db.Encoding)
	}
	if db.LcCollate != "" {
		q += " LC_COLLATE " + Literal(db.LcCollate)
	}
	if db.LcCtype != "" {
		q += " LC_CTYPE " + Literal(db.LcCtype)
	}
	if db.Encoding != "" || db.LcCollate != "" || db.LcCtype != "" {
		q += " TEMPLATE template0"
	}
	return []plan.Statement{plan.SQL("", q)}
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
		return []plan.Statement{plan.SQL("", "ALTER DATABASE "+Ident(db.Name)+" OWNER TO "+Ident(db.Owner))}, warns
	}
	return nil, warns
}

// DropDatabase implements diff.Dialect.
func (Dialect) DropDatabase(name string) []plan.Statement {
	return []plan.Statement{plan.SQL("", "DROP DATABASE "+Ident(name))}
}

// CreateSchema implements diff.Dialect.
func (Dialect) CreateSchema(s model.Schema) []plan.Statement {
	q := "CREATE SCHEMA " + Ident(s.Name)
	if s.Owner != "" {
		q += " AUTHORIZATION " + Ident(s.Owner)
	}
	return []plan.Statement{plan.SQL(s.Database, q)}
}

// AlterSchema implements diff.Dialect.
func (Dialect) AlterSchema(s, cur model.Schema) []plan.Statement {
	if s.Owner == "" || s.Owner == cur.Owner {
		return nil
	}
	return []plan.Statement{plan.SQL(s.Database, "ALTER SCHEMA "+Ident(s.Name)+" OWNER TO "+Ident(s.Owner))}
}

// DropSchema implements diff.Dialect. It fails on non-empty schemas.
func (Dialect) DropSchema(s model.Schema) []plan.Statement {
	return []plan.Statement{plan.SQL(s.Database, "DROP SCHEMA "+Ident(s.Name))}
}

func onObject(obj model.Object) (database, target string) {
	if obj.Type == model.ObjectSchema {
		return obj.Database, "SCHEMA " + Ident(obj.Schema)
	}
	return "", "DATABASE " + Ident(obj.Database)
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
	db, target := onObject(obj)
	q := "GRANT " + strings.Join(privs, ", ") + " ON " + target + " TO " + Grantee(grantee.Name)
	if grantOption {
		q += " WITH GRANT OPTION"
	}
	return []plan.Statement{plan.SQL(db, q)}
}

// Revoke implements diff.Dialect.
func (Dialect) Revoke(grantee model.RoleID, obj model.Object, privs []string) ([]plan.Statement, []string) {
	db, target := onObject(obj)
	return []plan.Statement{plan.SQL(db, "REVOKE "+strings.Join(privs, ", ")+" ON "+target+" FROM "+Grantee(grantee.Name))}, nil
}

// RevokeGrantOption implements diff.Dialect.
func (Dialect) RevokeGrantOption(grantee model.RoleID, obj model.Object, privs []string) ([]plan.Statement, []string) {
	db, target := onObject(obj)
	return []plan.Statement{plan.SQL(db, "REVOKE GRANT OPTION FOR "+strings.Join(privs, ", ")+" ON "+target+" FROM "+Grantee(grantee.Name))}, nil
}
