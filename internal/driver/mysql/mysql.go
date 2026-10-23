// Package mysql implements the dbfence driver for MySQL 8.0+.
package mysql

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	gomysql "github.com/go-sql-driver/mysql"
	"github.com/mazrean/dbfence/internal/apply"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/password"
	"github.com/mazrean/dbfence/internal/plan"
)

// Driver is a MySQL driver. All statements run on the configured
// connection; Statement.Database is always empty.
type Driver struct {
	db *sql.DB
	Dialect
}

// Open connects to dsn (go-sql-driver/mysql format).
func Open(ctx context.Context, dsn string) (*Driver, error) {
	cfg, err := parseDSN(dsn)
	if err != nil {
		return nil, err
	}
	conn, err := gomysql.NewConnector(cfg)
	if err != nil {
		return nil, fmt.Errorf("mysql connector: %w", err)
	}
	db := sql.OpenDB(conn)
	// A single connection keeps session state such as sql_mode stable.
	db.SetMaxOpenConns(1)
	// cfg.Timeout only bounds the dial; a server that accepts the
	// connection but never sends the handshake would block forever.
	// The connection is reused, so the session queries below share it.
	connectCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	if err := db.PingContext(connectCtx); err != nil {
		_ = db.Close()
		if ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("connect to mysql: timed out after %s: %w", cfg.Timeout, err)
		}
		return nil, fmt.Errorf("connect to mysql: %w", err)
	}
	ctx = connectCtx
	var mode, charset string
	var lowerCaseNames int
	if err := db.QueryRowContext(ctx, "SELECT @@SESSION.sql_mode, @@SESSION.character_set_client, @@lower_case_table_names").
		Scan(&mode, &charset, &lowerCaseNames); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("read session settings: %w", err)
	}
	if err := checkCharset(charset); err != nil {
		_ = db.Close()
		return nil, err
	}
	d := &Driver{db: db}
	d.NoBackslashEscapes = strings.Contains(mode, "NO_BACKSLASH_ESCAPES")
	d.CaseInsensitiveNames = lowerCaseNames != 0
	var partial bool
	switch err := db.QueryRowContext(ctx, "SELECT @@GLOBAL.partial_revokes").Scan(&partial); {
	case mysqlErrorIn(err, errUnknownSystemVariable):
		// Before MySQL 8.0.16 wildcards in grants are always active.
	case err != nil:
		_ = db.Close()
		return nil, fmt.Errorf("read partial_revokes: %w", err)
	default:
		d.PartialRevokes = partial
	}
	return d, nil
}

// defaultTimeout bounds connecting when the DSN sets no timeout.
const defaultTimeout = 10 * time.Second

// parseDSN parses a go-sql-driver/mysql DSN and applies defaults.
func parseDSN(dsn string) (*gomysql.Config, error) {
	const hint = "expected a go-sql-driver/mysql DSN such as user:password@tcp(host:3306)/; URLs are not supported"
	if strings.HasPrefix(strings.ToLower(dsn), "mysql://") {
		return nil, errors.New("parse mysql dsn: " + hint)
	}
	cfg, err := gomysql.ParseDSN(dsn)
	if err != nil {
		// The driver's errors quote parts of the DSN, which can be parts
		// of the password, so they are not passed on.
		return nil, errors.New("parse mysql dsn: invalid DSN; " + hint + "; a password containing '/' needs the '/' before the database name")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	return cfg, nil
}

// unsafeCharsets are client character sets with multibyte characters
// whose trailing byte can be 0x5C (backslash). Backslash escaping of
// literals is not safe with them.
var unsafeCharsets = []string{"big5", "cp932", "gb18030", "gbk", "sjis"}

func checkCharset(charset string) error {
	if slices.Contains(unsafeCharsets, strings.ToLower(charset)) {
		return fmt.Errorf("connection character set %s is not supported because it breaks string escaping; use charset=utf8mb4 in the DSN", charset)
	}
	return nil
}

// Exec implements driver.Driver.
// Errors the server answered with are marked as rejected; others, such
// as a lost connection, leave the outcome unknown.
func (d *Driver) Exec(ctx context.Context, _, query string) error {
	_, err := d.db.ExecContext(ctx, query)
	if _, ok := errors.AsType[*gomysql.MySQLError](err); ok {
		return apply.Rejected(err)
	}
	return err
}

// Close implements driver.Driver.
func (d *Driver) Close() error { return d.db.Close() }

// Inspect implements driver.Driver.
func (d *Driver) Inspect(ctx context.Context, desired *model.Desired) (*model.Current, error) {
	cur := &model.Current{}
	var user string
	var database sql.NullString
	if err := d.db.QueryRowContext(ctx, "SELECT CURRENT_USER(), DATABASE()").Scan(&user, &database); err != nil {
		return nil, fmt.Errorf("current user: %w", err)
	}
	// The database named in the DSN is never pruned.
	cur.CurrentDatabase = d.declaredName(database.String, desired)
	if name, host, ok := strings.CutLast(user, "@"); ok {
		// Host names are case-insensitive; the server reports them in lower case.
		cur.CurrentUser = model.RoleID{Name: name, Host: strings.ToLower(host)}
	}
	for _, step := range []func(context.Context, *model.Current) error{d.inspectDatabases, d.inspectUsers, d.inspectRoleEdges, d.inspectDefaultRoles} {
		if err := step(ctx, cur); err != nil {
			return nil, err
		}
	}
	for i := range cur.Databases {
		cur.Databases[i].Name = d.declaredName(cur.Databases[i].Name, desired)
	}
	if p := declaredPatterns(desired); len(p) > 0 && d.PartialRevokes {
		return nil, fmt.Errorf("database_pattern %q needs partial_revokes = OFF: with partial_revokes ON, MySQL reads %% and _ in grants literally", p[0])
	}
	if err := d.inspectDBPrivileges(ctx, cur, desired); err != nil {
		return nil, err
	}
	if w := defaultRolesWarning(desired, cur); w != "" {
		cur.Warnings = append(cur.Warnings, w)
	}
	plugins, err := d.activeAuthPlugins(ctx)
	if err != nil {
		return nil, err
	}
	cur.Warnings = append(cur.Warnings, roleWarnings(desired, cur, plugins)...)
	return cur, nil
}

// defaultRolesWarning explains the fallback when mysql.default_roles
// cannot be read and the configuration manages memberships.
func defaultRolesWarning(desired *model.Desired, cur *model.Current) string {
	if desired == nil || !slices.ContainsFunc(cur.Roles, func(r model.RoleState) bool { return r.DefaultRolesUnknown }) ||
		!slices.ContainsFunc(desired.Roles, func(r model.Role) bool { return r.MemberOf != nil }) {
		return ""
	}
	return "cannot read default roles (mysql.default_roles): SET DEFAULT ROLE is issued on every run for declared accounts with member_of"
}

// activeAuthPlugins lists the loaded authentication plugins, or nil when
// they cannot be read.
func (d *Driver) activeAuthPlugins(ctx context.Context) ([]string, error) {
	var plugins []string
	err := query(ctx, d.db, `SELECT PLUGIN_NAME FROM information_schema.PLUGINS
		WHERE PLUGIN_TYPE = 'AUTHENTICATION' AND PLUGIN_STATUS = 'ACTIVE'`,
		func(rows *sql.Rows) error {
			var name string
			if err := rows.Scan(&name); err != nil {
				return err
			}
			plugins = append(plugins, name)
			return nil
		})
	if isAccessDenied(err) {
		return nil, nil
	}
	return plugins, err
}

// roleWarnings reports declared accounts that will accept logins without
// a password, and declared plugins the server has not loaded. plugins is
// nil when the loaded plugins are unknown.
func roleWarnings(desired *model.Desired, cur *model.Current, plugins []string) []string {
	if desired == nil {
		return nil
	}
	var warns []string
	for _, r := range desired.Roles {
		if r.AuthPlugin != "" && plugins != nil && !slices.ContainsFunc(plugins, func(p string) bool { return strings.EqualFold(p, r.AuthPlugin) }) {
			hint := ""
			if strings.EqualFold(r.AuthPlugin, password.PluginNative) {
				hint = " (MySQL 8.4 loads it only with --mysql-native-password=ON)"
			}
			warns = append(warns, fmt.Sprintf("auth_plugin %q of %q is not an active authentication plugin on the server%s; creating or changing the account will fail", r.AuthPlugin, r.ID, hint))
		}
		if r.Login == nil || !*r.Login || r.Password != nil || (r.AuthPlugin != "" && !isPasswordPlugin(r.AuthPlugin)) {
			continue
		}
		i := slices.IndexFunc(cur.Roles, func(s model.RoleState) bool { return s.ID == r.ID })
		if i < 0 || (cur.Roles[i].PasswordReadable && len(cur.Roles[i].PasswordHash) == 0 && isPasswordPlugin(cur.Roles[i].AuthPlugin)) {
			warns = append(warns, fmt.Sprintf("%q can log in without a password; declare a password or auth_plugin, or set login = false", r.ID))
		}
	}
	return warns
}

func (d *Driver) inspectDatabases(ctx context.Context, cur *model.Current) error {
	return query(ctx, d.db, `SELECT SCHEMA_NAME, DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME
		FROM information_schema.SCHEMATA ORDER BY SCHEMA_NAME`,
		func(rows *sql.Rows) error {
			var db model.Database
			if err := rows.Scan(&db.Name, &db.Charset, &db.Collation); err != nil {
				return err
			}
			cur.Databases = append(cur.Databases, db)
			return nil
		})
}

// MySQL error numbers that mean the connected user may not read a table.
var accessDeniedErrors = []uint16{
	1044, // ER_DBACCESS_DENIED_ERROR
	1142, // ER_TABLEACCESS_DENIED_ERROR
	1143, // ER_COLUMNACCESS_DENIED_ERROR
	1227, // ER_SPECIFIC_ACCESS_DENIED_ERROR
}

// errUnknownTable is ER_UNKNOWN_TABLE, returned for
// information_schema.USER_ATTRIBUTES before MySQL 8.0.21.
const errUnknownTable = 1109

// errUnknownSystemVariable is ER_UNKNOWN_SYSTEM_VARIABLE.
const errUnknownSystemVariable = 1193

func mysqlErrorIn(err error, numbers ...uint16) bool {
	var me *gomysql.MySQLError
	return errors.As(err, &me) && slices.Contains(numbers, me.Number)
}

func isAccessDenied(err error) bool { return mysqlErrorIn(err, accessDeniedErrors...) }

// inspectUsers reads accounts from mysql.user. Without access it falls
// back to information_schema.USER_ATTRIBUTES, which lists every account
// (but no credentials) for users with CREATE USER and SYSTEM_USER.
func (d *Driver) inspectUsers(ctx context.Context, cur *model.Current) error {
	err := d.inspectMySQLUser(ctx, cur)
	if !isAccessDenied(err) {
		return err
	}
	cur.Roles = nil
	cur.Unreadable.RoleAttributes = true
	var accounts []model.RoleID
	err = query(ctx, d.db, `SELECT USER, LOWER(HOST) FROM information_schema.USER_ATTRIBUTES ORDER BY USER, HOST`,
		func(rows *sql.Rows) error {
			var id model.RoleID
			if scanErr := rows.Scan(&id.Name, &id.Host); scanErr != nil {
				return scanErr
			}
			accounts = append(accounts, id)
			return nil
		})
	switch {
	case isAccessDenied(err) || mysqlErrorIn(err, errUnknownTable):
		cur.Unreadable.Roles = true
		return nil
	case err != nil:
		return err
	}
	for _, id := range accounts {
		cur.Roles = append(cur.Roles, model.RoleState{ID: id, AttributesUnknown: true})
	}
	cur.Unreadable.Roles = !listsAllAccounts(accounts)
	return nil
}

// listsAllAccounts reports whether USER_ATTRIBUTES showed every account.
// Without SYSTEM_USER, accounts holding it are hidden. The built-in
// mysql.sys, mysql.session and mysql.infoschema accounts hold it, so
// seeing one of them proves that nothing is hidden.
func listsAllAccounts(accounts []model.RoleID) bool {
	return slices.ContainsFunc(accounts, func(id model.RoleID) bool {
		return slices.Contains([]string{"mysql.sys", "mysql.session", "mysql.infoschema"}, id.Name)
	})
}

func (d *Driver) inspectMySQLUser(ctx context.Context, cur *model.Current) error {
	return query(ctx, d.db, `SELECT User, LOWER(Host), plugin, COALESCE(HEX(authentication_string), ''), account_locked
		FROM mysql.user ORDER BY User, Host`,
		func(rows *sql.Rows) error {
			var r model.RoleState
			var auth, locked string
			if err := rows.Scan(&r.ID.Name, &r.ID.Host, &r.AuthPlugin, &auth, &locked); err != nil {
				return err
			}
			hash, err := hex.DecodeString(auth)
			if err != nil {
				return fmt.Errorf("decode authentication_string of %s: %w", model.Account(r.ID), err)
			}
			r.PasswordHash = hash
			r.PasswordReadable = true
			r.Login = locked != "Y"
			cur.Roles = append(cur.Roles, r)
			return nil
		})
}

func (d *Driver) inspectRoleEdges(ctx context.Context, cur *model.Current) error {
	err := query(ctx, d.db, `SELECT FROM_USER, LOWER(FROM_HOST), TO_USER, LOWER(TO_HOST), WITH_ADMIN_OPTION FROM mysql.role_edges`,
		func(rows *sql.Rows) error {
			var role, member model.RoleID
			var admin string
			if err := rows.Scan(&role.Name, &role.Host, &member.Name, &member.Host, &admin); err != nil {
				return err
			}
			for i := range cur.Roles {
				r := &cur.Roles[i]
				if r.ID != member {
					continue
				}
				r.MemberOf = append(r.MemberOf, role)
				if r.MemberOptions == nil {
					r.MemberOptions = map[model.RoleID]model.MembershipState{}
				}
				// MySQL has no INHERIT or SET options; granted roles are
				// usable once active.
				r.MemberOptions[role] = model.MembershipState{Admin: admin == "Y", Inherit: true, Set: true}
			}
			return nil
		})
	if isAccessDenied(err) {
		for i := range cur.Roles {
			cur.Roles[i].MemberOf = nil
			cur.Roles[i].MemberOptions = nil
		}
		cur.Unreadable.Memberships = true
		return nil
	}
	return err
}

func (d *Driver) inspectDefaultRoles(ctx context.Context, cur *model.Current) error {
	err := query(ctx, d.db, `SELECT DEFAULT_ROLE_USER, LOWER(DEFAULT_ROLE_HOST), USER, LOWER(HOST) FROM mysql.default_roles`,
		func(rows *sql.Rows) error {
			var role, member model.RoleID
			if err := rows.Scan(&role.Name, &role.Host, &member.Name, &member.Host); err != nil {
				return err
			}
			for i := range cur.Roles {
				if cur.Roles[i].ID == member {
					cur.Roles[i].DefaultRoles = append(cur.Roles[i].DefaultRoles, role)
				}
			}
			return nil
		})
	if isAccessDenied(err) {
		for i := range cur.Roles {
			cur.Roles[i].DefaultRoles = nil
			cur.Roles[i].DefaultRolesUnknown = true
		}
		return nil
	}
	return err
}

// dbPrivilegeColumns maps mysql.db columns to privilege names.
var dbPrivilegeColumns = []struct{ column, name string }{
	{"Select_priv", "SELECT"}, {"Insert_priv", "INSERT"}, {"Update_priv", "UPDATE"}, {"Delete_priv", "DELETE"},
	{"Create_priv", "CREATE"}, {"Drop_priv", "DROP"}, {"References_priv", "REFERENCES"}, {"Index_priv", "INDEX"},
	{"Alter_priv", "ALTER"}, {"Create_tmp_table_priv", "CREATE TEMPORARY TABLES"}, {"Lock_tables_priv", "LOCK TABLES"},
	{"Create_view_priv", "CREATE VIEW"}, {"Show_view_priv", "SHOW VIEW"}, {"Create_routine_priv", "CREATE ROUTINE"},
	{"Alter_routine_priv", "ALTER ROUTINE"}, {"Execute_priv", "EXECUTE"}, {"Event_priv", "EVENT"}, {"Trigger_priv", "TRIGGER"},
}

// dbGrant is a row of mysql.db.
type dbGrant struct {
	grantee     model.RoleID
	db          string
	privs       []string
	grantOption bool
}

func (d *Driver) inspectDBPrivileges(ctx context.Context, cur *model.Current, desired *model.Desired) error {
	cols := make([]string, 0, len(dbPrivilegeColumns))
	for _, c := range dbPrivilegeColumns {
		cols = append(cols, c.column)
	}
	q := "SELECT User, LOWER(Host), Db, Grant_priv, " + strings.Join(cols, ", ") + " FROM mysql.db ORDER BY User, Host, Db"
	var rows []dbGrant
	err := query(ctx, d.db, q, func(r *sql.Rows) error {
		var g dbGrant
		var grantOpt string
		flags := make([]string, len(cols))
		dest := []any{&g.grantee.Name, &g.grantee.Host, &g.db, &grantOpt}
		for i := range flags {
			dest = append(dest, &flags[i])
		}
		if err := r.Scan(dest...); err != nil {
			return err
		}
		g.grantOption = grantOpt == "Y"
		for i, f := range flags {
			if f == "Y" {
				g.privs = append(g.privs, dbPrivilegeColumns[i].name)
			}
		}
		rows = append(rows, g)
		return nil
	})
	if isAccessDenied(err) {
		cur.Unreadable.Privileges = true
		return nil
	}
	if err != nil {
		return err
	}
	privs, warns := d.dbPrivileges(rows, desired)
	cur.Privileges = append(cur.Privileges, privs...)
	cur.Warnings = append(cur.Warnings, warns...)
	return nil
}

// dbPrivileges converts mysql.db rows to privileges. Unless partial_revokes
// is on, Db is a LIKE pattern: escaped rows name a literal database and
// rows with an unescaped wildcard are pattern grants. A pattern grant whose
// text equals a declared database (as written by GRANT ON `my_app`.*) keeps
// its Pattern, so it is revoked and replaced by an escaped grant.
func (d Dialect) dbPrivileges(rows []dbGrant, desired *model.Desired) ([]model.Privilege, []string) {
	if desired == nil {
		desired = &model.Desired{}
	}
	var out []model.Privilege
	var warns []string
	patterns := declaredPatterns(desired)
	for _, g := range rows {
		if p, ok := d.declaredPattern(g.db, patterns); ok {
			out = append(out, levelPrivileges(g, model.Object{Type: model.ObjectDatabase, Pattern: p}, desired)...)
			continue
		}
		obj := d.dbObject(g.db)
		obj.Database = d.declaredName(obj.Database, desired)
		if stale, ok := d.staleEscapedRow(g.db, desired); ok {
			obj = stale
		}
		if obj.Pattern != "" && !slices.ContainsFunc(desired.Databases, func(db model.Database) bool { return db.Name == obj.Database }) &&
			slices.ContainsFunc(desired.Roles, func(r model.Role) bool { return r.ID == g.grantee }) {
			for _, db := range desired.Databases {
				if matchPattern(obj.Pattern, db.Name) {
					warns = append(warns, fmt.Sprintf("%q holds privileges on the database pattern %q, which also matches declared database %q; undeclared pattern grants are not managed (declare it with database_pattern)", g.grantee, obj.Pattern, db.Name))
					break
				}
			}
		}
		out = append(out, levelPrivileges(g, obj, desired)...)
	}
	warns = append(warns, mixedGrantOptions(desired)...)
	return out, append(warns, shadowedPatterns(desired)...)
}

// declaredPatterns returns the database patterns of declared grants.
func declaredPatterns(desired *model.Desired) []string {
	if desired == nil {
		return nil
	}
	var out []string
	for _, p := range desired.Privileges {
		if p.Object.IsDeclaredPattern() && !slices.Contains(out, p.Object.Pattern) {
			out = append(out, p.Object.Pattern)
		}
	}
	return out
}

// declaredPattern returns the declared pattern a mysql.db row was granted
// on, in its declared spelling.
func (d Dialect) declaredPattern(raw string, patterns []string) (string, bool) {
	for _, p := range patterns {
		if p == raw || (d.CaseInsensitiveNames && strings.EqualFold(p, raw)) {
			return p, true
		}
	}
	return "", false
}

// shadowedPatterns warns about declared patterns that MySQL does not apply
// to some declared databases. Database level privileges are not added up:
// for an account, the server uses only the most specific mysql.db row that
// matches the database, so a literal grant (or another pattern) hides the
// pattern's privileges there.
func shadowedPatterns(desired *model.Desired) []string {
	type level struct {
		grantee model.RoleID
		obj     model.Object
	}
	var levels []level
	for _, p := range desired.Privileges {
		l := level{p.Grantee, p.Object}
		if !slices.Contains(levels, l) {
			levels = append(levels, l)
		}
	}
	var warns []string
	for _, l := range levels {
		if !l.obj.IsDeclaredPattern() {
			continue
		}
		for _, db := range desired.Databases {
			if !matchPattern(l.obj.Pattern, db.Name) {
				continue
			}
			for _, o := range levels {
				if o.grantee != l.grantee || o == l {
					continue
				}
				switch {
				case !o.obj.IsDeclaredPattern() && o.obj.Database == db.Name:
					warns = append(warns, fmt.Sprintf("%q has a grant on database %q, so MySQL ignores its grants on the matching database pattern %q there; list every privilege it needs on %q in the database grant",
						l.grantee, db.Name, l.obj.Pattern, db.Name))
				case o.obj.IsDeclaredPattern() && matchPattern(o.obj.Pattern, db.Name) && l.obj.Pattern < o.obj.Pattern:
					warns = append(warns, fmt.Sprintf("database patterns %q and %q of %q both match database %q; MySQL applies only one of them there",
						l.obj.Pattern, o.obj.Pattern, l.grantee, db.Name))
				}
			}
		}
	}
	return warns
}

// grantOptionPrivilege stands for a grant option that no declared
// privilege asks for. diff revokes it as REVOKE ..., GRANT OPTION.
const grantOptionPrivilege = "GRANT OPTION"

// levelPrivileges expands one mysql.db row. MySQL keeps a single grant
// option per (account, database), so it is compared at that level: when
// any declared privilege there has the grant option, the declared
// per-privilege values are reported; otherwise a held grant option shows
// up as grantOptionPrivilege, which is not declared and gets revoked.
func levelPrivileges(g dbGrant, obj model.Object, desired *model.Desired) []model.Privilege {
	declared := map[string]bool{}
	wantOption := false
	for _, p := range desired.Privileges {
		if p.Grantee == g.grantee && p.Object == obj {
			declared[p.Name] = p.GrantOption
			wantOption = wantOption || p.GrantOption
		}
	}
	out := make([]model.Privilege, 0, len(g.privs)+1)
	for _, name := range g.privs {
		opt := false
		if g.grantOption && wantOption {
			opt = true
			if d, ok := declared[name]; ok {
				opt = d
			}
		}
		out = append(out, model.Privilege{Grantee: g.grantee, Object: obj, Name: name, GrantOption: opt})
	}
	if g.grantOption && !wantOption {
		out = append(out, model.Privilege{Grantee: g.grantee, Object: obj, Name: grantOptionPrivilege})
	}
	return out
}

// mixedGrantOptions warns about declared levels that mix privileges with
// and without the grant option.
func mixedGrantOptions(desired *model.Desired) []string {
	type level struct {
		grantee model.RoleID
		obj     model.Object
	}
	seen := map[level]map[bool]bool{}
	var order []level
	for _, p := range desired.Privileges {
		l := level{p.Grantee, p.Object}
		if seen[l] == nil {
			seen[l] = map[bool]bool{}
			order = append(order, l)
		}
		seen[l][p.GrantOption] = true
	}
	var warns []string
	for _, l := range order {
		if seen[l][true] && seen[l][false] {
			warns = append(warns, fmt.Sprintf("MySQL keeps one grant option per database: %q can grant all of its privileges on %s, not only those declared with with_grant_option", l.grantee, targetLabel(l.obj)))
		}
	}
	return warns
}

// declaredName returns the declared spelling of an inspected database
// name when the server compares database names case-insensitively.
func (d Dialect) declaredName(name string, desired *model.Desired) string {
	if !d.CaseInsensitiveNames || desired == nil {
		return name
	}
	for _, db := range desired.Databases {
		if db.Name == name {
			return name
		}
	}
	for _, db := range desired.Databases {
		if strings.EqualFold(db.Name, name) {
			return db.Name
		}
	}
	return name
}

// dbObject classifies the Db column of mysql.db.
func (d Dialect) dbObject(raw string) model.Object {
	obj := model.Object{Type: model.ObjectDatabase, Database: raw}
	if d.PartialRevokes {
		return obj
	}
	var sb strings.Builder
	pattern := false
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case c == '\\' && i+1 < len(raw):
			i++
			sb.WriteByte(raw[i])
		case c == '_' || c == '%':
			pattern = true
			sb.WriteByte(c)
		default:
			sb.WriteByte(c)
		}
	}
	obj.Database = sb.String()
	if pattern {
		obj.Pattern = raw
	}
	return obj
}

// staleEscapedRow recognizes a row written with escaped wildcards while
// partial_revokes was off, such as my\_app for database my_app. With
// partial_revokes on, MySQL reads Db literally, so the row no longer
// covers the declared database. It is reported with the raw text as
// Pattern, so that diff revokes it (REVOKE ... ON `my\_app`.* removes
// the row) and grants on the literal name instead.
func (d Dialect) staleEscapedRow(raw string, desired *model.Desired) (model.Object, bool) {
	if !d.PartialRevokes || !strings.Contains(raw, `\`) {
		return model.Object{}, false
	}
	name := d.declaredName(Dialect{}.dbObject(raw).Database, desired)
	if !slices.ContainsFunc(desired.Databases, func(db model.Database) bool { return db.Name == name }) {
		return model.Object{}, false
	}
	return model.Object{Type: model.ObjectDatabase, Database: name, Pattern: raw}, true
}

// matchPattern reports whether name matches the database pattern p, in
// which _ and % are wildcards and a backslash escapes the next character.
// Patterns can come from the server, so failed states are memoized to
// keep runs of % from backtracking exponentially.
func matchPattern(p, name string) bool {
	failed := make([]bool, (len(p)+1)*(len(name)+1))
	var match func(i, j int) bool
	match = func(i, j int) bool {
		key := i*(len(name)+1) + j
		if failed[key] {
			return false
		}
		ok := matchStep(p, name, i, j, match)
		if !ok {
			failed[key] = true
		}
		return ok
	}
	return match(0, 0)
}

// matchStep matches p[i:] against name[j:], using match for the rest.
func matchStep(p, name string, i, j int, match func(i, j int) bool) bool {
	if i == len(p) {
		return j == len(name)
	}
	switch p[i] {
	case '%':
		// % matches nothing, or one more byte of name.
		return match(i+1, j) || (j < len(name) && match(i, j+1))
	case '_':
		if j == len(name) {
			return false
		}
		_, size := utf8.DecodeRuneInString(name[j:])
		return match(i+1, j+size)
	case '\\':
		if i+1 < len(p) {
			i++
		}
	}
	_, size := utf8.DecodeRuneInString(p[i:])
	return strings.HasPrefix(name[j:], p[i:i+size]) && match(i+size, j+size)
}

// targetLabel names a database level grant target in warnings.
func targetLabel(o model.Object) string {
	if o.Pattern != "" {
		return fmt.Sprintf("database pattern %q", o.Pattern)
	}
	return fmt.Sprintf("database %q", o.Database)
}

// escapeWildcards escapes the LIKE wildcards of a database name for
// database level grants.
func escapeWildcards(s string) string {
	return strings.NewReplacer(`\`, `\\`, "_", `\_`, "%", `\%`).Replace(s)
}

// grantTarget renders the target of a database level GRANT or REVOKE.
func (d Dialect) grantTarget(obj model.Object) string {
	switch {
	case obj.Pattern != "":
		return Ident(obj.Pattern) + ".*"
	case d.PartialRevokes:
		return Ident(obj.Database) + ".*"
	default:
		return Ident(escapeWildcards(obj.Database)) + ".*"
	}
}

func query(ctx context.Context, db *sql.DB, q string, scan func(*sql.Rows) error) error {
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		first, _, _ := strings.Cut(q, "\n")
		return fmt.Errorf("query %q: %w", first, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Dialect renders MySQL SQL. It is usable without a connection.
type Dialect struct {
	// NoBackslashEscapes reflects the NO_BACKSLASH_ESCAPES sql_mode.
	NoBackslashEscapes bool
	// PartialRevokes reflects partial_revokes. When it is off, _ and % in
	// database level grants are wildcards, so names are escaped.
	PartialRevokes bool
	// CaseInsensitiveNames is set when lower_case_table_names is not 0, so
	// the server stores or compares database names in lower case.
	CaseInsensitiveNames bool
}

// Ident quotes an identifier.
func Ident(s string) string { return "`" + strings.ReplaceAll(s, "`", "``") + "`" }

// Literal quotes a string literal.
func (d Dialect) Literal(s string) string {
	if !d.NoBackslashEscapes {
		s = strings.ReplaceAll(s, `\`, `\\`)
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// Account quotes 'user'@'host'.
func (d Dialect) Account(id model.RoleID) string {
	return d.Literal(id.Name) + "@" + d.Literal(id.Host)
}

// IsSystemRole implements diff.Dialect.
func (Dialect) IsSystemRole(id model.RoleID) bool {
	lower := strings.ToLower(id.Name)
	return slices.Contains([]string{"root", "mariadb.sys", "debian-sys-maint"}, id.Name) ||
		slices.ContainsFunc([]string{
			"mysql.", // mysql.sys, mysql.session, mysql.infoschema
			"rds",    // RDS: rdsadmin, rdsrepladmin, rdsproxyadmin, rds_superuser_role
			"aws_",   // Aurora: AWS_LOAD_S3_ACCESS, AWS_LAMBDA_ACCESS, ...
			"cloudsql", "azure_",
		}, func(p string) bool { return strings.HasPrefix(lower, p) })
}

// IsSystemDatabase implements diff.Dialect.
func (Dialect) IsSystemDatabase(name string) bool {
	return slices.Contains([]string{"mysql", "sys", "information_schema", "performance_schema", "ndbinfo"}, strings.ToLower(name))
}

// IsSystemSchema implements diff.Dialect. MySQL has no schemas inside databases.
func (Dialect) IsSystemSchema(string) bool { return true }

// Name renders a charset, collation or plugin name: bare when it is a
// plain word, quoted as an identifier otherwise.
func Name(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return r != '_' && (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z')
	}) < 0 {
		return s
	}
	return Ident(s)
}

// passwordPlugins are authentication plugins that verify a password.
// IDENTIFIED WITH one of them without BY sets an empty password.
var passwordPlugins = []string{password.PluginCachingSHA2, password.PluginNative, "sha256_password"}

func isPasswordPlugin(plugin string) bool {
	return slices.ContainsFunc(passwordPlugins, func(p string) bool { return strings.EqualFold(p, plugin) })
}

func (d Dialect) identified(plugin string, pw *string) []any {
	switch {
	case pw == nil && plugin == "":
		return nil
	case pw == nil:
		return []any{" IDENTIFIED WITH " + Name(plugin)}
	}
	clause := " IDENTIFIED"
	if plugin != "" {
		clause += " WITH " + Name(plugin)
	}
	return []any{clause + " BY ", plan.Secret(d.Literal(*pw))}
}

// CreateRole implements diff.Dialect. Non-login roles are locked accounts,
// which is what CREATE ROLE produces.
func (d Dialect) CreateRole(r model.Role) []plan.Statement {
	return d.createUser("CREATE USER ", r)
}

func (d Dialect) createUser(verb string, r model.Role) []plan.Statement {
	parts := []any{verb + d.Account(r.ID)}
	parts = append(parts, d.identified(r.AuthPlugin, r.Password)...)
	if r.Login != nil && !*r.Login {
		parts = append(parts, " ACCOUNT LOCK")
	}
	return []plan.Statement{plan.SQL("", parts...)}
}

// EnsureRole implements diff.Dialect. IF NOT EXISTS leaves an existing
// account, including its password and lock state, untouched.
func (d Dialect) EnsureRole(r model.Role) []plan.Statement {
	return d.createUser("CREATE USER IF NOT EXISTS ", r)
}

// AlterRole implements diff.Dialect.
func (d Dialect) AlterRole(r model.Role, cur model.RoleState, force bool) ([]plan.Statement, []string) {
	if cur.AttributesUnknown {
		// Nothing can be compared; only an explicitly forced password is set.
		if !force || r.Password == nil {
			return nil, nil
		}
		parts := append([]any{"ALTER USER " + d.Account(r.ID)}, d.identified(r.AuthPlugin, r.Password)...)
		return []plan.Statement{plan.SQL("", parts...)}, nil
	}
	var out []plan.Statement
	var warns []string
	plugin := cmpOr(r.AuthPlugin, cur.AuthPlugin)
	pluginChanged := r.AuthPlugin != "" && !strings.EqualFold(r.AuthPlugin, cur.AuthPlugin)
	identify := false
	switch {
	case r.Password == nil:
		switch {
		case !pluginChanged:
		case isPasswordPlugin(r.AuthPlugin):
			// Switching without BY would set an empty password.
			warns = append(warns, fmt.Sprintf("auth_plugin of %q is %s, not %s, but no password is declared; declare one to change the plugin", r.ID, cur.AuthPlugin, r.AuthPlugin))
		default:
			identify = true
		}
	case force, pluginChanged:
		identify = true
	default:
		ok, err := password.MatchMySQL(cur.AuthPlugin, cur.PasswordHash, *r.Password)
		switch {
		case err != nil:
			warns = append(warns, fmt.Sprintf("cannot compare the password of %q: %v; use --force-password to set it", r.ID, err))
		case !ok:
			identify = true
		}
	}
	if identify {
		parts := append([]any{"ALTER USER " + d.Account(r.ID)}, d.identified(plugin, r.Password)...)
		out = append(out, plan.SQL("", parts...))
	}
	if r.Login != nil && *r.Login != cur.Login {
		out = append(out, plan.SQL("", "ALTER USER "+d.Account(r.ID)+" ACCOUNT "+map[bool]string{true: "UNLOCK", false: "LOCK"}[*r.Login]))
	}
	return out, warns
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// DropRole implements diff.Dialect.
func (d Dialect) DropRole(id model.RoleID, _ []string) []plan.Statement {
	return []plan.Statement{plan.SQL("", "DROP USER "+d.Account(id))}
}

// GrantMembership implements diff.Dialect. SetDefaultRoles activates the role.
func (d Dialect) GrantMembership(member, role model.RoleID, opts model.MembershipOptions) ([]plan.Statement, []string) {
	return d.grantMembership(member, role, opts), nil
}

func (d Dialect) grantMembership(member, role model.RoleID, opts model.MembershipOptions) []plan.Statement {
	q := "GRANT " + d.Account(role) + " TO " + d.Account(member)
	if opts.Admin != nil && *opts.Admin {
		q += " WITH ADMIN OPTION"
	}
	return []plan.Statement{plan.SQL("", q)}
}

// AlterMembership implements diff.Dialect. MySQL cannot revoke only the
// ADMIN OPTION, so the role is revoked and granted again; that also
// removes it from the default roles, which SetDefaultRoles restores.
func (d Dialect) AlterMembership(member, role model.RoleID, want model.MembershipOptions, have model.MembershipState) ([]plan.Statement, []string) {
	if want.Admin == nil || *want.Admin == have.Admin {
		return nil, nil
	}
	if *want.Admin {
		return d.grantMembership(member, role, want), nil
	}
	return append(d.revokeMembership(member, role), d.grantMembership(member, role, want)...), nil
}

// losesAdmin reports whether AlterMembership revokes and grants role again
// to drop the ADMIN OPTION of r.
func losesAdmin(r model.Role, cur model.RoleState, role model.RoleID) bool {
	admin := r.MemberOptions[role].Admin
	return admin != nil && !*admin && cur.MemberOptions[role].Admin
}

// SetDefaultRoles implements diff.DefaultRoleSetter. Declared memberships
// are the default roles, so they are active without SET ROLE.
func (d Dialect) SetDefaultRoles(r model.Role, cur model.RoleState) []plan.Statement {
	want := model.SortRoleIDs(slices.Clone(r.MemberOf))
	have := model.SortRoleIDs(slices.DeleteFunc(slices.Clone(cur.DefaultRoles), func(id model.RoleID) bool {
		return losesAdmin(r, cur, id)
	}))
	if !cur.DefaultRolesUnknown && slices.Equal(want, have) {
		return nil
	}
	if len(want) == 0 {
		if cur.DefaultRolesUnknown {
			return nil
		}
		return []plan.Statement{plan.SQL("", "SET DEFAULT ROLE NONE TO "+d.Account(r.ID))}
	}
	roles := make([]string, 0, len(want))
	for _, id := range want {
		roles = append(roles, d.Account(id))
	}
	return []plan.Statement{plan.SQL("", "SET DEFAULT ROLE "+strings.Join(roles, ", ")+" TO "+d.Account(r.ID))}
}

// RevokeMembership implements diff.Dialect.
func (d Dialect) RevokeMembership(member, role model.RoleID) ([]plan.Statement, []string) {
	return d.revokeMembership(member, role), nil
}

func (d Dialect) revokeMembership(member, role model.RoleID) []plan.Statement {
	return []plan.Statement{plan.SQL("", "REVOKE "+d.Account(role)+" FROM "+d.Account(member))}
}

// CreateDatabase implements diff.Dialect.
func (Dialect) CreateDatabase(db model.Database) []plan.Statement {
	return []plan.Statement{plan.SQL("", "CREATE DATABASE "+Ident(db.Name)+charsetClause(db.Charset, db.Collation))}
}

func charsetClause(charset, collation string) string {
	var s string
	if charset != "" {
		s += " CHARACTER SET " + Name(charset)
	}
	if collation != "" {
		s += " COLLATE " + Name(collation)
	}
	return s
}

// canonicalCharset lower-cases a charset or collation name and resolves
// the utf8 alias, which MySQL stores as utf8mb3.
func canonicalCharset(s string) string {
	s = strings.ToLower(s)
	if s == "utf8" {
		return "utf8mb3"
	}
	if rest, ok := strings.CutPrefix(s, "utf8_"); ok {
		return "utf8mb3_" + rest
	}
	return s
}

// AlterDatabase implements diff.Dialect.
func (Dialect) AlterDatabase(db, cur model.Database) ([]plan.Statement, []string) {
	var charset, collation string
	if db.Charset != "" && canonicalCharset(db.Charset) != canonicalCharset(cur.Charset) {
		charset = db.Charset
	}
	if db.Collation != "" && canonicalCharset(db.Collation) != canonicalCharset(cur.Collation) {
		collation = db.Collation
	}
	if charset == "" && collation == "" {
		return nil, nil
	}
	return []plan.Statement{plan.SQL("", "ALTER DATABASE "+Ident(db.Name)+charsetClause(charset, collation))}, nil
}

// DropDatabase implements diff.Dialect.
func (Dialect) DropDatabase(name string) []plan.Statement {
	return []plan.Statement{plan.SQL("", "DROP DATABASE "+Ident(name))}
}

// CreateSchema implements diff.Dialect; schemas are rejected at load time.
func (Dialect) CreateSchema(model.Schema) []plan.Statement { return nil }

// AlterSchema implements diff.Dialect.
func (Dialect) AlterSchema(_, _ model.Schema) []plan.Statement { return nil }

// DropSchema implements diff.Dialect.
func (Dialect) DropSchema(model.Schema) []plan.Statement { return nil }

// Grant implements diff.Dialect.
func (d Dialect) Grant(grantee model.RoleID, obj model.Object, privs []string, grantOption bool) []plan.Statement {
	q := "GRANT " + strings.Join(privs, ", ") + " ON " + d.grantTarget(obj) + " TO " + d.Account(grantee)
	if grantOption {
		q += " WITH GRANT OPTION"
	}
	return []plan.Statement{plan.SQL("", q)}
}

// Revoke implements diff.Dialect.
func (d Dialect) Revoke(grantee model.RoleID, obj model.Object, privs []string) ([]plan.Statement, []string) {
	return []plan.Statement{plan.SQL("", "REVOKE "+strings.Join(privs, ", ")+" ON "+d.grantTarget(obj)+" FROM "+d.Account(grantee))}, nil
}

// RevokeGrantOption implements diff.Dialect. MySQL tracks the grant
// option per level, not per privilege.
func (d Dialect) RevokeGrantOption(grantee model.RoleID, obj model.Object, _ []string) ([]plan.Statement, []string) {
	return []plan.Statement{plan.SQL("", "REVOKE GRANT OPTION ON "+d.grantTarget(obj)+" FROM "+d.Account(grantee))}, nil
}
