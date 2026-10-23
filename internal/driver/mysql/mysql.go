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

	gomysql "github.com/go-sql-driver/mysql"
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
	if _, err := gomysql.ParseDSN(dsn); err != nil {
		return nil, fmt.Errorf("parse mysql dsn: %w", err)
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	// A single connection keeps session state such as sql_mode stable.
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect to mysql: %w", err)
	}
	var mode string
	if err := db.QueryRowContext(ctx, "SELECT @@SESSION.sql_mode").Scan(&mode); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("read sql_mode: %w", err)
	}
	d := &Driver{db: db}
	d.NoBackslashEscapes = strings.Contains(mode, "NO_BACKSLASH_ESCAPES")
	return d, nil
}

// Exec implements driver.Driver.
func (d *Driver) Exec(ctx context.Context, _, query string) error {
	_, err := d.db.ExecContext(ctx, query)
	return err
}

// Close implements driver.Driver.
func (d *Driver) Close() error { return d.db.Close() }

// Inspect implements driver.Driver.
func (d *Driver) Inspect(ctx context.Context, _ *model.Desired) (*model.Current, error) {
	cur := &model.Current{}
	var user string
	if err := d.db.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&user); err != nil {
		return nil, fmt.Errorf("current user: %w", err)
	}
	if name, host, ok := strings.CutLast(user, "@"); ok {
		cur.CurrentUser = model.RoleID{Name: name, Host: host}
	}
	for _, step := range []func(context.Context, *model.Current) error{d.inspectDatabases, d.inspectUsers, d.inspectRoleEdges, d.inspectDBPrivileges} {
		if err := step(ctx, cur); err != nil {
			return nil, err
		}
	}
	return cur, nil
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
	err = query(ctx, d.db, `SELECT USER, HOST FROM information_schema.USER_ATTRIBUTES ORDER BY USER, HOST`,
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
	// Without full visibility only the current account is listed. Every
	// server also has system accounts such as mysql.sys, so seeing any
	// other account proves the list is complete.
	if !slices.ContainsFunc(accounts, func(id model.RoleID) bool { return id != cur.CurrentUser }) {
		cur.Unreadable.Roles = true
		return nil
	}
	for _, id := range accounts {
		cur.Roles = append(cur.Roles, model.RoleState{ID: id, AttributesUnknown: true})
	}
	return nil
}

func (d *Driver) inspectMySQLUser(ctx context.Context, cur *model.Current) error {
	return query(ctx, d.db, `SELECT User, Host, plugin, HEX(authentication_string), account_locked
		FROM mysql.user ORDER BY User, Host`,
		func(rows *sql.Rows) error {
			var r model.RoleState
			var auth, locked string
			if err := rows.Scan(&r.ID.Name, &r.ID.Host, &r.AuthPlugin, &auth, &locked); err != nil {
				return err
			}
			hash, err := hex.DecodeString(auth)
			if err != nil {
				return fmt.Errorf("decode authentication_string of %s: %w", r.ID, err)
			}
			r.PasswordHash = hash
			r.PasswordReadable = true
			r.Login = locked != "Y"
			cur.Roles = append(cur.Roles, r)
			return nil
		})
}

func (d *Driver) inspectRoleEdges(ctx context.Context, cur *model.Current) error {
	err := query(ctx, d.db, `SELECT FROM_USER, FROM_HOST, TO_USER, TO_HOST FROM mysql.role_edges`,
		func(rows *sql.Rows) error {
			var role, member model.RoleID
			if err := rows.Scan(&role.Name, &role.Host, &member.Name, &member.Host); err != nil {
				return err
			}
			for i := range cur.Roles {
				if cur.Roles[i].ID == member {
					cur.Roles[i].MemberOf = append(cur.Roles[i].MemberOf, role)
				}
			}
			return nil
		})
	if isAccessDenied(err) {
		for i := range cur.Roles {
			cur.Roles[i].MemberOf = nil
		}
		cur.Unreadable.Memberships = true
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

func (d *Driver) inspectDBPrivileges(ctx context.Context, cur *model.Current) error {
	cols := make([]string, 0, len(dbPrivilegeColumns))
	for _, c := range dbPrivilegeColumns {
		cols = append(cols, c.column)
	}
	q := "SELECT User, Host, Db, Grant_priv, " + strings.Join(cols, ", ") + " FROM mysql.db"
	err := query(ctx, d.db, q, func(rows *sql.Rows) error {
		var grantee model.RoleID
		var db, grantOpt string
		flags := make([]string, len(cols))
		dest := []any{&grantee.Name, &grantee.Host, &db, &grantOpt}
		for i := range flags {
			dest = append(dest, &flags[i])
		}
		if err := rows.Scan(dest...); err != nil {
			return err
		}
		for i, f := range flags {
			if f == "Y" {
				cur.Privileges = append(cur.Privileges, model.Privilege{
					Grantee: grantee, Object: model.Object{Type: model.ObjectDatabase, Database: db},
					Name: dbPrivilegeColumns[i].name, GrantOption: grantOpt == "Y",
				})
			}
		}
		return nil
	})
	if isAccessDenied(err) {
		cur.Privileges = nil
		cur.Unreadable.Privileges = true
		return nil
	}
	return err
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
	return slices.Contains([]string{"root", "mysql.sys", "mysql.session", "mysql.infoschema", "mariadb.sys", "rdsadmin", "rdsrepladmin", "debian-sys-maint"}, id.Name) ||
		strings.HasPrefix(id.Name, "cloudsql") || strings.HasPrefix(id.Name, "azure_")
}

// IsSystemDatabase implements diff.Dialect.
func (Dialect) IsSystemDatabase(name string) bool {
	return slices.Contains([]string{"mysql", "sys", "information_schema", "performance_schema", "ndbinfo"}, strings.ToLower(name))
}

// IsSystemSchema implements diff.Dialect. MySQL has no schemas inside databases.
func (Dialect) IsSystemSchema(string) bool { return true }

func (d Dialect) identified(plugin string, pw *string) []any {
	if pw == nil {
		return nil
	}
	clause := " IDENTIFIED"
	if plugin != "" {
		clause += " WITH " + plugin
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
	pluginChanged := r.AuthPlugin != "" && r.AuthPlugin != cur.AuthPlugin
	setPassword := false
	switch {
	case r.Password == nil:
		if pluginChanged {
			warns = append(warns, fmt.Sprintf("auth_plugin of %q differs (%s) but no password is declared; it cannot be changed", r.ID, cur.AuthPlugin))
		}
	case force, pluginChanged:
		setPassword = true
	default:
		ok, err := password.MatchMySQL(cur.AuthPlugin, cur.PasswordHash, *r.Password)
		switch {
		case err != nil:
			warns = append(warns, fmt.Sprintf("cannot compare the password of %q: %v; use --force-password to set it", r.ID, err))
		case !ok:
			setPassword = true
		}
	}
	if setPassword {
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

// GrantMembership implements diff.Dialect. Granted roles are activated by default.
func (d Dialect) GrantMembership(member, role model.RoleID) []plan.Statement {
	return []plan.Statement{
		plan.SQL("", "GRANT "+d.Account(role)+" TO "+d.Account(member)),
		plan.SQL("", "SET DEFAULT ROLE ALL TO "+d.Account(member)),
	}
}

// RevokeMembership implements diff.Dialect.
func (d Dialect) RevokeMembership(member, role model.RoleID) []plan.Statement {
	return []plan.Statement{plan.SQL("", "REVOKE "+d.Account(role)+" FROM "+d.Account(member))}
}

// CreateDatabase implements diff.Dialect.
func (Dialect) CreateDatabase(db model.Database) []plan.Statement {
	return []plan.Statement{plan.SQL("", "CREATE DATABASE "+Ident(db.Name)+charsetClause(db.Charset, db.Collation))}
}

func charsetClause(charset, collation string) string {
	var s string
	if charset != "" {
		s += " CHARACTER SET " + charset
	}
	if collation != "" {
		s += " COLLATE " + collation
	}
	return s
}

// AlterDatabase implements diff.Dialect.
func (Dialect) AlterDatabase(db, cur model.Database) ([]plan.Statement, []string) {
	var charset, collation string
	if db.Charset != "" && !strings.EqualFold(db.Charset, cur.Charset) {
		charset = db.Charset
	}
	if db.Collation != "" && !strings.EqualFold(db.Collation, cur.Collation) {
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
	q := "GRANT " + strings.Join(privs, ", ") + " ON " + Ident(obj.Database) + ".* TO " + d.Account(grantee)
	if grantOption {
		q += " WITH GRANT OPTION"
	}
	return []plan.Statement{plan.SQL("", q)}
}

// Revoke implements diff.Dialect.
func (d Dialect) Revoke(grantee model.RoleID, obj model.Object, privs []string) []plan.Statement {
	return []plan.Statement{plan.SQL("", "REVOKE "+strings.Join(privs, ", ")+" ON "+Ident(obj.Database)+".* FROM "+d.Account(grantee))}
}

// RevokeGrantOption implements diff.Dialect. MySQL tracks the grant
// option per level, not per privilege.
func (d Dialect) RevokeGrantOption(grantee model.RoleID, obj model.Object, _ []string) []plan.Statement {
	return []plan.Statement{plan.SQL("", "REVOKE GRANT OPTION ON "+Ident(obj.Database)+".* FROM "+d.Account(grantee))}
}
