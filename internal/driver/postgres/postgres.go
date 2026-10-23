// Package postgres implements the dbfence driver for PostgreSQL.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

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
	mu    sync.Mutex
}

// Open connects to dsn.
func Open(ctx context.Context, dsn string) (*Driver, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres dsn: %w", err)
	}
	db := stdlib.OpenDB(*cfg)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}
	return &Driver{cfg: cfg, db: db, conns: map[string]*sql.DB{}}, nil
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
		return nil, fmt.Errorf("connect to database %q: %w", database, err)
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
	_, err = c.ExecContext(ctx, query)
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

// Inspect implements driver.Driver.
func (d *Driver) Inspect(ctx context.Context, desired *model.Desired) (*model.Current, error) {
	cur := &model.Current{}
	var user string
	if err := d.db.QueryRowContext(ctx, "SELECT current_user").Scan(&user); err != nil {
		return nil, fmt.Errorf("current user: %w", err)
	}
	cur.CurrentUser = model.RoleID{Name: user}

	steps := []func(context.Context, *model.Current) error{d.inspectDatabases, d.inspectRoles, d.inspectMembership, d.inspectDatabaseACL}
	for _, step := range steps {
		if err := step(ctx, cur); err != nil {
			return nil, err
		}
	}
	for _, db := range desired.Databases {
		if !slices.ContainsFunc(cur.Databases, func(c model.Database) bool { return c.Name == db.Name }) {
			continue
		}
		if err := d.inspectSchemas(ctx, cur, db.Name); err != nil {
			return nil, err
		}
		cur.InspectedDatabases = append(cur.InspectedDatabases, db.Name)
	}
	return cur, nil
}

func (d *Driver) inspectDatabases(ctx context.Context, cur *model.Current) error {
	return query(ctx, d.db, `SELECT datname, pg_get_userbyid(datdba), pg_encoding_to_char(encoding), datcollate, datctype
		FROM pg_database WHERE NOT datistemplate AND datallowconn ORDER BY datname`,
		func(rows *sql.Rows) error {
			var db model.Database
			if err := rows.Scan(&db.Name, &db.Owner, &db.Encoding, &db.LcCollate, &db.LcCtype); err != nil {
				return err
			}
			cur.Databases = append(cur.Databases, db)
			return nil
		})
}

func (d *Driver) inspectRoles(ctx context.Context, cur *model.Current) error {
	if err := query(ctx, d.db, `SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolinherit,
			rolreplication, rolbypassrls, rolconnlimit
		FROM pg_roles ORDER BY rolname`,
		func(rows *sql.Rows) error {
			var r model.RoleState
			if err := rows.Scan(&r.ID.Name, &r.Login, &r.Superuser, &r.CreateDB, &r.CreateRole, &r.Inherit,
				&r.Replication, &r.BypassRLS, &r.ConnectionLimit); err != nil {
				return err
			}
			cur.Roles = append(cur.Roles, r)
			return nil
		}); err != nil {
		return err
	}
	// pg_authid is readable by superusers only; otherwise passwords
	// cannot be compared.
	verifiers := map[string]sql.NullString{}
	err := query(ctx, d.db, `SELECT rolname, rolpassword FROM pg_authid`, func(rows *sql.Rows) error {
		var name string
		var pw sql.NullString
		if scanErr := rows.Scan(&name, &pw); scanErr != nil {
			return scanErr
		}
		verifiers[name] = pw
		return nil
	})
	if pgErr := (*pgconn.PgError)(nil); errors.As(err, &pgErr) && pgErr.Code == sqlstateInsufficientPrivilege {
		// Expected on managed services where the admin is not a superuser.
		return nil
	}
	if err != nil {
		return err
	}
	for i := range cur.Roles {
		cur.Roles[i].PasswordReadable = true
		cur.Roles[i].PasswordHash = []byte(verifiers[cur.Roles[i].ID.Name].String)
	}
	return nil
}

func (d *Driver) inspectMembership(ctx context.Context, cur *model.Current) error {
	return query(ctx, d.db, `SELECT DISTINCT m.rolname, r.rolname
		FROM pg_auth_members am
		JOIN pg_roles r ON r.oid = am.roleid
		JOIN pg_roles m ON m.oid = am.member
		ORDER BY 1, 2`,
		func(rows *sql.Rows) error {
			var member, role string
			if err := rows.Scan(&member, &role); err != nil {
				return err
			}
			for i := range cur.Roles {
				if cur.Roles[i].ID.Name == member {
					cur.Roles[i].MemberOf = append(cur.Roles[i].MemberOf, model.RoleID{Name: role})
				}
			}
			return nil
		})
}

func (d *Driver) inspectDatabaseACL(ctx context.Context, cur *model.Current) error {
	return query(ctx, d.db, `SELECT d.datname, r.rolname, a.privilege_type, a.is_grantable
		FROM pg_database d
		CROSS JOIN LATERAL aclexplode(d.datacl) a
		JOIN pg_roles r ON r.oid = a.grantee
		WHERE NOT d.datistemplate AND d.datallowconn`,
		func(rows *sql.Rows) error {
			p := model.Privilege{Object: model.Object{Type: model.ObjectDatabase}}
			if err := rows.Scan(&p.Object.Database, &p.Grantee.Name, &p.Name, &p.GrantOption); err != nil {
				return err
			}
			cur.Privileges = append(cur.Privileges, p)
			return nil
		})
}

func (d *Driver) inspectSchemas(ctx context.Context, cur *model.Current, database string) error {
	c, err := d.conn(ctx, database)
	if err != nil {
		return err
	}
	if err := query(ctx, c, `SELECT nspname, pg_get_userbyid(nspowner) FROM pg_namespace
		WHERE nspname NOT LIKE 'pg\_%' AND nspname <> 'information_schema' ORDER BY nspname`,
		func(rows *sql.Rows) error {
			s := model.Schema{Database: database}
			if err := rows.Scan(&s.Name, &s.Owner); err != nil {
				return err
			}
			cur.Schemas = append(cur.Schemas, s)
			return nil
		}); err != nil {
		return err
	}
	return query(ctx, c, `SELECT n.nspname, r.rolname, a.privilege_type, a.is_grantable
		FROM pg_namespace n
		CROSS JOIN LATERAL aclexplode(n.nspacl) a
		JOIN pg_roles r ON r.oid = a.grantee
		WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'`,
		func(rows *sql.Rows) error {
			p := model.Privilege{Object: model.Object{Type: model.ObjectSchema, Database: database}}
			if err := rows.Scan(&p.Object.Schema, &p.Grantee.Name, &p.Name, &p.GrantOption); err != nil {
				return err
			}
			cur.Privileges = append(cur.Privileges, p)
			return nil
		})
}

func query(ctx context.Context, db *sql.DB, q string, scan func(*sql.Rows) error) error {
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return fmt.Errorf("query %q: %w", firstLine(q), err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return s
}

// Dialect renders PostgreSQL SQL. It is usable without a connection.
type Dialect struct{}

// Ident quotes an identifier.
func Ident(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// Literal quotes a string literal (standard_conforming_strings = on).
func Literal(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// IsSystemRole implements diff.Dialect.
func (Dialect) IsSystemRole(id model.RoleID) bool {
	n := id.Name
	return n == "postgres" || n == "rdsadmin" || n == "rdsrepladmin" ||
		hasAnyPrefix(n, "pg_", "rds_", "cloudsql", "azure_", "alloydb")
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
		parts = append(parts, " PASSWORD ", plan.Secret(Literal(*r.Password)))
	}
	return []plan.Statement{plan.SQL("", parts...)}
}

// EnsureRole implements diff.Dialect. pg_roles is always readable, so
// this is only a fallback; PostgreSQL has no CREATE ROLE IF NOT EXISTS.
func (d Dialect) EnsureRole(r model.Role) []plan.Statement { return d.CreateRole(r) }

// AlterRole implements diff.Dialect.
func (Dialect) AlterRole(r model.Role, cur model.RoleState, force bool) ([]plan.Statement, []string) {
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
		case !cur.PasswordReadable:
			warns = append(warns, fmt.Sprintf("cannot read the password verifier of role %q (superuser required); password not compared, use --force-password to set it", r.ID))
		default:
			ok, err := password.MatchPostgres(string(cur.PasswordHash), r.ID.Name, *r.Password)
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
		parts = append(parts, " PASSWORD ", plan.Secret(Literal(*r.Password)))
	}
	return []plan.Statement{plan.SQL("", parts...)}, warns
}

// DropRole implements diff.Dialect. Objects owned by the role are
// reassigned to the connected user in every surviving database.
func (Dialect) DropRole(id model.RoleID, databases []string) []plan.Statement {
	var out []plan.Statement
	for _, db := range databases {
		out = append(out,
			plan.SQL(db, "REASSIGN OWNED BY "+Ident(id.Name)+" TO CURRENT_USER"),
			plan.SQL(db, "DROP OWNED BY "+Ident(id.Name)),
		)
	}
	return append(out, plan.SQL("", "DROP ROLE "+Ident(id.Name)))
}

// GrantMembership implements diff.Dialect.
func (Dialect) GrantMembership(member, role model.RoleID) []plan.Statement {
	return []plan.Statement{plan.SQL("", "GRANT "+Ident(role.Name)+" TO "+Ident(member.Name))}
}

// RevokeMembership implements diff.Dialect.
func (Dialect) RevokeMembership(member, role model.RoleID) []plan.Statement {
	return []plan.Statement{plan.SQL("", "REVOKE "+Ident(role.Name)+" FROM "+Ident(member.Name))}
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

func normEncoding(s string) string { return strings.ToUpper(strings.ReplaceAll(s, "-", "")) }

// AlterDatabase implements diff.Dialect.
func (Dialect) AlterDatabase(db, cur model.Database) ([]plan.Statement, []string) {
	var warns []string
	immutable := func(attr, want, have string, eq func(a, b string) bool) {
		if want != "" && !eq(want, have) {
			warns = append(warns, fmt.Sprintf("database %q has %s %q but %q is declared; it cannot be changed after creation", db.Name, attr, have, want))
		}
	}
	immutable("encoding", db.Encoding, cur.Encoding, func(a, b string) bool { return normEncoding(a) == normEncoding(b) })
	immutable("lc_collate", db.LcCollate, cur.LcCollate, strings.EqualFold)
	immutable("lc_ctype", db.LcCtype, cur.LcCtype, strings.EqualFold)
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

// Grant implements diff.Dialect.
func (Dialect) Grant(grantee model.RoleID, obj model.Object, privs []string, grantOption bool) []plan.Statement {
	db, target := onObject(obj)
	q := "GRANT " + strings.Join(privs, ", ") + " ON " + target + " TO " + Ident(grantee.Name)
	if grantOption {
		q += " WITH GRANT OPTION"
	}
	return []plan.Statement{plan.SQL(db, q)}
}

// Revoke implements diff.Dialect.
func (Dialect) Revoke(grantee model.RoleID, obj model.Object, privs []string) []plan.Statement {
	db, target := onObject(obj)
	return []plan.Statement{plan.SQL(db, "REVOKE "+strings.Join(privs, ", ")+" ON "+target+" FROM "+Ident(grantee.Name))}
}

// RevokeGrantOption implements diff.Dialect.
func (Dialect) RevokeGrantOption(grantee model.RoleID, obj model.Object, privs []string) []plan.Statement {
	db, target := onObject(obj)
	return []plan.Statement{plan.SQL(db, "REVOKE GRANT OPTION FOR "+strings.Join(privs, ", ")+" ON "+target+" FROM "+Ident(grantee.Name))}
}
