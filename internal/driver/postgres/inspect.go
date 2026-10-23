package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/mazrean/dbfence/internal/model"
)

// SQLSTATEs that mean a database cannot be connected to.
const (
	sqlstateInvalidAuthorization = "28000"
	sqlstateInvalidCatalogName   = "3D000"
)

// pg16 is the server_version_num from which memberships record one row
// per grantor and carry INHERIT and SET options.
const pg16 = 160000

// state is what Inspect learned beyond model.Current.
type state struct {
	desired *model.Desired
	// connectable holds databases that statements may be run on.
	connectable map[string]bool
	// owners maps databases (Schema "") and inspected schemas to owners.
	owners map[model.Object]string
	// objects counts the objects in inspected schemas.
	objects map[model.Object]int
	roles   map[string]roleAccess
	// createroleSelfGrant is the createrole_self_grant setting (PG16+).
	createroleSelfGrant string
	user                string
	acl                 []aclEntry
	members             []memberEntry
	version             int
	superuser           bool
	createRole          bool
}

// roleAccess records what the connected user may do with a role.
type roleAccess struct {
	// admin: it holds ADMIN OPTION on the role.
	admin bool
	// use: it has the privileges of the role (REASSIGN/DROP OWNED).
	use bool
	// set: it may SET ROLE to the role (owner changes).
	set bool
	// superuser: the role is a superuser.
	superuser bool
}

// aclEntry is one aclexplode row.
type aclEntry struct {
	obj       model.Object
	grantee   string
	grantor   string
	priv      string
	grantable bool
}

// memberEntry is one pg_auth_members row.
type memberEntry struct {
	role, member, grantor string
	admin, inherit        bool
}

// Inspect implements driver.Driver.
func (d *Driver) Inspect(ctx context.Context, desired *model.Desired) (*model.Current, error) {
	st := &state{
		desired:     desired,
		connectable: map[string]bool{},
		owners:      map[model.Object]string{},
		objects:     map[model.Object]int{},
		roles:       map[string]roleAccess{},
	}
	cur := &model.Current{}
	var authidReadable bool
	if err := d.db.QueryRowContext(ctx, `SELECT current_user, current_database(),
			current_setting('server_version_num')::int,
			coalesce(current_setting('createrole_self_grant', true), ''),
			r.rolsuper, r.rolcreaterole, has_table_privilege('pg_catalog.pg_authid', 'SELECT')
		FROM pg_roles r WHERE r.rolname = current_user`).
		Scan(&st.user, &cur.CurrentDatabase, &st.version, &st.createroleSelfGrant, &st.superuser, &st.createRole, &authidReadable); err != nil {
		return nil, fmt.Errorf("current user: %w", err)
	}
	cur.CurrentUser = model.RoleID{Name: st.user}

	steps := []func(context.Context, *model.Current, *state) error{
		d.inspectDatabases, d.inspectRoles, d.inspectMembership, d.inspectDatabaseACL,
	}
	for _, step := range steps {
		if err := step(ctx, cur, st); err != nil {
			return nil, err
		}
	}
	if authidReadable {
		if err := d.inspectPasswords(ctx, cur); err != nil {
			return nil, err
		}
	}
	for _, db := range desired.Databases {
		if !slices.ContainsFunc(cur.Databases, func(c model.Database) bool { return c.Name == db.Name }) {
			continue
		}
		if !st.connectable[db.Name] {
			cur.Warnings = append(cur.Warnings, fmt.Sprintf("cannot connect to database %q (connections are disabled or not permitted): its schemas and schema privileges are not inspected", db.Name))
			continue
		}
		ok, err := d.inspectSchemas(ctx, cur, st, db.Name)
		if err != nil {
			return nil, err
		}
		if !ok {
			cur.Warnings = append(cur.Warnings, fmt.Sprintf("cannot connect to database %q: its schemas and schema privileges are not inspected", db.Name))
			delete(st.connectable, db.Name)
			continue
		}
		cur.InspectedDatabases = append(cur.InspectedDatabases, db.Name)
	}
	d.st = st
	return cur, nil
}

// providerDatabase reports databases reserved by PostgreSQL or a managed
// service, on which dbfence never runs statements. "postgres" is a normal
// maintenance database and may hold objects.
func providerDatabase(name string) bool {
	return (name != "postgres" && (Dialect{}).IsSystemDatabase(name)) || strings.HasPrefix(name, "template")
}

func (d *Driver) inspectDatabases(ctx context.Context, cur *model.Current, st *state) error {
	declared := func(name string) bool {
		return slices.ContainsFunc(st.desired.Databases, func(db model.Database) bool { return db.Name == name })
	}
	return query(ctx, d.db, `SELECT datname, pg_get_userbyid(datdba), pg_encoding_to_char(encoding), datcollate, datctype,
			datallowconn, datistemplate, has_database_privilege(oid, 'CONNECT')
		FROM pg_database ORDER BY datname`,
		func(rows *sql.Rows) error {
			var db model.Database
			var allowConn, template, canConnect bool
			if err := rows.Scan(&db.Name, &db.Owner, &db.Encoding, &db.LcCollate, &db.LcCtype, &allowConn, &template, &canConnect); err != nil {
				return err
			}
			// Templates and databases that refuse connections are only
			// reported when declared; otherwise they are not managed.
			if (!allowConn || template) && !declared(db.Name) {
				return nil
			}
			cur.Databases = append(cur.Databases, db)
			st.owners[model.Object{Type: model.ObjectDatabase, Database: db.Name}] = db.Owner
			if allowConn && canConnect && !providerDatabase(db.Name) {
				st.connectable[db.Name] = true
			}
			return nil
		})
}

func (d *Driver) inspectRoles(ctx context.Context, cur *model.Current, st *state) error {
	setPriv := "MEMBER"
	if st.version >= pg16 {
		setPriv = "SET"
	}
	return query(ctx, d.db, `SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolinherit,
			rolreplication, rolbypassrls, rolconnlimit,
			pg_has_role(oid, 'MEMBER WITH ADMIN OPTION'), pg_has_role(oid, 'USAGE'), pg_has_role(oid, '`+setPriv+`')
		FROM pg_roles ORDER BY rolname`,
		func(rows *sql.Rows) error {
			var r model.RoleState
			var a roleAccess
			if err := rows.Scan(&r.ID.Name, &r.Login, &r.Superuser, &r.CreateDB, &r.CreateRole, &r.Inherit,
				&r.Replication, &r.BypassRLS, &r.ConnectionLimit, &a.admin, &a.use, &a.set); err != nil {
				return err
			}
			a.superuser = r.Superuser
			st.roles[r.ID.Name] = a
			cur.Roles = append(cur.Roles, r)
			return nil
		})
}

// inspectPasswords reads verifiers. pg_authid is readable by superusers
// only; Inspect checks has_table_privilege first so that a failing query
// does not reach the server log.
func (d *Driver) inspectPasswords(ctx context.Context, cur *model.Current) error {
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

func (d *Driver) inspectMembership(ctx context.Context, cur *model.Current, st *state) error {
	inherit := "true"
	if st.version >= pg16 {
		inherit = "am.inherit_option"
	}
	return query(ctx, d.db, `SELECT m.rolname, r.rolname, coalesce(g.rolname, ''), am.admin_option, `+inherit+`
		FROM pg_auth_members am
		JOIN pg_roles r ON r.oid = am.roleid
		JOIN pg_roles m ON m.oid = am.member
		LEFT JOIN pg_roles g ON g.oid = am.grantor
		ORDER BY 1, 2, 3`,
		func(rows *sql.Rows) error {
			var e memberEntry
			if err := rows.Scan(&e.member, &e.role, &e.grantor, &e.admin, &e.inherit); err != nil {
				return err
			}
			st.members = append(st.members, e)
			for i := range cur.Roles {
				r := &cur.Roles[i]
				if r.ID.Name == e.member && !slices.Contains(r.MemberOf, model.RoleID{Name: e.role}) {
					r.MemberOf = append(r.MemberOf, model.RoleID{Name: e.role})
				}
			}
			return nil
		})
}

func (d *Driver) inspectDatabaseACL(ctx context.Context, cur *model.Current, st *state) error {
	listed := func(name string) bool {
		return slices.ContainsFunc(cur.Databases, func(db model.Database) bool { return db.Name == name })
	}
	return query(ctx, d.db, `SELECT d.datname, r.rolname, g.rolname, a.privilege_type, a.is_grantable
		FROM pg_database d
		CROSS JOIN LATERAL aclexplode(d.datacl) a
		JOIN pg_roles r ON r.oid = a.grantee
		JOIN pg_roles g ON g.oid = a.grantor
		ORDER BY 1, 2, 4, 3`,
		func(rows *sql.Rows) error {
			e := aclEntry{obj: model.Object{Type: model.ObjectDatabase}}
			if err := rows.Scan(&e.obj.Database, &e.grantee, &e.grantor, &e.priv, &e.grantable); err != nil {
				return err
			}
			if listed(e.obj.Database) {
				st.addACL(cur, e)
			}
			return nil
		})
}

// addACL records e and folds it into cur.Privileges: a privilege is held
// when any grantor granted it, and grantable when any grantor granted it
// WITH GRANT OPTION.
func (st *state) addACL(cur *model.Current, e aclEntry) {
	st.acl = append(st.acl, e)
	p := model.Privilege{Grantee: model.RoleID{Name: e.grantee}, Object: e.obj, Name: e.priv, GrantOption: e.grantable}
	for i := range cur.Privileges {
		if cur.Privileges[i].Key() == p.Key() {
			cur.Privileges[i].GrantOption = cur.Privileges[i].GrantOption || p.GrantOption
			return
		}
	}
	cur.Privileges = append(cur.Privileges, p)
}

// inspectSchemas reads the schemas of database. It reports false when the
// database cannot be connected to.
func (d *Driver) inspectSchemas(ctx context.Context, cur *model.Current, st *state, database string) (bool, error) {
	c, err := d.conn(ctx, database)
	if pgErr := (*pgconn.PgError)(nil); errors.As(err, &pgErr) &&
		slices.Contains([]string{sqlstateInsufficientPrivilege, sqlstateInvalidAuthorization, sqlstateInvalidCatalogName}, pgErr.Code) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := query(ctx, c, `SELECT n.nspname, pg_get_userbyid(n.nspowner),
			(SELECT count(*) FROM pg_class WHERE relnamespace = n.oid)
			+ (SELECT count(*) FROM pg_proc WHERE pronamespace = n.oid)
			+ (SELECT count(*) FROM pg_type WHERE typnamespace = n.oid AND typrelid = 0 AND typelem = 0)
		FROM pg_namespace n
		WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema' ORDER BY n.nspname`,
		func(rows *sql.Rows) error {
			s := model.Schema{Database: database}
			var objects int
			if err := rows.Scan(&s.Name, &s.Owner, &objects); err != nil {
				return err
			}
			cur.Schemas = append(cur.Schemas, s)
			obj := model.Object{Type: model.ObjectSchema, Database: database, Schema: s.Name}
			st.owners[obj] = s.Owner
			st.objects[obj] = objects
			return nil
		}); err != nil {
		return false, err
	}
	return true, query(ctx, c, `SELECT n.nspname, r.rolname, g.rolname, a.privilege_type, a.is_grantable
		FROM pg_namespace n
		CROSS JOIN LATERAL aclexplode(n.nspacl) a
		JOIN pg_roles r ON r.oid = a.grantee
		JOIN pg_roles g ON g.oid = a.grantor
		WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
		ORDER BY 1, 2, 4, 3`,
		func(rows *sql.Rows) error {
			e := aclEntry{obj: model.Object{Type: model.ObjectSchema, Database: database}}
			if err := rows.Scan(&e.obj.Schema, &e.grantee, &e.grantor, &e.priv, &e.grantable); err != nil {
				return err
			}
			st.addACL(cur, e)
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
