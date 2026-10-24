package postgres

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
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
	// otherOwners maps the schemas of other databases (see
	// inspectSchemaOwners) to owners.
	otherOwners map[model.Object]string
	// otherACL holds the schema privileges of those databases. Unlike
	// acl, it is only used to keep roles from --prune.
	otherACL []aclEntry
	// shared holds the dependencies of roles on shared objects
	// (pg_shdepend with dbid 0), which REASSIGN OWNED and DROP OWNED
	// change from any database.
	shared []sharedDep
	// objects counts the objects in inspected schemas.
	objects map[model.Object]int
	roles   map[string]roleAccess
	// createroleSelfGrant is the createrole_self_grant setting (PG16+).
	createroleSelfGrant string
	user                string
	// database is the database the connection is to.
	database string
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

// sharedDep is a dependency of role on a shared object: class is its
// catalog (pg_database, pg_tablespace, ...), name the database or
// tablespace name ("" for other catalogs).
type sharedDep struct {
	role, class, name string
}

// memberEntry is one pg_auth_members row.
type memberEntry struct {
	role, member, grantor string
	admin, inherit, set   bool
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
		Scan(&st.user, &st.database, &st.version, &st.createroleSelfGrant, &st.superuser, &st.createRole, &authidReadable); err != nil {
		return nil, fmt.Errorf("current user: %w", err)
	}
	cur.CurrentUser = model.RoleID{Name: st.user}
	cur.CurrentDatabase = st.database
	warns, err := checkMembershipOptions(desired, st.version)
	if err != nil {
		return nil, err
	}
	cur.Warnings = append(cur.Warnings, warns...)

	steps := []func(context.Context, *model.Current, *state) error{
		d.inspectDatabases, d.inspectRoles, d.inspectMembership, d.inspectDatabaseACL, d.inspectSharedDependencies,
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
	} else if w := unreadableVerifiersWarning(desired, cur); w != "" {
		cur.Warnings = append(cur.Warnings, w)
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
	// Pruning a role runs REASSIGN OWNED and DROP OWNED in the other
	// databases too, and pruning one of them drops its schemas, so their
	// schemas are read.
	for _, db := range otherSchemaDatabases(desired, cur, st.connectable) {
		ok, err := d.inspectSchemaOwners(ctx, cur, st, db)
		if err != nil {
			return nil, err
		}
		if !ok {
			cur.Warnings = append(cur.Warnings, fmt.Sprintf("cannot connect to database %q: owners of and privileges on its schemas are not known, so --prune does not run REASSIGN OWNED and DROP OWNED there", db))
			delete(st.connectable, db)
		}
	}
	st.entangleUnread(cur)
	st.otherOwners = map[model.Object]string{}
	for _, s := range cur.OtherSchemas {
		st.otherOwners[model.Object{Type: model.ObjectSchema, Database: s.Database, Schema: s.Name}] = s.Owner
	}
	// Names read from the server are untrusted: objects dbfence would
	// have to name but does not manage are left out from here on.
	if _, err := cur.DropUntrusted(model.EnginePostgres); err != nil {
		return nil, fmt.Errorf("inspect: %w", err)
	}
	cur.Warnings = append(cur.Warnings, st.unmanagedOwnerMembershipWarnings(cur)...)
	if !st.superuser {
		cur.Warnings = append(cur.Warnings, st.ownerWarnings(cur)...)
		cur.Warnings = append(cur.Warnings, st.pruneWarnings(cur)...)
	}
	depWarns, depErr := d.unreachableDependencyWarnings(ctx, cur, st)
	if depErr != nil {
		return nil, depErr
	}
	cur.Warnings = append(cur.Warnings, depWarns...)
	d.st = st
	return cur, nil
}

// unreadableVerifiersWarning names, in one warning, the existing declared
// roles whose password cannot be compared because pg_authid is not
// readable. Driver.AlterRole leaves the per-role warning out.
func unreadableVerifiersWarning(desired *model.Desired, cur *model.Current) string {
	var names []string
	for _, r := range desired.Roles {
		if r.Password != nil && slices.ContainsFunc(cur.Roles, func(c model.RoleState) bool { return c.ID.Name == r.ID.Name }) {
			names = append(names, strconv.Quote(r.ID.Name))
		}
	}
	if len(names) == 0 {
		return ""
	}
	slices.Sort(names)
	noun := "role"
	if len(names) > 1 {
		noun = "roles"
	}
	return fmt.Sprintf("cannot read the password verifiers of existing %s %s (superuser required): their passwords are not compared and are set only with --force-password",
		noun, strings.Join(names, ", "))
}

// checkMembershipOptions rejects inherit and set membership options
// before PostgreSQL 16, and warns where a membership's inherit option
// disagrees with the inherit attribute of its member.
func checkMembershipOptions(desired *model.Desired, version int) ([]string, error) {
	var warns []string
	for _, r := range desired.Roles {
		for _, m := range r.MemberOf {
			o := r.MemberOptions[m]
			if version < pg16 && (o.Inherit != nil || o.Set != nil) {
				return nil, fmt.Errorf("membership of %q in %q declares inherit or set, which need PostgreSQL 16 or later (server_version_num %d)", r.ID, m, version)
			}
			if o.Inherit != nil && r.Inherit != nil && *o.Inherit != *r.Inherit {
				warns = append(warns, fmt.Sprintf("membership of %q in %q declares inherit = %v, but the role has inherit = %v: the membership option wins, and the role's inherit only applies to its other memberships", r.ID, m, *o.Inherit, *r.Inherit))
			}
		}
	}
	return warns, nil
}

// canSet reports whether the connected user may make role an owner:
// CREATE DATABASE ... OWNER, ALTER ... OWNER TO and CREATE SCHEMA ...
// AUTHORIZATION need SET ROLE on it (membership before PostgreSQL 16).
func (st *state) canSet(role string) bool {
	if st.superuser || role == st.user {
		return true
	}
	if a, ok := st.roles[role]; ok {
		return a.set
	}
	// Created by the plan: PostgreSQL 16+ grants the creator SET only
	// when createrole_self_grant includes it.
	return st.version >= pg16 && slices.Contains(strings.Split(strings.ReplaceAll(st.createroleSelfGrant, " ", ""), ","), "set")
}

// canUse reports whether the connected user has the privileges of role,
// which creating schemas in a database it owns and granting on objects it
// owns need (USAGE: membership with INHERIT).
func (st *state) canUse(role string) bool {
	if st.superuser || role == st.user {
		return true
	}
	if a, ok := st.roles[role]; ok {
		return a.use
	}
	// Created by the plan: PostgreSQL 16+ grants the creator INHERIT only
	// when createrole_self_grant includes it.
	return st.version >= pg16 && slices.Contains(strings.Split(strings.ReplaceAll(st.createroleSelfGrant, " ", ""), ","), "inherit")
}

// ownerWarnings warns about owner changes the connected user cannot make,
// and about schemas and grants it cannot create on objects of an owner
// whose privileges it does not have.
func (st *state) ownerWarnings(cur *model.Current) []string {
	var warns []string
	check := func(obj model.Object, what, owner, have string, needsOwner bool) {
		effective := cmp.Or(owner, have)
		set := owner != "" && owner != have && !st.canSet(owner)
		use := needsOwner && effective != "" && !st.canUse(effective)
		if !set && !use {
			return
		}
		fix := "run " + st.memberGrant(effective, set, use) + " first"
		switch {
		case set && use:
			warns = append(warns, fmt.Sprintf("%s: %q cannot SET ROLE %q or use its privileges, so making it the owner and %s will fail; %s",
				what, st.user, effective, ownerActions(obj), fix))
		case set:
			warns = append(warns, fmt.Sprintf("%s: %q cannot SET ROLE %q, so making it the owner will fail; %s", what, st.user, owner, fix))
		default:
			warns = append(warns, fmt.Sprintf("%s: %q does not have the privileges of its owner %q, so %s will fail; %s",
				what, st.user, effective, ownerActions(obj), fix))
		}
	}
	for _, db := range st.desired.Databases {
		have := ""
		if i := slices.IndexFunc(cur.Databases, func(c model.Database) bool { return c.Name == db.Name }); i >= 0 {
			have = cur.Databases[i].Owner
		}
		obj := model.Object{Type: model.ObjectDatabase, Database: db.Name}
		needsOwner := st.plansGrants(obj, cmp.Or(db.Owner, have)) || slices.ContainsFunc(st.desired.Schemas, func(s model.Schema) bool {
			return s.Database == db.Name && st.createsSchema(s)
		})
		check(obj, fmt.Sprintf("database %q", db.Name), db.Owner, have, needsOwner)
	}
	for _, s := range st.desired.Schemas {
		obj := model.Object{Type: model.ObjectSchema, Database: s.Database, Schema: s.Name}
		have := st.owners[obj]
		check(obj, fmt.Sprintf("schema %q in database %q", s.Name, s.Database), s.Owner, have, st.plansGrants(obj, cmp.Or(s.Owner, have)))
	}
	return warns
}

// ownerActions names what needs the privileges of the owner of obj.
func ownerActions(obj model.Object) string {
	if obj.Type == model.ObjectSchema {
		return "granting on it"
	}
	return "creating schemas in it or granting on it"
}

// memberGrant renders the GRANT that lets the connected user SET ROLE to
// role (set) and use its privileges (use). Before PostgreSQL 16 plain
// membership gives both.
func (st *state) memberGrant(role string, set, use bool) string {
	q := "GRANT " + Ident(role).String() + " TO " + Ident(st.user).String()
	if st.version < pg16 {
		return q
	}
	switch {
	case set && use:
		return q + " WITH INHERIT TRUE, SET TRUE"
	case set:
		return q + " WITH SET TRUE, INHERIT FALSE"
	default:
		return q + " WITH INHERIT TRUE"
	}
}

// createsSchema reports whether the plan creates s, which needs CREATE on
// its database. Schemas of databases that were not inspected are created
// unless they are system schemas copied from the template.
func (st *state) createsSchema(s model.Schema) bool {
	_, exists := st.owners[model.Object{Type: model.ObjectSchema, Database: s.Database, Schema: s.Name}]
	return !exists && !(Dialect{}).IsSystemSchema(s.Name)
}

// plansGrants reports whether a declared privilege on obj, owned by owner,
// is not held yet, so that the plan grants it.
func (st *state) plansGrants(obj model.Object, owner string) bool {
	return slices.ContainsFunc(st.desired.Privileges, func(p model.Privilege) bool {
		return p.Object == obj && p.Grantee.Name != owner && !slices.ContainsFunc(st.acl, func(e aclEntry) bool {
			return e.obj == obj && e.grantee == p.Grantee.Name && e.priv == p.Name && (e.grantable || !p.GrantOption)
		})
	})
}

// pruneWarnings warns about unmanaged roles whose objects the connected
// user may not reassign, so that --prune would fail on them.
func (st *state) pruneWarnings(cur *model.Current) []string {
	ignore := compileIgnore(st.desired.Ignore.Roles)
	var warns []string
	for _, r := range cur.Roles {
		name := r.ID.Name
		if name == st.user || st.roles[name].use || (Dialect{}).IsSystemRole(r.ID) ||
			slices.ContainsFunc(st.desired.Roles, func(d model.Role) bool { return d.ID == r.ID }) ||
			slices.ContainsFunc(ignore, func(re *regexp.Regexp) bool { return re.MatchString(name) }) {
			continue
		}
		warns = append(warns, fmt.Sprintf("role %q: %q does not have its privileges, so dropping it with --prune will fail at REASSIGN OWNED; run GRANT %s TO %s first",
			name, st.user, Ident(name), Ident(st.user)))
	}
	for _, r := range cur.Roles {
		name := r.ID.Name
		if !st.prunable(name, ignore) {
			continue
		}
		for _, e := range st.ownerMemberships(name) {
			if !st.canManageMembership(e.role, e.grantor) {
				warns = append(warns, fmt.Sprintf("role %q granted privileges on objects whose owner's privileges it has through its membership in %q, which %q may not revoke, so dropping it with --prune will fail at DROP ROLE",
					name, e.role, st.user))
			}
		}
		warns = append(warns, st.pruneRegrantWarnings(name)...)
	}
	return warns
}

// pruneRegrantWarnings names the declared memberships that dropping role
// revokes (those it granted, PostgreSQL 16+) and that the connected user
// may not grant again.
func (st *state) pruneRegrantWarnings(role string) []string {
	if st.version < pg16 {
		return nil
	}
	var granted, warns []string
	for _, e := range st.members {
		if e.grantor != role || slices.Contains(granted, e.role) {
			continue
		}
		granted = append(granted, e.role)
		if st.canManageMembership(e.role, st.user) {
			continue
		}
		id := model.RoleID{Name: e.role}
		for _, dep := range st.memberDependents(role, e.role) {
			if slices.ContainsFunc(st.desired.Roles, func(r model.Role) bool { return r.ID.Name == dep && slices.Contains(r.MemberOf, id) }) {
				warns = append(warns, fmt.Sprintf("role %q: dropping it with --prune revokes the declared membership of %q in %q that it granted, and %q may not grant it again (it needs ADMIN OPTION on the role)",
					role, dep, e.role, st.user))
			}
		}
	}
	return warns
}

// prunable reports whether --prune may drop the inspected role name: it
// is not the connected user, a system role, declared or ignored.
func (st *state) prunable(name string, ignore []*regexp.Regexp) bool {
	return name != st.user && !(Dialect{}).IsSystemRole(model.RoleID{Name: name}) &&
		!slices.ContainsFunc(st.desired.Roles, func(d model.Role) bool { return d.ID.Name == name }) &&
		!slices.ContainsFunc(ignore, func(re *regexp.Regexp) bool { return re.MatchString(name) })
}

// unreachableDependencyWarnings warns about unmanaged roles that own
// objects or hold privileges (pg_shdepend) in databases where DropRole
// does not run REASSIGN OWNED and DROP OWNED: databases dbfence cannot
// connect to, and ignored ones. DROP ROLE would fail on them.
func (d *Driver) unreachableDependencyWarnings(ctx context.Context, cur *model.Current, st *state) ([]string, error) {
	ignoreRoles := compileIgnore(st.desired.Ignore.Roles)
	ignoreDBs := compileIgnore(st.desired.Ignore.Databases)
	matches := func(res []*regexp.Regexp, s string) bool {
		return slices.ContainsFunc(res, func(re *regexp.Regexp) bool { return re.MatchString(s) })
	}
	prunable := func(name string) bool {
		id := model.RoleID{Name: name}
		return name != st.user && !(Dialect{}).IsSystemRole(id) && !matches(ignoreRoles, name) &&
			slices.ContainsFunc(cur.Roles, func(r model.RoleState) bool { return r.ID == id }) &&
			!slices.ContainsFunc(st.desired.Roles, func(r model.Role) bool { return r.ID == id })
	}
	blocked := map[string][]string{}
	var roles []string
	err := query(ctx, d.db, `SELECT DISTINCT r.rolname, db.datname
		FROM pg_shdepend s
		JOIN pg_roles r ON r.oid = s.refobjid
		JOIN pg_database db ON db.oid = s.dbid
		WHERE s.refclassid = 'pg_authid'::regclass AND s.dbid <> 0 AND s.deptype <> 'p'
		ORDER BY 1, 2`,
		func(rows *sql.Rows) error {
			var role, db string
			if err := rows.Scan(&role, &db); err != nil {
				return err
			}
			if unmanagedRole(role) && !unmanagedName(model.NameDatabase, db) {
				cur.Entangle(model.Object{Type: model.ObjectDatabase, Database: db},
					fmt.Sprintf("role %q, which dbfence does not manage, owns objects or holds privileges in it", role))
				return nil
			}
			var why string
			switch {
			case !prunable(role):
				return nil
			case unmanagedName(model.NameDatabase, db):
				why = "not managed by dbfence"
			case matches(ignoreDBs, db) && !slices.ContainsFunc(st.desired.Databases, func(d model.Database) bool { return d.Name == db }):
				why = "ignored"
			case !st.connectable[db]:
				why = "cannot connect"
			default:
				return nil
			}
			if _, ok := blocked[role]; !ok {
				roles = append(roles, role)
			}
			blocked[role] = append(blocked[role], fmt.Sprintf("database %q (%s)", db, why))
			return nil
		})
	if err != nil {
		return nil, err
	}
	warns := make([]string, 0, len(roles))
	for _, role := range roles {
		warns = append(warns, fmt.Sprintf("role %q owns objects or holds privileges in %s, where dbfence does not run REASSIGN OWNED and DROP OWNED, so dropping it with --prune will fail at DROP ROLE; reassign or drop them there first",
			role, strings.Join(blocked[role], ", ")))
	}
	return warns, nil
}

// unmanagedName reports whether dbfence does not manage an object named
// name because of the name itself (model.CheckName). Inspect removes such
// objects from model.Current; the state keeps them, so that grants and
// memberships depending on them are still known, and the statements that
// would name one of them are skipped with a warning instead.
func unmanagedName(kind model.NameKind, name string) bool {
	return model.CheckName(model.EnginePostgres, kind, name) != ""
}

// unmanagedRole reports whether role is a role (or grantor) that
// unmanagedName excludes. "" is no role.
func unmanagedRole(role string) bool { return unmanagedName(model.NameRole, role) }

// unmanagedObject reports whether unmanagedName excludes obj: its
// database, or its schema.
func unmanagedObject(obj model.Object) bool {
	return unmanagedName(model.NameDatabase, obj.Database) ||
		(obj.Type == model.ObjectSchema && unmanagedName(model.NameSchema, obj.Schema))
}

// unmanagedOwnerMembershipWarnings names the memberships that
// revokeOwnerMemberships would revoke before pruning a role, but cannot
// because they name a role dbfence does not manage, so DROP ROLE may fail.
func (st *state) unmanagedOwnerMembershipWarnings(cur *model.Current) []string {
	ignore := compileIgnore(st.desired.Ignore.Roles)
	var warns []string
	for _, r := range cur.Roles {
		if !st.prunable(r.ID.Name, ignore) {
			continue
		}
		for _, e := range st.ownerMemberships(r.ID.Name) {
			if unmanagedRole(e.role) || unmanagedRole(e.grantor) {
				warns = append(warns, fmt.Sprintf("role %q has the privileges of the owner of objects it granted privileges on through a membership that names a role dbfence does not manage, which is not revoked, so dropping it with --prune may fail at DROP ROLE; revoke that membership manually first",
					r.ID.Name))
				break
			}
		}
	}
	return warns
}

func compileIgnore(patterns []string) []*regexp.Regexp {
	var out []*regexp.Regexp
	for _, p := range patterns {
		if re, err := model.CompileIgnorePattern(p); err == nil {
			out = append(out, re)
		}
	}
	return out
}

// canAlter reports whether the connected user may ALTER role: from
// PostgreSQL 16 on it needs ADMIN OPTION on it, before that CREATEROLE;
// only superusers may alter superusers.
func (st *state) canAlter(role string) bool {
	a, known := st.roles[role]
	switch {
	case st.superuser || role == st.user || !known:
		return true
	case a.superuser:
		return false
	case st.version >= pg16:
		return a.admin
	default:
		return st.createRole
	}
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
	// Before PostgreSQL 16 the options do not exist: membership always
	// allows SET ROLE, and inheritance is the member's rolinherit.
	options := "true, true"
	if st.version >= pg16 {
		options = "am.inherit_option, am.set_option"
	}
	return query(ctx, d.db, `SELECT m.rolname, r.rolname, coalesce(g.rolname, ''), am.admin_option, `+options+`
		FROM pg_auth_members am
		JOIN pg_roles r ON r.oid = am.roleid
		JOIN pg_roles m ON m.oid = am.member
		LEFT JOIN pg_roles g ON g.oid = am.grantor
		ORDER BY 1, 2, 3`,
		func(rows *sql.Rows) error {
			var e memberEntry
			if err := rows.Scan(&e.member, &e.role, &e.grantor, &e.admin, &e.inherit, &e.set); err != nil {
				return err
			}
			st.members = append(st.members, e)
			for i := range cur.Roles {
				r := &cur.Roles[i]
				if r.ID.Name != e.member {
					continue
				}
				id := model.RoleID{Name: e.role}
				if !slices.Contains(r.MemberOf, id) {
					r.MemberOf = append(r.MemberOf, id)
				}
				if r.MemberOptions == nil {
					r.MemberOptions = map[model.RoleID]model.MembershipState{}
				}
				// Several grantors: an option holds if any grant has it.
				o := r.MemberOptions[id]
				o.Admin, o.Inherit, o.Set = o.Admin || e.admin, o.Inherit || e.inherit, o.Set || e.set
				r.MemberOptions[id] = o
			}
			return nil
		})
}

// inspectSharedDependencies reads the dependencies of roles on shared
// objects: the owners of and privileges on databases (also those that
// inspectDatabases leaves out), tablespaces and, from PostgreSQL 15 on,
// parameters. REASSIGN OWNED and DROP OWNED change them wherever they
// run. Memberships (pg_auth_members, PostgreSQL 16+) are left out:
// inspectMembership reads them. The catalog is named by classid so that
// older servers, which lack some catalogs, accept the query.
func (d *Driver) inspectSharedDependencies(ctx context.Context, _ *model.Current, st *state) error {
	return query(ctx, d.db, `SELECT DISTINCT r.rolname, s.classid::regclass::text, coalesce(db.datname, ts.spcname, '')
		FROM pg_shdepend s
		JOIN pg_roles r ON r.oid = s.refobjid
		LEFT JOIN pg_database db ON s.classid = 'pg_database'::regclass AND db.oid = s.objid
		LEFT JOIN pg_tablespace ts ON s.classid = 'pg_tablespace'::regclass AND ts.oid = s.objid
		WHERE s.refclassid = 'pg_authid'::regclass AND s.dbid = 0 AND s.deptype <> 'p'
			AND s.classid <> 'pg_auth_members'::regclass
		ORDER BY 1, 2, 3`,
		func(rows *sql.Rows) error {
			var e sharedDep
			if err := rows.Scan(&e.role, &e.class, &e.name); err != nil {
				return err
			}
			st.shared = append(st.shared, e)
			return nil
		})
}

func (d *Driver) inspectDatabaseACL(ctx context.Context, cur *model.Current, st *state) error {
	listed := func(name string) bool {
		return slices.ContainsFunc(cur.Databases, func(db model.Database) bool { return db.Name == name })
	}
	// A NULL ACL means the defaults, which include CONNECT and TEMPORARY
	// for PUBLIC (grantee 0, reported as model.PublicRole).
	return query(ctx, d.db, `SELECT d.datname, CASE WHEN a.grantee = 0 THEN 'public' ELSE r.rolname END,
			g.rolname, a.privilege_type, a.is_grantable
		FROM pg_database d
		CROSS JOIN LATERAL aclexplode(COALESCE(d.datacl, acldefault('d', d.datdba))) a
		LEFT JOIN pg_roles r ON r.oid = a.grantee
		JOIN pg_roles g ON g.oid = a.grantor
		WHERE a.grantee = 0 OR r.oid IS NOT NULL
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

// entangleUnread records in cur.Entangled the undeclared databases with
// names dbfence manages that it cannot connect to (no CONNECT, or the
// connection failed): what they contain is not known, so --prune keeps
// them. Provider databases are never dropped.
func (st *state) entangleUnread(cur *model.Current) {
	for _, db := range cur.Databases {
		if st.connectable[db.Name] || providerDatabase(db.Name) || unmanagedName(model.NameDatabase, db.Name) ||
			slices.ContainsFunc(st.desired.Databases, func(d model.Database) bool { return d.Name == db.Name }) {
			continue
		}
		cur.Entangle(model.Object{Type: model.ObjectDatabase, Database: db.Name},
			"dbfence cannot connect to it and does not know what it contains")
	}
}

// otherSchemaDatabases returns the connectable databases that are neither
// declared nor ignored: pruning a role runs REASSIGN OWNED and DROP OWNED
// there, so the owners of their schemas (ignored ones, see
// model.Current.OtherSchemas, and unmanaged ones) and the privileges on
// them must be known.
func otherSchemaDatabases(desired *model.Desired, cur *model.Current, connectable map[string]bool) []string {
	ignoreDBs := compileIgnore(desired.Ignore.Databases)
	var out []string
	for _, db := range cur.Databases {
		if !connectable[db.Name] || unmanagedName(model.NameDatabase, db.Name) ||
			slices.ContainsFunc(desired.Databases, func(d model.Database) bool { return d.Name == db.Name }) ||
			slices.ContainsFunc(ignoreDBs, func(re *regexp.Regexp) bool { return re.MatchString(db.Name) }) {
			continue
		}
		out = append(out, db.Name)
	}
	return out
}

// inspectSchemaOwners reads the schemas and their owners of an undeclared
// database into cur.OtherSchemas, and the privileges on them into
// st.otherACL. It reports false when the database cannot be connected to.
// The connection is closed afterwards: the plan may drop the database.
func (d *Driver) inspectSchemaOwners(ctx context.Context, cur *model.Current, st *state, database string) (bool, error) {
	c, err := d.conn(ctx, database)
	defer d.closeConn(database)
	if pgErr := (*pgconn.PgError)(nil); errors.As(err, &pgErr) &&
		slices.Contains([]string{sqlstateInsufficientPrivilege, sqlstateInvalidAuthorization, sqlstateInvalidCatalogName}, pgErr.Code) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	err = query(ctx, c, `SELECT nspname, pg_get_userbyid(nspowner) FROM pg_namespace
		WHERE nspname NOT LIKE 'pg\_%' AND nspname <> 'information_schema' ORDER BY nspname`,
		func(rows *sql.Rows) error {
			s := model.Schema{Database: database}
			if scanErr := rows.Scan(&s.Name, &s.Owner); scanErr != nil {
				return scanErr
			}
			cur.OtherSchemas = append(cur.OtherSchemas, s)
			return nil
		})
	if err != nil {
		return false, fmt.Errorf("schemas of database %q: %w", database, err)
	}
	err = query(ctx, c, schemaACLQuery, func(rows *sql.Rows) error {
		e := aclEntry{obj: model.Object{Type: model.ObjectSchema, Database: database}}
		if scanErr := rows.Scan(&e.obj.Schema, &e.grantee, &e.grantor, &e.priv, &e.grantable); scanErr != nil {
			return scanErr
		}
		st.otherACL = append(st.otherACL, e)
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("schema privileges of database %q: %w", database, err)
	}
	return true, nil
}

// schemaACLQuery reads the privileges on the schemas of the connected
// database.
const schemaACLQuery = `SELECT n.nspname, CASE WHEN a.grantee = 0 THEN 'public' ELSE r.rolname END,
		g.rolname, a.privilege_type, a.is_grantable
	FROM pg_namespace n
	CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) a
	LEFT JOIN pg_roles r ON r.oid = a.grantee
	JOIN pg_roles g ON g.oid = a.grantor
	WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
		AND (a.grantee = 0 OR r.oid IS NOT NULL)
	ORDER BY 1, 2, 4, 3`

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
	return true, query(ctx, c, schemaACLQuery,
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
