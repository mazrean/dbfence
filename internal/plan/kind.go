package plan

import "github.com/mazrean/dbfence/internal/model"

// Kind is what a statement does. Dialect builders set it with Target, so
// that a plan can be checked without parsing SQL.
type Kind string

// Statement kinds.
const (
	KindOther            Kind = "other"
	KindCreateRole       Kind = "create-role"
	KindAlterRole        Kind = "alter-role"
	KindDropRole         Kind = "drop-role"
	KindGrant            Kind = "grant"
	KindRevoke           Kind = "revoke"
	KindGrantMembership  Kind = "grant-membership"
	KindRevokeMembership Kind = "revoke-membership"
	KindSetDefaultRole   Kind = "set-default-role"
	KindCreateDatabase   Kind = "create-database"
	KindAlterDatabase    Kind = "alter-database"
	KindDropDatabase     Kind = "drop-database"
	KindCreateSchema     Kind = "create-schema"
	KindAlterSchema      Kind = "alter-schema"
	KindDropSchema       Kind = "drop-schema"
	KindReassign         Kind = "reassign-owned"
	KindDropOwned        Kind = "drop-owned"
)

// ObjectKind is the kind of object a statement acts on.
type ObjectKind string

// Object kinds.
const (
	ObjectNone     ObjectKind = ""
	ObjectRole     ObjectKind = "role"
	ObjectDatabase ObjectKind = "database"
	ObjectSchema   ObjectKind = "schema"
)

// Target is the object a statement acts on.
//
//   - Roles (create, alter, drop, set default role, reassign owned, drop
//     owned): Object is ObjectRole and Role the role; for REASSIGN OWNED
//     and DROP OWNED, Database is the database the statement runs on.
//   - Memberships: Object is ObjectRole, Role the role granted or revoked
//     and Grantee the member.
//   - Privileges: Object is ObjectDatabase or ObjectSchema, Database,
//     Schema and Pattern (a MySQL database pattern) name it, and Grantee
//     is the role the privileges are granted to or revoked from.
//   - Databases and schemas: Object, Database and Schema name them.
type Target struct {
	Role     model.RoleID
	Grantee  model.RoleID
	Object   ObjectKind
	Database string
	Schema   string
	Pattern  string
	// Option is set when a grant gives the grant option or ADMIN OPTION,
	// and when a revoke removes only that option.
	Option bool
}

// RoleTarget is the Target of a statement on role id.
func RoleTarget(id model.RoleID) Target { return Target{Object: ObjectRole, Role: id} }

// MembershipTarget is the Target of a grant or revoke of role to member.
func MembershipTarget(member, role model.RoleID) Target {
	return Target{Object: ObjectRole, Role: role, Grantee: member}
}

// PrivilegeTarget is the Target of a grant or revoke of privileges on obj
// to grantee.
func PrivilegeTarget(grantee model.RoleID, obj model.Object) Target {
	t := ObjectTarget(obj)
	t.Grantee = grantee
	return t
}

// ObjectTarget is the Target of a statement on the database or schema
// obj.
func ObjectTarget(obj model.Object) Target {
	t := Target{Object: ObjectDatabase, Database: obj.Database, Pattern: obj.Pattern}
	if obj.Type == model.ObjectSchema {
		t.Object, t.Schema = ObjectSchema, obj.Schema
	}
	return t
}

// WithOption returns t with Option set to on.
func (t Target) WithOption(on bool) Target {
	t.Option = on
	return t
}

// RoleChange is what a CREATE or ALTER of a role, or a GRANT of a
// membership, sets that a plan check needs: changes that can lock the
// connected user out or take away its powers.
type RoleChange struct {
	// ConnectionLimit is the connection limit set, if any.
	ConnectionLimit *int
	// DisablesLogin is set by PostgreSQL NOLOGIN.
	DisablesLogin bool
	// RemovesSuperuser is set by PostgreSQL NOSUPERUSER.
	RemovesSuperuser bool
	// LocksAccount is set by MySQL ACCOUNT LOCK.
	LocksAccount bool
	// DisablesInherit is set by PostgreSQL NOINHERIT and by a membership
	// GRANT with INHERIT FALSE.
	DisablesInherit bool
	// DisablesSet is set by a PostgreSQL membership GRANT with SET FALSE.
	DisablesSet bool
	// SetsPassword is set when the statement sets or clears the password
	// or changes the authentication plugin.
	SetsPassword bool
}
