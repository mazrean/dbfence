// Package model defines the engine-neutral representation of the
// cluster-level objects managed by dbfence.
package model

import (
	"slices"
	"strings"
)

// Engine identifies a database engine.
type Engine string

const (
	EngineMySQL    Engine = "mysql"
	EnginePostgres Engine = "postgres"
)

// RoleID identifies a role. Host is empty for PostgreSQL.
type RoleID struct {
	Name string
	Host string
}

func (id RoleID) String() string {
	if id.Host == "" {
		return id.Name
	}
	return id.Name + "@" + id.Host
}

// Database is a database (MySQL: schema).
type Database struct {
	Name string
	// PostgreSQL only.
	Owner     string
	Encoding  string
	LcCollate string
	LcCtype   string
	// MySQL only.
	Charset   string
	Collation string
}

// Role is a PostgreSQL role or a MySQL account.
// Nil pointer fields are not managed.
type Role struct {
	Login    *bool
	Password *string

	// PostgreSQL only.
	Superuser       *bool
	CreateDB        *bool
	CreateRole      *bool
	Inherit         *bool
	Replication     *bool
	BypassRLS       *bool
	ConnectionLimit *int

	ID RoleID
	// AuthPlugin is MySQL only.
	AuthPlugin string
	// MemberOf is nil when membership is not managed.
	MemberOf []RoleID
}

// RoleState is the observed state of a role.
type RoleState struct {
	ID         RoleID
	AuthPlugin string
	// PasswordHash is the stored verifier. PasswordReadable is false
	// when the connected user cannot read verifiers.
	PasswordHash     []byte
	MemberOf         []RoleID
	ConnectionLimit  int
	CreateDB         bool
	Replication      bool
	BypassRLS        bool
	Inherit          bool
	CreateRole       bool
	Superuser        bool
	Login            bool
	PasswordReadable bool
	// AttributesUnknown is set when the account exists but its login,
	// authentication plugin and password could not be read.
	AttributesUnknown bool
}

// Schema is a PostgreSQL schema inside Database.
type Schema struct {
	Database string
	Name     string
	Owner    string
}

// ObjectType is the kind of object a privilege is granted on.
type ObjectType string

const (
	ObjectDatabase ObjectType = "database"
	ObjectSchema   ObjectType = "schema"
)

// Object is a grant target.
type Object struct {
	Type     ObjectType
	Database string
	Schema   string
}

func (o Object) String() string {
	if o.Type == ObjectSchema {
		return o.Database + "." + o.Schema
	}
	return o.Database
}

// Privilege is a single privilege held by a grantee on an object.
type Privilege struct {
	Grantee     RoleID
	Object      Object
	Name        string
	GrantOption bool
}

// Key identifies a privilege irrespective of the grant option.
func (p Privilege) Key() PrivilegeKey {
	return PrivilegeKey{Grantee: p.Grantee, Object: p.Object, Name: p.Name}
}

// PrivilegeKey is the identity of a Privilege.
type PrivilegeKey struct {
	Grantee RoleID
	Object  Object
	Name    string
}

// Ignore lists regular expressions of unmanaged objects that must not
// be reported or pruned.
type Ignore struct {
	Roles     []string
	Databases []string
	Schemas   []string
}

// Unreadable records facets of the current state that the connected
// user is not allowed to read. The zero value means everything was read.
type Unreadable struct {
	// Roles is set when the list of roles is unknown.
	Roles bool
	// RoleAttributes is set when login, authentication plugin and
	// password verifiers of existing roles are unknown.
	RoleAttributes bool
	// Memberships is set when role memberships are unknown.
	Memberships bool
	// Privileges is set when database level privileges are unknown.
	Privileges bool
}

// Desired is the state declared in configuration.
type Desired struct {
	Engine     Engine
	Databases  []Database
	Roles      []Role
	Schemas    []Schema
	Privileges []Privilege
	Ignore     Ignore
}

// Current is the state observed in the live server.
type Current struct {
	// CurrentUser is the role dbfence is connected as.
	CurrentUser RoleID
	Databases   []Database
	Roles       []RoleState
	// Schemas only contains schemas of inspected databases.
	Schemas    []Schema
	Privileges []Privilege
	// InspectedDatabases lists databases whose schemas were inspected.
	InspectedDatabases []string
	// CurrentDatabase is the database the connection is bound to
	// (PostgreSQL only).
	CurrentDatabase string
	// Warnings are inspection notes that diff adds to the plan.
	Warnings []string
	// Unreadable lists what could not be inspected.
	Unreadable Unreadable
}

// NormalizePrivilege upper-cases and collapses whitespace.
func NormalizePrivilege(p string) string {
	return strings.Join(strings.Fields(strings.ToUpper(p)), " ")
}

// SortRoleIDs sorts ids in place and returns them.
func SortRoleIDs(ids []RoleID) []RoleID {
	slices.SortFunc(ids, func(a, b RoleID) int {
		return strings.Compare(a.String(), b.String())
	})
	return ids
}
