// Package model defines the engine-neutral representation of the
// cluster-level objects managed by dbfence.
package model

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strconv"
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

// PublicRole is PostgreSQL's PUBLIC pseudo-role, which every role is
// implicitly a member of. Its name is reserved by PostgreSQL, so no real
// role can collide with it.
var PublicRole = RoleID{Name: "public"}

// IsPublic reports whether id is the PUBLIC pseudo-role.
func (id RoleID) IsPublic() bool { return id == PublicRole }

func (id RoleID) String() string {
	if id.IsPublic() {
		return "PUBLIC"
	}
	if id.Host == "" {
		return id.Name
	}
	return id.Name + "@" + id.Host
}

// Format implements fmt.Formatter. %q quotes the name and the host
// separately ("name"@"host") so that names containing '@' stay
// unambiguous; other verbs, and PUBLIC, print String.
func (id RoleID) Format(f fmt.State, verb rune) {
	if verb != 'q' || id.IsPublic() {
		_, _ = f.Write([]byte(id.String()))
		return
	}
	s := strconv.Quote(id.Name)
	if id.Host != "" {
		s += "@" + strconv.Quote(id.Host)
	}
	_, _ = f.Write([]byte(s))
}

// Account is a RoleID shown as a MySQL account: the host is always
// printed, so that an account with an empty host ("name"@"") is not
// mistaken for a PostgreSQL role.
type Account RoleID

func (a Account) String() string { return a.Name + "@" + a.Host }

// Format implements fmt.Formatter. %q prints "name"@"host"; other verbs
// print String.
func (a Account) Format(f fmt.State, verb rune) {
	s := a.String()
	if verb == 'q' {
		s = strconv.Quote(a.Name) + "@" + strconv.Quote(a.Host)
	}
	_, _ = f.Write([]byte(s))
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
	// MemberOptions holds the managed options of memberships in MemberOf.
	// A membership without an entry has no managed options.
	MemberOptions map[RoleID]MembershipOptions
	// MemberOf is nil when membership is not managed.
	MemberOf []RoleID
}

// MembershipOptions are the options of a membership. Nil fields are not
// managed. Inherit and Set are PostgreSQL 16+ only.
type MembershipOptions struct {
	Admin   *bool
	Inherit *bool
	Set     *bool
}

// MembershipState is the observed state of a membership. When a membership
// was granted more than once (by several grantors on PostgreSQL 16+), an
// option is true if any of the grants carries it.
type MembershipState struct {
	Admin   bool
	Inherit bool
	Set     bool
}

// RoleState is the observed state of a role.
type RoleState struct {
	ID         RoleID
	AuthPlugin string
	// PasswordHash is the stored verifier. PasswordReadable is false
	// when the connected user cannot read verifiers.
	PasswordHash []byte
	MemberOf     []RoleID
	// MemberOptions is the state of each membership in MemberOf.
	MemberOptions map[RoleID]MembershipState
	// DefaultRoles are the roles activated at login (MySQL only).
	DefaultRoles     []RoleID
	ConnectionLimit  int
	CreateDB         bool
	Replication      bool
	BypassRLS        bool
	Inherit          bool
	CreateRole       bool
	Superuser        bool
	Login            bool
	PasswordReadable bool
	// RetainedPassword is set when a secondary password kept by MySQL's
	// RETAIN CURRENT PASSWORD still authenticates the account.
	RetainedPassword bool
	// AttributesUnknown is set when the account exists but its login,
	// authentication plugin and password could not be read.
	AttributesUnknown bool
	// DefaultRolesUnknown is set when DefaultRoles could not be read.
	DefaultRolesUnknown bool
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
	// Pattern is a raw MySQL grant target with LIKE wildcards rather than
	// a literal database name. A declared pattern (grant database_pattern)
	// has an empty Database; an undeclared inspected one has Database set
	// to the pattern with escapes removed.
	Pattern string
}

// IsDeclaredPattern reports whether o is a database pattern declared with
// database_pattern (or the inspected grant matching one).
func (o Object) IsDeclaredPattern() bool {
	return o.Pattern != "" && o.Database == ""
}

func (o Object) String() string {
	switch {
	case o.Type == ObjectSchema:
		return o.Database + "." + o.Schema
	case o.IsDeclaredPattern():
		return o.Pattern
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
// be reported or pruned. Patterns match the whole name (see
// CompileIgnorePattern). Role patterns match the name or, for a MySQL
// account, "name@host"; schema patterns match the schema name or
// "<database>.<schema>".
type Ignore struct {
	Roles     []string
	Databases []string
	Schemas   []string
}

// CompileIgnorePattern compiles an ignore pattern anchored to match the
// whole name. Config validation and diff both use it, so a pattern that
// validates is matched exactly as written. The pattern must be valid on
// its own, so that unbalanced parentheses such as "a)|(b" cannot break
// out of the anchors, and '.' also matches a newline.
func CompileIgnorePattern(p string) (*regexp.Regexp, error) {
	if _, err := regexp.Compile(p); err != nil {
		return nil, fmt.Errorf("compile ignore pattern: %w", err)
	}
	re, err := regexp.Compile("(?s)^(?:" + p + ")$")
	if err != nil {
		return nil, fmt.Errorf("compile ignore pattern: %w", err)
	}
	return re, nil
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
	// PublicObjects lists the objects on which privileges of PUBLIC are
	// managed (PostgreSQL only): those with at least one PUBLIC grant.
	PublicObjects []Object
	Ignore        Ignore
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
	// OtherSchemas lists the schemas, with their owners only, of the
	// undeclared databases where pruning a role runs REASSIGN OWNED
	// (PostgreSQL only, read when ignore lists schema patterns or a role
	// may be pruned), so that --prune keeps the owners of ignored schemas
	// there.
	OtherSchemas []Schema
	// CurrentDatabase is the database dbfence is connected to
	// (PostgreSQL only). It is never pruned.
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

// CompareRoleIDs orders role IDs by name, then host.
func CompareRoleIDs(a, b RoleID) int {
	return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.Host, b.Host))
}

// SortRoleIDs sorts ids in place and returns them.
func SortRoleIDs(ids []RoleID) []RoleID {
	slices.SortFunc(ids, CompareRoleIDs)
	return ids
}
