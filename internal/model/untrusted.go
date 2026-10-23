package model

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// NameKind is what an identifier names, for CheckName.
type NameKind int

// Kinds of names.
const (
	NameRole NameKind = iota
	NameHost
	NameDatabase
	NameSchema
)

// Identifier length limits of the engines.
const (
	// PostgresMaxIdentBytes is NAMEDATALEN - 1; longer names are
	// truncated by PostgreSQL.
	PostgresMaxIdentBytes = 63
	MySQLMaxUserChars     = 32
	MySQLMaxDatabaseChars = 64
	MySQLMaxHostChars     = 255
)

// MaxNameLength returns the engine's limit for a name of kind, and
// whether it counts bytes (otherwise characters). 0 means no limit.
func MaxNameLength(engine Engine, kind NameKind) (limit int, bytes bool) {
	if engine == EnginePostgres {
		return PostgresMaxIdentBytes, true
	}
	switch kind {
	case NameRole:
		return MySQLMaxUserChars, false
	case NameHost:
		return MySQLMaxHostChars, false
	case NameDatabase, NameSchema:
		return MySQLMaxDatabaseChars, false
	}
	return 0, false
}

// IsControl reports whether r is a C0 or C1 control character or DEL.
func IsControl(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f)
}

// HasControl reports whether s contains a control character (IsControl).
func HasControl(s string) bool { return strings.IndexFunc(s, IsControl) >= 0 }

// CheckName returns why dbfence does not manage an object called name,
// or "" when it does: names that are not valid UTF-8, contain control
// characters or exceed the engine's identifier limit. It applies the
// same rule to names declared in the configuration and to names read
// from the server.
func CheckName(engine Engine, kind NameKind, name string) string {
	switch {
	case !utf8.ValidString(name):
		return "is not valid UTF-8"
	case HasControl(name):
		return "contains control characters"
	}
	limit, inBytes := MaxNameLength(engine, kind)
	n, unit := utf8.RuneCountInString(name), "characters"
	if inBytes {
		n, unit = len(name), "bytes"
	}
	if limit > 0 && n > limit {
		return fmt.Sprintf("is %d %s long, more than the %s limit of %d", n, unit, engine, limit)
	}
	return ""
}

// CheckRoleID applies CheckName to the name and host of id.
func CheckRoleID(engine Engine, id RoleID) string {
	if why := CheckName(engine, NameRole, id.Name); why != "" {
		return "its name " + why
	}
	if why := CheckName(engine, NameHost, id.Host); why != "" {
		return "its host " + why
	}
	return ""
}

// Untrusted lists the objects that DropUntrusted removed.
type Untrusted struct {
	Roles     map[RoleID]bool
	Databases map[string]bool
	// Schemas is keyed by database and schema name.
	Schemas map[[2]string]bool
}

// maxShownName bounds how much of an untrusted name a warning shows.
const maxShownName = 128

// showName quotes name for a warning, cut to maxShownName bytes.
func showName(name string) string {
	if len(name) <= maxShownName {
		return strconv.Quote(name)
	}
	cut := maxShownName
	for cut > 0 && !utf8.RuneStart(name[cut]) {
		cut--
	}
	return strconv.Quote(name[:cut]) + "..."
}

func showRole(engine Engine, id RoleID) string {
	if engine == EngineMySQL {
		return showName(id.Name) + "@" + showName(id.Host)
	}
	return showName(id.Name)
}

// ErrUntrustedCurrentUser is returned by DropUntrusted when the connected
// user itself has a name dbfence does not manage.
var ErrUntrustedCurrentUser = errors.New("the connected user has a name dbfence does not manage")

// DropUntrusted treats the names read from the server as untrusted input:
// roles, databases and schemas whose names fail CheckName are removed
// from c, together with the memberships, default roles and privileges
// that name them, so that nothing is planned for them. Each one gets a
// warning saying that dbfence does not manage it.
func (c *Current) DropUntrusted(engine Engine) (Untrusted, error) {
	if why := CheckRoleID(engine, c.CurrentUser); why != "" {
		return Untrusted{}, fmt.Errorf("%w (%s): connect as another user", ErrUntrustedCurrentUser, why)
	}
	u := Untrusted{Roles: map[RoleID]bool{}, Databases: map[string]bool{}, Schemas: map[[2]string]bool{}}
	why := map[any]string{}
	role := func(id RoleID) bool {
		if r := CheckRoleID(engine, id); r != "" {
			u.Roles[id], why[id] = true, r
		}
		return u.Roles[id]
	}
	database := func(name string) bool {
		if r := CheckName(engine, NameDatabase, name); r != "" {
			u.Databases[name], why[name] = true, "its name "+r
		}
		return u.Databases[name]
	}
	schema := func(db, name string) bool {
		if database(db) {
			return true
		}
		key := [2]string{db, name}
		if r := CheckName(engine, NameSchema, name); r != "" {
			u.Schemas[key], why[key] = true, "its name "+r
		}
		return u.Schemas[key]
	}
	object := func(o Object) bool {
		// A MySQL pattern is checked as written (the Db column).
		if database(o.Pattern) || database(o.Database) {
			return true
		}
		return o.Type == ObjectSchema && schema(o.Database, o.Schema)
	}

	c.Roles = slices.DeleteFunc(c.Roles, func(r RoleState) bool { return role(r.ID) })
	for i := range c.Roles {
		r := &c.Roles[i]
		r.MemberOf = slices.DeleteFunc(r.MemberOf, role)
		maps.DeleteFunc(r.MemberOptions, func(id RoleID, _ MembershipState) bool { return role(id) })
		r.DefaultRoles = slices.DeleteFunc(r.DefaultRoles, role)
	}
	c.Databases = slices.DeleteFunc(c.Databases, func(d Database) bool { return database(d.Name) })
	c.Schemas = slices.DeleteFunc(c.Schemas, func(s Schema) bool { return schema(s.Database, s.Name) })
	c.OtherSchemas = slices.DeleteFunc(c.OtherSchemas, func(s Schema) bool { return schema(s.Database, s.Name) })
	c.Privileges = slices.DeleteFunc(c.Privileges, func(p Privilege) bool {
		return role(p.Grantee) || object(p.Object)
	})
	c.InspectedDatabases = slices.DeleteFunc(c.InspectedDatabases, database)

	const manual = "dbfence does not manage it (nothing is created, changed, granted, revoked or dropped for it); handle it manually"
	for _, id := range slices.SortedFunc(maps.Keys(u.Roles), CompareRoleIDs) {
		kind := "role"
		if engine == EngineMySQL {
			kind = "account"
		}
		c.Warnings = append(c.Warnings, fmt.Sprintf("%s %s: %s, so %s", kind, showRole(engine, id), why[id], manual))
	}
	for _, name := range slices.Sorted(maps.Keys(u.Databases)) {
		c.Warnings = append(c.Warnings, fmt.Sprintf("database %s: %s, so %s", showName(name), why[name], manual))
	}
	for _, key := range slices.SortedFunc(maps.Keys(u.Schemas), func(a, b [2]string) int { return slices.Compare(a[:], b[:]) }) {
		c.Warnings = append(c.Warnings, fmt.Sprintf("schema %s in database %s: %s, so %s", showName(key[1]), showName(key[0]), why[key], manual))
	}
	return u, nil
}
