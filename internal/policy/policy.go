// Package policy checks a finished plan against the protections dbfence
// promises, independently of the diff logic that produced it. It reads
// only statement metadata (Kind, Target, RoleChange, DefaultRoles,
// AsRole), never SQL text, and does no I/O.
package policy

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
)

// System tells built-in objects apart. Every engine dialect implements it.
type System interface {
	IsSystemRole(id model.RoleID) bool
	IsSystemDatabase(name string) bool
	IsSystemSchema(name string) bool
}

// Options are the settings the plan was computed with.
type Options struct {
	// System identifies built-in roles, databases and schemas.
	System System
	// Prune is set when unmanaged objects may be dropped.
	Prune bool
}

// Violation is a planned statement that breaks a protection.
type Violation struct {
	// Resource is the plan change the statement belongs to.
	Resource string
	// Kind is what the statement does.
	Kind plan.Kind
	// Reason says which protection it breaks.
	Reason string
}

func (v Violation) String() string {
	if v.Resource == "" {
		return v.Reason
	}
	return fmt.Sprintf("%s (%s statement of %s)", v.Reason, v.Kind, v.Resource)
}

// Verify returns the statements of p that drop or lock out what dbfence
// never touches: the connected user and its database, built-in, ignored,
// declared or referenced objects, roles the connected user relies on and
// owners of ignored objects. cur and desired are the states p was
// computed from. An empty result means p passed.
func Verify(p *plan.Plan, cur *model.Current, desired *model.Desired, opts Options) []Violation {
	ig, err := newIgnorer(desired.Ignore, desired.Engine)
	if err != nil {
		return []Violation{{Reason: fmt.Sprintf("cannot verify the plan: %v", err)}}
	}
	c := &checker{cur: cur, desired: desired, opts: opts, ignore: ig, reassigned: map[plan.Target]bool{}}
	c.dropped = c.droppedDatabases(p)
	c.edges = map[membership]bool{}
	for _, r := range cur.Roles {
		for _, m := range r.MemberOf {
			c.edges[membership{r.ID, m}] = true
		}
	}
	c.relied = c.reachable()
	c.referenced = c.referencedRoles()
	var out []Violation
	for _, ch := range p.Changes {
		for _, s := range ch.Statements {
			for _, reason := range append(c.check(s), c.unmanagedNames(s)...) {
				out = append(out, Violation{Resource: ch.Resource, Kind: s.Kind(), Reason: reason})
			}
		}
	}
	return out
}

type checker struct {
	opts       Options
	cur        *model.Current
	desired    *model.Desired
	relied     map[model.RoleID]bool
	referenced map[model.RoleID]bool
	// reassigned holds the roles and databases of the REASSIGN OWNED
	// statements checked so far.
	reassigned map[plan.Target]bool
	// edges are the memberships after the statements checked so far.
	edges   map[membership]bool
	dropped []string
	ignore  ignorer
}

func (c *checker) check(s plan.Statement) []string {
	t := s.Target()
	switch s.Kind() {
	case plan.KindDropRole, plan.KindReassign, plan.KindDropOwned:
		reasons := c.prunes()
		reasons = append(reasons, c.dropRole(t.Role)...)
		if s.Kind() != plan.KindDropRole {
			reasons = append(reasons, c.ownedIn(t.Database)...)
		}
		return append(reasons, c.reassignedFirst(s)...)
	case plan.KindDropDatabase:
		return append(c.prunes(), c.dropDatabase(t.Database)...)
	case plan.KindDropSchema:
		return append(c.prunes(), c.dropSchema(t.Database, t.Schema)...)
	case plan.KindCreateRole, plan.KindAlterRole:
		if t.Role == c.cur.CurrentUser {
			return c.lockOut(s.RoleChange())
		}
		if c.relied[t.Role] {
			return c.noInheritOnChain(t.Role, s.RoleChange())
		}
	case plan.KindGrantMembership:
		c.edges[membership{t.Grantee, t.Role}] = true
		if t.Grantee == c.cur.CurrentUser || c.relied[t.Grantee] {
			return c.narrowsMembership(t.Grantee, t.Role, s.RoleChange())
		}
	case plan.KindRevokeMembership:
		if t.Grantee == c.cur.CurrentUser {
			return []string{fmt.Sprintf("revokes a membership or ADMIN OPTION of the connected user %q in %q", t.Grantee, t.Role)}
		}
		if !t.Option {
			return c.revokeRelied(t.Grantee, t.Role)
		}
	case plan.KindSetDefaultRole:
		if t.Role == c.cur.CurrentUser {
			return c.narrowsDefaultRoles(s.DefaultRoles())
		}
	case plan.KindOther, plan.KindGrant, plan.KindRevoke,
		plan.KindCreateDatabase, plan.KindAlterDatabase, plan.KindCreateSchema, plan.KindAlterSchema:
		// Nothing they do can drop a protected object or lock the
		// connected user out.
	}
	return nil
}

// unmanagedNames reports the names in the target of s (including the
// GRANTED BY grantor and the owner it sets), its default roles and the
// role it runs as that dbfence never manages (model.CheckName): such
// objects are left out of the inspected state, so no statement may name
// them.
func (c *checker) unmanagedNames(s plan.Statement) []string {
	t := s.Target()
	e := c.desired.Engine
	var out []string
	roles := append([]model.RoleID{t.Role, t.Grantee}, s.DefaultRoles()...)
	for _, id := range roles {
		if why := model.CheckRoleID(e, id); why != "" {
			out = append(out, fmt.Sprintf("names role %q, which dbfence does not manage: %s", id, why))
		}
	}
	if why := model.CheckRoleID(e, t.Grantor); why != "" {
		out = append(out, fmt.Sprintf("names grantor %q in GRANTED BY, which dbfence does not manage: %s", t.Grantor, why))
	}
	if why := model.CheckName(e, model.NameRole, t.Owner); why != "" {
		out = append(out, fmt.Sprintf("makes role %q an owner, which dbfence does not manage: its name %s", t.Owner, why))
	}
	if why := model.CheckName(e, model.NameRole, s.AsRole); why != "" {
		out = append(out, fmt.Sprintf("runs as role %q, which dbfence does not manage: its name %s", s.AsRole, why))
	}
	for _, n := range []struct {
		what, name string
		kind       model.NameKind
	}{
		{"database", t.Database, model.NameDatabase},
		{"database pattern", t.Pattern, model.NameDatabase},
		{"schema", t.Schema, model.NameSchema},
	} {
		if why := model.CheckName(e, n.kind, n.name); why != "" {
			out = append(out, fmt.Sprintf("names %s %q, which dbfence does not manage: its name %s", n.what, n.name, why))
		}
	}
	return out
}

// reassignedFirst records a REASSIGN OWNED and checks that a DROP OWNED
// comes after the REASSIGN OWNED of the same role in the same database:
// without it, DROP OWNED drops the objects the role owns there.
// Both must run on the database their target names.
func (c *checker) reassignedFirst(s plan.Statement) []string {
	t := s.Target()
	if s.Kind() == plan.KindDropRole {
		return nil
	}
	if s.Database != t.Database {
		return []string{fmt.Sprintf("runs on database %q, but its target is in database %q", s.Database, t.Database)}
	}
	key := plan.Target{Role: t.Role, Database: t.Database}
	switch {
	case s.Kind() == plan.KindReassign:
		c.reassigned[key] = true
	case !c.reassigned[key]:
		return []string{fmt.Sprintf("drops the objects role %q owns in database %q: no REASSIGN OWNED of the role runs there first", t.Role, t.Database)}
	}
	return nil
}

// prunes reports a drop planned without --prune.
func (c *checker) prunes() []string {
	if c.opts.Prune {
		return nil
	}
	return []string{"drops an object without --prune"}
}

func (c *checker) dropRole(id model.RoleID) []string {
	var out []string
	add := func(cond bool, format string, args ...any) {
		if cond {
			out = append(out, fmt.Sprintf(format, args...))
		}
	}
	add(c.cur.Unreadable.Roles, "drops role %q although the role list is unreadable", id)
	add(id == c.cur.CurrentUser, "drops the connected user %q", id)
	add(c.opts.System.IsSystemRole(id), "drops the built-in role %q", id)
	add(c.ignore.role(id), "drops the ignored role %q", id)
	add(slices.ContainsFunc(c.desired.Roles, func(r model.Role) bool { return r.ID == id }), "drops the declared role %q", id)
	add(c.referenced[id], "drops role %q, which the configuration references", id)
	add(c.relied[id], "drops role %q, which is granted to the connected user", id)
	add(!slices.ContainsFunc(c.cur.Roles, func(r model.RoleState) bool { return r.ID == id }), "drops role %q, which does not exist", id)
	if id.Host == "" {
		if what := c.ownsIgnored(id.Name); what != "" {
			out = append(out, fmt.Sprintf("drops role %q, which owns the ignored %s", id, what))
		}
	}
	return out
}

// ownsIgnored names an ignored object that role owns, or returns "".
func (c *checker) ownsIgnored(role string) string {
	for _, db := range c.cur.Databases {
		if db.Owner == role && c.ignore.database(db.Name) && !c.declaredDatabase(db.Name) {
			return fmt.Sprintf("database %q", db.Name)
		}
	}
	for _, s := range c.cur.Schemas {
		if s.Owner == role && c.ignore.schema(s.Database, s.Name) && !c.declaredSchema(s.Database, s.Name) && !c.opts.System.IsSystemSchema(s.Name) {
			return fmt.Sprintf("schema %q in database %q", s.Name, s.Database)
		}
	}
	for _, s := range c.cur.OtherSchemas {
		if s.Owner == role && c.survives(s.Database) && c.ignore.schema(s.Database, s.Name) && !c.opts.System.IsSystemSchema(s.Name) {
			return fmt.Sprintf("schema %q in database %q", s.Name, s.Database)
		}
	}
	return ""
}

// survives reports whether REASSIGN OWNED may run on database: it exists,
// is not dropped by the plan, and is not ignored unless declared.
func (c *checker) survives(database string) bool {
	return c.existingDatabase(database) && !slices.Contains(c.dropped, database) &&
		(!c.ignore.database(database) || c.declaredDatabase(database))
}

// ownedIn checks where REASSIGN OWNED or DROP OWNED runs.
func (c *checker) ownedIn(database string) []string {
	switch {
	case !c.existingDatabase(database):
		return []string{fmt.Sprintf("runs on database %q, which does not exist", database)}
	case slices.Contains(c.dropped, database):
		return []string{fmt.Sprintf("runs on database %q, which the plan drops", database)}
	case c.ignore.database(database) && !c.declaredDatabase(database):
		return []string{fmt.Sprintf("changes objects in the ignored database %q", database)}
	}
	return nil
}

func (c *checker) dropDatabase(name string) []string {
	var out []string
	add := func(cond bool, format string) {
		if cond {
			out = append(out, fmt.Sprintf(format, name))
		}
	}
	add(name != "" && name == c.cur.CurrentDatabase, "drops the database %q dbfence is connected to")
	add(c.opts.System.IsSystemDatabase(name), "drops the built-in database %q")
	add(c.ignore.database(name), "drops the ignored database %q")
	add(c.declaredDatabase(name), "drops the declared database %q")
	add(!c.existingDatabase(name), "drops database %q, which does not exist")
	return out
}

func (c *checker) dropSchema(database, name string) []string {
	var out []string
	add := func(cond bool, format string) {
		if cond {
			out = append(out, fmt.Sprintf(format, name, database))
		}
	}
	add(c.opts.System.IsSystemSchema(name), "drops the built-in schema %q in database %q")
	add(c.ignore.schema(database, name), "drops the ignored schema %q in database %q")
	add(c.declaredSchema(database, name), "drops the declared schema %q in database %q")
	add(!slices.ContainsFunc(c.cur.Schemas, func(s model.Schema) bool { return s.Database == database && s.Name == name }),
		"drops schema %q in database %q, which does not exist")
	return out
}

// lockOut checks a CREATE or ALTER of the connected user.
func (c *checker) lockOut(ch plan.RoleChange) []string {
	id := c.cur.CurrentUser
	var out []string
	if ch.DisablesLogin {
		out = append(out, fmt.Sprintf("disables login of the connected user %q", id))
	}
	if ch.LocksAccount {
		out = append(out, fmt.Sprintf("locks the account of the connected user %q", id))
	}
	if ch.DisablesInherit {
		out = append(out, fmt.Sprintf("sets NOINHERIT on the connected user %q", id))
	}
	if ch.RemovesSuperuser {
		out = append(out, fmt.Sprintf("removes superuser from the connected user %q", id))
	}
	if ch.ConnectionLimit != nil && *ch.ConnectionLimit == 0 && !c.superuser() {
		out = append(out, fmt.Sprintf("sets connection limit 0 on the connected user %q, which is not a superuser", id))
	}
	return out
}

// narrowsDefaultRoles checks a SET DEFAULT ROLE of the connected user
// (MySQL): it must keep every current default role, or, when those could
// not be read, every role granted to it, so that later sessions still
// have the privileges dbfence gets from them.
func (c *checker) narrowsDefaultRoles(set []model.RoleID) []string {
	id := c.cur.CurrentUser
	i := slices.IndexFunc(c.cur.Roles, func(r model.RoleState) bool { return r.ID == id })
	if i < 0 {
		return []string{fmt.Sprintf("sets the default roles of the connected user %q, whose current default roles are unknown", id)}
	}
	cur := c.cur.Roles[i]
	keep := cur.DefaultRoles
	if cur.DefaultRolesUnknown {
		keep = cur.MemberOf
	}
	var out []string
	for _, r := range keep {
		if !slices.Contains(set, r) {
			out = append(out, fmt.Sprintf("removes %q from the default roles of the connected user %q", r, id))
		}
	}
	return out
}

// narrowsMembership checks a GRANT of role to member, the connected user
// or a role granted to it: it may not turn off INHERIT or SET on a
// membership member has, or (for the connected user) may have when
// memberships are unreadable. The connected user would lose the
// privileges of role or the right to SET ROLE to it, since PostgreSQL 16
// needs INHERIT, or SET, on every membership along the chain.
func (c *checker) narrowsMembership(member, role model.RoleID, ch plan.RoleChange) []string {
	if !ch.DisablesInherit && !ch.DisablesSet {
		return nil
	}
	id := c.cur.CurrentUser
	i := slices.IndexFunc(c.cur.Roles, func(r model.RoleState) bool { return r.ID == member })
	var have model.MembershipState
	switch {
	case i < 0 || c.cur.Unreadable.Roles || c.cur.Unreadable.Memberships:
		have = model.MembershipState{Inherit: true, Set: true}
	case slices.Contains(c.cur.Roles[i].MemberOf, role):
		have = c.cur.Roles[i].MemberOptions[role]
	}
	what := fmt.Sprintf("the membership of the connected user %q in %q", id, role)
	if member != id {
		what = fmt.Sprintf("the membership of %q in %q, through which the connected user %q has its roles", member, role, id)
	}
	var out []string
	if ch.DisablesInherit && have.Inherit {
		out = append(out, "sets INHERIT FALSE on "+what)
	}
	if ch.DisablesSet && have.Set {
		out = append(out, "sets SET FALSE on "+what)
	}
	return out
}

// noInheritOnChain checks a CREATE or ALTER of role, which is granted to
// the connected user: NOINHERIT on it stops the privileges of the roles
// it is a member of with INHERIT from reaching the connected user (and
// from PostgreSQL 16 on, dbfence turns INHERIT off on those memberships
// too).
func (c *checker) noInheritOnChain(role model.RoleID, ch plan.RoleChange) []string {
	if !ch.DisablesInherit {
		return nil
	}
	i := slices.IndexFunc(c.cur.Roles, func(r model.RoleState) bool { return r.ID == role })
	if i < 0 || !slices.ContainsFunc(c.cur.Roles[i].MemberOf, func(m model.RoleID) bool { return c.cur.Roles[i].MemberOptions[m].Inherit }) {
		return nil
	}
	return []string{fmt.Sprintf("sets NOINHERIT on %q, through which the connected user %q has its roles", role, c.cur.CurrentUser)}
}

func (c *checker) superuser() bool {
	i := slices.IndexFunc(c.cur.Roles, func(r model.RoleState) bool { return r.ID == c.cur.CurrentUser })
	return i >= 0 && c.cur.Roles[i].Superuser
}

func (c *checker) existingDatabase(name string) bool {
	return slices.ContainsFunc(c.cur.Databases, func(d model.Database) bool { return d.Name == name })
}

func (c *checker) declaredDatabase(name string) bool {
	return slices.ContainsFunc(c.desired.Databases, func(d model.Database) bool { return d.Name == name })
}

func (c *checker) declaredSchema(database, name string) bool {
	return slices.ContainsFunc(c.desired.Schemas, func(s model.Schema) bool { return s.Database == database && s.Name == name })
}

// droppedDatabases returns the databases p drops.
func (c *checker) droppedDatabases(p *plan.Plan) []string {
	var out []string
	for _, s := range p.Statements() {
		if s.Kind() == plan.KindDropDatabase {
			out = append(out, s.Target().Database)
		}
	}
	return out
}

// membership is a membership of member in role.
type membership struct{ member, role model.RoleID }

// reachable returns the roles granted to the connected user, directly or
// transitively, through c.edges.
func (c *checker) reachable() map[model.RoleID]bool {
	seen := map[model.RoleID]bool{}
	for queue := []model.RoleID{c.cur.CurrentUser}; len(queue) > 0; queue = queue[1:] {
		for e := range c.edges {
			if e.member == queue[0] && !seen[e.role] {
				seen[e.role] = true
				queue = append(queue, e.role)
			}
		}
	}
	return seen
}

// revokeRelied records the revoke of the membership of member in role and
// checks that the connected user still has every role it had before the
// plan: a revoke of another role's membership on its chain takes away
// the roles it reaches only through it.
func (c *checker) revokeRelied(member, role model.RoleID) []string {
	before := c.reachable()
	delete(c.edges, membership{member, role})
	after := c.reachable()
	var lost []string
	for id := range c.relied {
		if before[id] && !after[id] {
			lost = append(lost, fmt.Sprintf("%q", id))
		}
	}
	if len(lost) == 0 {
		return nil
	}
	slices.Sort(lost)
	return []string{fmt.Sprintf("revokes the membership of %q in %q, through which the connected user %q has %s", member, role, c.cur.CurrentUser, strings.Join(lost, ", "))}
}

// referencedRoles returns the roles the configuration refers to: member_of
// entries, owners and grantees.
func (c *checker) referencedRoles() map[model.RoleID]bool {
	refs := map[model.RoleID]bool{}
	for _, r := range c.desired.Roles {
		for _, m := range r.MemberOf {
			refs[m] = true
		}
	}
	for _, db := range c.desired.Databases {
		if db.Owner != "" {
			refs[model.RoleID{Name: db.Owner}] = true
		}
	}
	for _, s := range c.desired.Schemas {
		if s.Owner != "" {
			refs[model.RoleID{Name: s.Owner}] = true
		}
	}
	for _, p := range c.desired.Privileges {
		refs[p.Grantee] = true
	}
	return refs
}

// ignorer matches the ignore patterns of the configuration. It is kept
// apart from the one in diff on purpose: the check must not share the
// code it checks.
type ignorer struct {
	engine                    model.Engine
	roles, databases, schemas []*regexp.Regexp
}

func newIgnorer(ig model.Ignore, engine model.Engine) (ignorer, error) {
	i := ignorer{engine: engine}
	for _, l := range []struct {
		dst  *[]*regexp.Regexp
		pats []string
	}{{&i.roles, ig.Roles}, {&i.databases, ig.Databases}, {&i.schemas, ig.Schemas}} {
		for _, p := range l.pats {
			re, err := model.CompileIgnorePattern(p)
			if err != nil {
				return i, fmt.Errorf("ignore pattern %q: %w", p, err)
			}
			*l.dst = append(*l.dst, re)
		}
	}
	return i, nil
}

func matchAny(res []*regexp.Regexp, s string) bool {
	return slices.ContainsFunc(res, func(re *regexp.Regexp) bool { return re.MatchString(s) })
}

// role matches the role name or, for a MySQL account, "name@host" (also
// when the host is empty); a PostgreSQL id with a host also as name@host.
func (i ignorer) role(id model.RoleID) bool {
	switch {
	case matchAny(i.roles, id.Name):
		return true
	case i.engine == model.EngineMySQL:
		return matchAny(i.roles, model.Account(id).String())
	default:
		return id.Host != "" && matchAny(i.roles, id.String())
	}
}

func (i ignorer) database(name string) bool { return matchAny(i.databases, name) }

// schema matches the schema name or "<database>.<schema>".
func (i ignorer) schema(database, name string) bool {
	return matchAny(i.schemas, name) || matchAny(i.schemas, database+"."+name)
}
