// Package diff compares the desired and current state and produces a plan.
package diff

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
)

// Options controls diff behavior.
type Options struct {
	// Prune drops unmanaged objects instead of warning about them.
	Prune bool
	// ForcePassword sets declared passwords even when they cannot be
	// verified or already match.
	ForcePassword bool
}

// Dialect renders engine specific SQL.
type Dialect interface {
	IsSystemRole(id model.RoleID) bool
	IsSystemDatabase(name string) bool
	IsSystemSchema(name string) bool

	CreateRole(r model.Role) []plan.Statement
	// EnsureRole creates r unless it exists. It is used when the list of
	// roles cannot be read.
	EnsureRole(r model.Role) []plan.Statement
	// AlterRole returns statements and warnings needed to converge cur to r.
	AlterRole(r model.Role, cur model.RoleState, force bool) ([]plan.Statement, []string)
	// DropRole drops id. databases lists existing databases that survive the plan.
	DropRole(id model.RoleID, databases []string) []plan.Statement
	GrantMembership(member, role model.RoleID) []plan.Statement
	RevokeMembership(member, role model.RoleID) []plan.Statement

	CreateDatabase(db model.Database) []plan.Statement
	AlterDatabase(db, cur model.Database) ([]plan.Statement, []string)
	DropDatabase(name string) []plan.Statement

	CreateSchema(s model.Schema) []plan.Statement
	AlterSchema(s, cur model.Schema) []plan.Statement
	DropSchema(s model.Schema) []plan.Statement

	Grant(grantee model.RoleID, obj model.Object, privs []string, grantOption bool) []plan.Statement
	Revoke(grantee model.RoleID, obj model.Object, privs []string) []plan.Statement
	RevokeGrantOption(grantee model.RoleID, obj model.Object, privs []string) []plan.Statement
}

// DefaultRoleSetter is implemented by dialects whose granted roles must be
// activated separately (MySQL). SetDefaultRoles is called once per role
// with managed memberships, after its memberships are granted and revoked.
type DefaultRoleSetter interface {
	SetDefaultRoles(r model.Role, cur model.RoleState) []plan.Statement
}

// Execution phases. Roles come first because databases and schemas
// reference owners. Memberships follow right after roles: creating a
// database owned by another role, or handing it over, requires the
// connected user to be a member of that role. Drops run in reverse
// dependency order.
const (
	phaseRole = iota
	phaseMembership
	phaseDatabase
	phaseSchema
	phaseGrant
	phaseRevoke
	phaseDropSchema
	phaseDropDatabase
	phaseDropRole
)

type change struct {
	plan.Change
	phase int
}

type differ struct {
	d        Dialect
	desired  *model.Desired
	current  *model.Current
	ignore   ignorer
	changes  []change
	warnings []string
	opts     Options
}

// Compute builds the plan converging current to desired.
func Compute(desired *model.Desired, current *model.Current, d Dialect, opts Options) (*plan.Plan, error) {
	ig, err := newIgnorer(desired.Ignore)
	if err != nil {
		return nil, err
	}
	df := &differ{d: d, opts: opts, desired: desired, current: sortedCurrent(current), ignore: ig, warnings: slices.Clone(current.Warnings)}
	if !current.Unreadable.Roles {
		if err := df.checkReferences(); err != nil {
			return nil, err
		}
	}
	df.warnUnreadable()
	df.roles()
	dropped := df.databases()
	df.schemas()
	df.privileges()
	df.pruneRoles(dropped)

	slices.SortStableFunc(df.changes, func(a, b change) int { return cmp.Compare(a.phase, b.phase) })
	p := &plan.Plan{Warnings: df.warnings}
	for _, c := range df.changes {
		p.Changes = append(p.Changes, c.Change)
	}
	return p, nil
}

// sortedCurrent returns a copy of cur whose objects are sorted, so that
// the plan does not depend on the order in which they were read.
func sortedCurrent(cur *model.Current) *model.Current {
	c := *cur
	c.Roles = slices.SortedFunc(slices.Values(cur.Roles), func(a, b model.RoleState) int { return model.CompareRoleIDs(a.ID, b.ID) })
	c.Databases = slices.SortedFunc(slices.Values(cur.Databases), func(a, b model.Database) int { return strings.Compare(a.Name, b.Name) })
	c.Schemas = slices.SortedFunc(slices.Values(cur.Schemas), func(a, b model.Schema) int {
		return cmp.Or(strings.Compare(a.Database, b.Database), strings.Compare(a.Name, b.Name))
	})
	return &c
}

func (df *differ) add(phase int, action plan.Action, resource string, stmts []plan.Statement) {
	if len(stmts) == 0 {
		return
	}
	c := change{phase: phase}
	c.Action, c.Resource, c.Statements = action, resource, stmts
	df.changes = append(df.changes, c)
}

func (df *differ) warn(format string, args ...any) {
	df.warnings = append(df.warnings, fmt.Sprintf(format, args...))
}

// roleResource names a role for plan output: "user" for login roles
// (declared by user blocks by default), "role" otherwise.
func (df *differ) roleResource(id model.RoleID) string {
	kind := "role"
	if i := slices.IndexFunc(df.desired.Roles, func(r model.Role) bool { return r.ID == id }); i >= 0 {
		if l := df.desired.Roles[i].Login; l != nil && *l {
			kind = "user"
		}
	} else if cur, ok := df.currentRole(id); ok && cur.Login {
		kind = "user"
	}
	return fmt.Sprintf("%s %q", kind, id)
}

func (df *differ) currentRole(id model.RoleID) (model.RoleState, bool) {
	i := slices.IndexFunc(df.current.Roles, func(r model.RoleState) bool { return r.ID == id })
	if i < 0 {
		return model.RoleState{}, false
	}
	return df.current.Roles[i], true
}

func (df *differ) desiredRole(id model.RoleID) bool {
	return slices.ContainsFunc(df.desired.Roles, func(r model.Role) bool { return r.ID == id })
}

// checkReferences rejects references to roles that neither exist nor are declared.
func (df *differ) checkReferences() error {
	known := func(id model.RoleID) bool {
		_, ok := df.currentRole(id)
		return ok || df.desiredRole(id)
	}
	var missing []string
	check := func(what string, id model.RoleID) {
		if id.Name != "" && !known(id) {
			missing = append(missing, fmt.Sprintf("%s references role %q, which neither exists nor is declared", what, id))
		}
	}
	for _, r := range df.desired.Roles {
		for _, m := range r.MemberOf {
			check(df.roleResource(r.ID)+" member_of", m)
		}
	}
	for _, db := range df.desired.Databases {
		check(fmt.Sprintf("database %q owner", db.Name), model.RoleID{Name: db.Owner})
	}
	for _, s := range df.desired.Schemas {
		check(fmt.Sprintf("schema %q owner", s.Name), model.RoleID{Name: s.Owner})
	}
	if len(missing) > 0 {
		return fmt.Errorf("invalid references:\n  %s", strings.Join(missing, "\n  "))
	}
	return nil
}

// warnUnreadable explains how missing read access changes the plan.
func (df *differ) warnUnreadable() {
	u := df.current.Unreadable
	if u.Roles {
		df.warn("cannot list roles: declared roles are created with IF NOT EXISTS on every run, existing ones are not updated, and unmanaged roles are not checked")
	}
	if u.RoleAttributes && len(df.desired.Roles) > 0 {
		df.warn("cannot read login state, authentication plugin and passwords of existing roles: they are not compared (use --force-password to set declared passwords)")
	}
	if u.Memberships || u.Roles {
		df.warn("cannot read role memberships: declared memberships are granted on every run and undeclared ones are not revoked")
	}
	if u.Privileges {
		df.warn("cannot read privileges: declared privileges are granted on every run and undeclared ones are not revoked")
	}
}

func (df *differ) roles() {
	u := df.current.Unreadable
	for _, r := range df.desired.Roles {
		cur, exists := df.currentRole(r.ID)
		self := exists && r.ID == df.current.CurrentUser
		if self {
			r = df.protectCurrentUser(r, cur)
		}
		switch {
		case !exists && u.Roles:
			// Existence is unknown: create idempotently and only apply
			// what does not need the current state.
			df.add(phaseRole, plan.ActionCreate, df.roleResource(r.ID)+" (if not exists)", df.d.EnsureRole(r))
			cur = model.RoleState{ID: r.ID, AttributesUnknown: true}
			stmts, warns := df.d.AlterRole(r, cur, df.opts.ForcePassword)
			df.warnings = append(df.warnings, warns...)
			df.add(phaseRole, plan.ActionUpdate, df.roleResource(r.ID), stmts)
		case !exists:
			df.add(phaseRole, plan.ActionCreate, df.roleResource(r.ID), df.d.CreateRole(r))
		default:
			stmts, warns := df.d.AlterRole(r, cur, df.opts.ForcePassword)
			df.warnings = append(df.warnings, warns...)
			df.add(phaseRole, plan.ActionUpdate, df.roleResource(r.ID), stmts)
		}
		if r.MemberOf == nil {
			continue
		}
		want := r.MemberOf
		have := cur.MemberOf
		// Roles created by this plan have no memberships yet; otherwise
		// unknown memberships are re-granted, which is idempotent.
		unknown := (u.Memberships && exists) || (u.Roles && !exists)
		for _, m := range want {
			if unknown || !slices.Contains(have, m) {
				df.add(phaseMembership, plan.ActionGrant, fmt.Sprintf("membership of %q in %q", r.ID, m), df.d.GrantMembership(r.ID, m))
			}
		}
		for _, m := range model.SortRoleIDs(slices.Clone(have)) {
			if unknown || slices.Contains(want, m) {
				continue
			}
			if self {
				df.warn("not revoking membership of the connected user %q in %q: dbfence may rely on it", r.ID, m)
				continue
			}
			df.add(phaseMembership, plan.ActionRevoke, fmt.Sprintf("membership of %q in %q", r.ID, m), df.d.RevokeMembership(r.ID, m))
		}
		if s, ok := df.d.(DefaultRoleSetter); ok {
			df.add(phaseMembership, plan.ActionUpdate, "default roles of "+df.roleResource(r.ID), s.SetDefaultRoles(r, cur))
		}
	}
}

// protectCurrentUser drops the attribute changes of r that would lock
// the connected user out or strip its superuser status.
func (df *differ) protectCurrentUser(r model.Role, cur model.RoleState) model.Role {
	if r.Login != nil && !*r.Login {
		if cur.Login || cur.AttributesUnknown {
			df.warn("not disabling login of the connected user %q: it would lock dbfence out", r.ID)
		}
		r.Login = nil
	}
	if r.Superuser != nil && !*r.Superuser && cur.Superuser {
		df.warn("not removing superuser from the connected user %q: dbfence may rely on it", r.ID)
		r.Superuser = nil
	}
	return r
}

// databases returns the names of databases dropped by the plan.
func (df *differ) databases() []string {
	for _, db := range df.desired.Databases {
		res := fmt.Sprintf("database %q", db.Name)
		i := slices.IndexFunc(df.current.Databases, func(c model.Database) bool { return c.Name == db.Name })
		if i < 0 {
			df.add(phaseDatabase, plan.ActionCreate, res, df.d.CreateDatabase(db))
			continue
		}
		stmts, warns := df.d.AlterDatabase(db, df.current.Databases[i])
		df.warnings = append(df.warnings, warns...)
		df.add(phaseDatabase, plan.ActionUpdate, res, stmts)
	}
	var dropped []string
	for _, c := range df.current.Databases {
		if df.managedDatabase(c.Name) || df.d.IsSystemDatabase(c.Name) || df.ignore.database(c.Name) ||
			(c.Name != "" && c.Name == df.current.CurrentDatabase) {
			continue
		}
		if !df.opts.Prune {
			df.warn("unmanaged database %q (use --prune to drop it)", c.Name)
			continue
		}
		dropped = append(dropped, c.Name)
		df.add(phaseDropDatabase, plan.ActionDrop, fmt.Sprintf("database %q", c.Name), df.d.DropDatabase(c.Name))
	}
	return dropped
}

func (df *differ) managedDatabase(name string) bool {
	return slices.ContainsFunc(df.desired.Databases, func(d model.Database) bool { return d.Name == name })
}

func (df *differ) managedSchema(db, name string) bool {
	return slices.ContainsFunc(df.desired.Schemas, func(s model.Schema) bool { return s.Database == db && s.Name == name })
}

func (df *differ) schemas() {
	for _, s := range df.desired.Schemas {
		res := fmt.Sprintf("schema %q in database %q", s.Name, s.Database)
		i := slices.IndexFunc(df.current.Schemas, func(c model.Schema) bool { return c.Database == s.Database && c.Name == s.Name })
		if i < 0 && !slices.Contains(df.current.InspectedDatabases, s.Database) && df.d.IsSystemSchema(s.Name) {
			// The database is created by this plan (or was not inspected)
			// and already contains the system schemas copied from its
			// template, such as public: only its owner is converged.
			df.add(phaseSchema, plan.ActionUpdate, res, df.d.AlterSchema(s, model.Schema{Database: s.Database, Name: s.Name}))
			continue
		}
		if i < 0 {
			df.add(phaseSchema, plan.ActionCreate, res, df.d.CreateSchema(s))
			continue
		}
		df.add(phaseSchema, plan.ActionUpdate, res, df.d.AlterSchema(s, df.current.Schemas[i]))
	}
	for _, c := range df.current.Schemas {
		if df.managedSchema(c.Database, c.Name) || df.d.IsSystemSchema(c.Name) || df.ignore.schema(c.Name) {
			continue
		}
		if !df.opts.Prune {
			df.warn("unmanaged schema %q in database %q (use --prune to drop it)", c.Name, c.Database)
			continue
		}
		df.add(phaseDropSchema, plan.ActionDrop, fmt.Sprintf("schema %q in database %q", c.Name, c.Database), df.d.DropSchema(c))
	}
}

// owner returns the effective owner of obj after the plan runs.
func (df *differ) owner(obj model.Object) string {
	if o := df.desiredOwner(obj); o != "" {
		return o
	}
	return df.currentOwner(obj)
}

// desiredOwner returns the declared owner of obj, or "" when the owner
// is not managed.
func (df *differ) desiredOwner(obj model.Object) string {
	if obj.Type == model.ObjectSchema {
		for _, s := range df.desired.Schemas {
			if s.Database == obj.Database && s.Name == obj.Schema {
				return s.Owner
			}
		}
		return ""
	}
	for _, d := range df.desired.Databases {
		if d.Name == obj.Database {
			return d.Owner
		}
	}
	return ""
}

// currentOwner returns the owner of obj before the plan runs.
func (df *differ) currentOwner(obj model.Object) string {
	if obj.Type == model.ObjectSchema {
		for _, s := range df.current.Schemas {
			if s.Database == obj.Database && s.Name == obj.Schema {
				return s.Owner
			}
		}
		return ""
	}
	for _, d := range df.current.Databases {
		if d.Name == obj.Database {
			return d.Owner
		}
	}
	return ""
}

// afterOwnerChange returns p as it will be after the planned owner
// changes. PostgreSQL's ALTER ... OWNER TO rewrites the old owner's ACL
// entries to the new owner, so they no longer belong to the old owner.
func (df *differ) afterOwnerChange(p model.Privilege) model.Privilege {
	if df.desired.Engine != model.EnginePostgres || p.Grantee.Host != "" {
		return p
	}
	from, to := df.currentOwner(p.Object), df.desiredOwner(p.Object)
	if from != "" && to != "" && from != to && p.Grantee.Name == from {
		p.Grantee = model.RoleID{Name: to}
	}
	return p
}

type grantGroup struct {
	grantee     model.RoleID
	obj         model.Object
	grantOption bool
}

// privileges converges privileges of declared roles on declared objects.
// Privileges held by object owners are implicit and ignored.
func (df *differ) privileges() {
	implicit := func(p model.Privilege) bool {
		return df.desired.Engine == model.EnginePostgres && p.Grantee.Name == df.owner(p.Object)
	}
	managed := func(p model.Privilege) bool {
		if !df.desiredRole(p.Grantee) || !df.managedDatabase(p.Object.Database) {
			return false
		}
		return p.Object.Type != model.ObjectSchema || df.managedSchema(p.Object.Database, p.Object.Schema)
	}
	want := map[model.PrivilegeKey]model.Privilege{}
	ineffective := map[grantGroup]bool{}
	for _, p := range df.desired.Privileges {
		if implicit(p) {
			ineffective[grantGroup{grantee: p.Grantee, obj: p.Object}] = true
			continue
		}
		want[p.Key()] = p
	}
	for _, g := range sortedGroups(ineffective) {
		df.warn("grant to %q on %s has no effect: %q owns it and holds every privilege implicitly", g.grantee, objectLabel(g.obj), g.grantee)
	}
	// Unknown privileges are re-granted (GRANT is idempotent) and never revoked.
	unknown := df.current.Unreadable.Privileges
	have := map[model.PrivilegeKey]model.Privilege{}
	for _, p := range df.current.Privileges {
		if unknown {
			break
		}
		p = df.afterOwnerChange(p)
		if !managed(p) || implicit(p) {
			continue
		}
		// One entry per grantor may exist; the grant option is held if
		// any of them carries it.
		if c, ok := have[p.Key()]; ok {
			p.GrantOption = p.GrantOption || c.GrantOption
		}
		have[p.Key()] = p
	}

	grants := map[grantGroup][]string{}
	revokes := map[grantGroup][]string{}
	revokeOpts := map[grantGroup][]string{}
	for k, p := range want {
		c, ok := have[k]
		switch {
		case !ok, p.GrantOption && !c.GrantOption:
			g := grantGroup{p.Grantee, p.Object, p.GrantOption}
			grants[g] = append(grants[g], p.Name)
		case !p.GrantOption && c.GrantOption:
			g := grantGroup{p.Grantee, p.Object, false}
			revokeOpts[g] = append(revokeOpts[g], p.Name)
		}
	}
	for k, c := range have {
		if _, ok := want[k]; !ok {
			g := grantGroup{c.Grantee, c.Object, false}
			revokes[g] = append(revokes[g], c.Name)
		}
	}
	res := func(g grantGroup, privs []string, prep string) string {
		return fmt.Sprintf("%s on %s %s %q", strings.Join(privs, ", "), objectLabel(g.obj), prep, g.grantee)
	}
	for _, g := range sortedGroups(grants) {
		privs := sortedPrivs(grants[g])
		df.add(phaseGrant, plan.ActionGrant, res(g, privs, "to"), df.d.Grant(g.grantee, g.obj, privs, g.grantOption))
	}
	for _, g := range sortedGroups(revokeOpts) {
		privs := sortedPrivs(revokeOpts[g])
		df.add(phaseRevoke, plan.ActionRevoke, "grant option for "+res(g, privs, "from"), df.d.RevokeGrantOption(g.grantee, g.obj, privs))
	}
	for _, g := range sortedGroups(revokes) {
		privs := sortedPrivs(revokes[g])
		df.add(phaseRevoke, plan.ActionRevoke, res(g, privs, "from"), df.d.Revoke(g.grantee, g.obj, privs))
	}
}

// objectLabel names obj for plan output.
func objectLabel(obj model.Object) string {
	if obj.Type == model.ObjectSchema {
		return fmt.Sprintf("schema %q in database %q", obj.Schema, obj.Database)
	}
	return fmt.Sprintf("%s %q", obj.Type, obj.Database)
}

func sortedGroups[V any](m map[grantGroup]V) []grantGroup {
	keys := make([]grantGroup, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b grantGroup) int {
		return cmp.Or(
			model.CompareRoleIDs(a.grantee, b.grantee),
			strings.Compare(string(a.obj.Type), string(b.obj.Type)),
			strings.Compare(a.obj.Database, b.obj.Database),
			strings.Compare(a.obj.Schema, b.obj.Schema),
			cmp.Compare(boolInt(a.grantOption), boolInt(b.grantOption)),
		)
	})
	return keys
}

func sortedPrivs(p []string) []string {
	slices.Sort(p)
	return p
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (df *differ) pruneRoles(droppedDatabases []string) {
	// Objects in ignored databases must not be reassigned or dropped.
	var surviving []string
	for _, db := range df.current.Databases {
		if !slices.Contains(droppedDatabases, db.Name) && !df.ignore.database(db.Name) {
			surviving = append(surviving, db.Name)
		}
	}
	if df.current.Unreadable.Roles {
		return
	}
	referenced := df.referencedRoles()
	reliedOn := df.currentUserRoles()
	if df.opts.Prune && df.current.Unreadable.Memberships {
		df.warn("cannot read role memberships: roles granted to the connected user are not protected from --prune")
	}
	for _, r := range df.current.Roles {
		if df.desiredRole(r.ID) || r.ID == df.current.CurrentUser || df.d.IsSystemRole(r.ID) || df.ignore.role(r.ID) {
			continue
		}
		if reason := df.keepRole(r.ID, referenced, reliedOn); reason != "" {
			if df.opts.Prune {
				df.warn("%s %s; not pruned", df.roleResource(r.ID), reason)
			}
			continue
		}
		if !df.opts.Prune {
			df.warn("unmanaged role %q (use --prune to drop it)", r.ID)
			continue
		}
		df.add(phaseDropRole, plan.ActionDrop, df.roleResource(r.ID), df.d.DropRole(r.ID, surviving))
	}
}

// keepRole explains why the undeclared role id must survive --prune, or
// returns "" when it may be dropped.
func (df *differ) keepRole(id model.RoleID, referenced, reliedOn map[model.RoleID]bool) string {
	switch {
	case referenced[id]:
		return "is referenced by the configuration but not declared (declare it to manage it)"
	case reliedOn[id]:
		return fmt.Sprintf("is granted to the connected user %q", df.current.CurrentUser)
	}
	// REASSIGN OWNED also reassigns databases the role owns, and DROP
	// ROLE fails while it still owns objects, so owners of ignored
	// objects are kept.
	if id.Host == "" {
		for _, db := range df.current.Databases {
			if db.Owner == id.Name && df.ignore.database(db.Name) {
				return fmt.Sprintf("owns the ignored database %q", db.Name)
			}
		}
		for _, s := range df.current.Schemas {
			if s.Owner == id.Name && df.ignore.schema(s.Name) && !df.d.IsSystemSchema(s.Name) {
				return fmt.Sprintf("owns the ignored schema %q in database %q", s.Name, s.Database)
			}
		}
	}
	return ""
}

// referencedRoles returns the roles the desired state refers to by name:
// owners, member_of entries and grantees.
func (df *differ) referencedRoles() map[model.RoleID]bool {
	refs := map[model.RoleID]bool{}
	for _, r := range df.desired.Roles {
		for _, m := range r.MemberOf {
			refs[m] = true
		}
	}
	for _, db := range df.desired.Databases {
		if db.Owner != "" {
			refs[model.RoleID{Name: db.Owner}] = true
		}
	}
	for _, s := range df.desired.Schemas {
		if s.Owner != "" {
			refs[model.RoleID{Name: s.Owner}] = true
		}
	}
	for _, p := range df.desired.Privileges {
		refs[p.Grantee] = true
	}
	return refs
}

// currentUserRoles returns the roles granted to the connected user,
// directly or transitively. Dropping them would take away the privileges
// dbfence runs with.
func (df *differ) currentUserRoles() map[model.RoleID]bool {
	seen := map[model.RoleID]bool{}
	queue := []model.RoleID{df.current.CurrentUser}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		cur, ok := df.currentRole(id)
		if !ok {
			continue
		}
		for _, m := range cur.MemberOf {
			if !seen[m] {
				seen[m] = true
				queue = append(queue, m)
			}
		}
	}
	return seen
}

type ignorer struct {
	roles, databases, schemas []*regexp.Regexp
}

func newIgnorer(ig model.Ignore) (ignorer, error) {
	compile := func(ps []string) ([]*regexp.Regexp, error) {
		out := make([]*regexp.Regexp, 0, len(ps))
		for _, p := range ps {
			re, err := model.CompileIgnorePattern(p)
			if err != nil {
				return nil, fmt.Errorf("ignore pattern %q: %w", p, err)
			}
			out = append(out, re)
		}
		return out, nil
	}
	var (
		i   ignorer
		err error
	)
	if i.roles, err = compile(ig.Roles); err != nil {
		return i, err
	}
	if i.databases, err = compile(ig.Databases); err != nil {
		return i, err
	}
	i.schemas, err = compile(ig.Schemas)
	return i, err
}

func matchAny(res []*regexp.Regexp, s string) bool {
	return slices.ContainsFunc(res, func(re *regexp.Regexp) bool { return re.MatchString(s) })
}

func (i ignorer) role(id model.RoleID) bool {
	return matchAny(i.roles, id.Name) || (id.Host != "" && matchAny(i.roles, id.String()))
}
func (i ignorer) database(name string) bool { return matchAny(i.databases, name) }
func (i ignorer) schema(name string) bool   { return matchAny(i.schemas, name) }
