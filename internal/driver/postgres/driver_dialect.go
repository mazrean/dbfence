package postgres

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
)

// The Driver overrides some Dialect methods with variants that use the
// state captured by Inspect. Without a prior Inspect they behave like
// Dialect.

// DropRole implements diff.Dialect. Databases that cannot be connected to
// are skipped. DROP OWNED revokes what the role holds with CASCADE, which
// also removes the grants it made to other roles from its grant option
// and, from PostgreSQL 16 on, the memberships it granted; the declared
// ones are granted again. Memberships that give the role the privileges
// of an owner it granted on are revoked first (see ownerMemberships).
func (d *Driver) DropRole(id model.RoleID, databases []string) []plan.Statement {
	if d.st == nil {
		return d.Dialect.DropRole(id, databases)
	}
	var reachable []string
	for _, db := range databases {
		if d.st.connectable[db] {
			reachable = append(reachable, db)
		}
	}
	out := d.Dialect.DropRole(id, reachable)
	if len(reachable) == 0 {
		// No DROP OWNED runs; DROP ROLE fails on the dependencies.
		return out
	}
	out = append(d.st.revokeOwnerMemberships(id.Name), out...)
	return append(out, d.st.regrantAfterDrop(id.Name, databases, reachable)...)
}

// ownerMemberships returns the memberships of role through which it has
// the privileges of the owner of an object on which it granted privileges
// to others. While role holds them, revoking its grant option does not
// cascade to those grants (it keeps the option through the owner), so
// DROP OWNED leaves them behind and DROP ROLE fails on them.
func (st *state) ownerMemberships(role string) []memberEntry {
	var owners []string
	for _, e := range st.acl {
		if o := st.owners[e.obj]; e.grantor == role && e.grantee != role && o != "" && o != role && !slices.Contains(owners, o) {
			owners = append(owners, o)
		}
	}
	var out []memberEntry
	for _, m := range st.members {
		if m.member == role && m.inherit && slices.ContainsFunc(owners, func(o string) bool { return m.role == o || st.inherits(m.role, o) }) {
			out = append(out, m)
		}
	}
	return out
}

// inherits reports whether member has the privileges of role through
// memberships with INHERIT.
func (st *state) inherits(member, role string) bool {
	seen := []string{member}
	for queue := []string{member}; len(queue) > 0; queue = queue[1:] {
		for _, e := range st.members {
			if e.member != queue[0] || !e.inherit || slices.Contains(seen, e.role) {
				continue
			}
			if e.role == role {
				return true
			}
			seen = append(seen, e.role)
			queue = append(queue, e.role)
		}
	}
	return false
}

// revokeOwnerMemberships revokes the ownerMemberships of the pruned role
// before DROP OWNED, so that DROP OWNED revokes the grants it made. The
// memberships it granted from them go too (CASCADE, PostgreSQL 16+);
// regrantAfterDrop grants the declared ones again. Memberships the
// connected user may not revoke are skipped; pruneWarnings names them.
func (st *state) revokeOwnerMemberships(role string) []plan.Statement {
	var out []plan.Statement
	var done []string
	for _, e := range st.ownerMemberships(role) {
		if !st.canManageMembership(e.role, e.grantor) || (st.version < pg16 && slices.Contains(done, e.role)) {
			continue
		}
		done = append(done, e.role)
		q := "REVOKE " + Ident(e.role) + " FROM " + Ident(role)
		if st.version >= pg16 && e.grantor != "" {
			q += " GRANTED BY " + Ident(e.grantor)
		}
		if st.version >= pg16 && len(st.memberDependents(role, e.role)) > 0 {
			q += " CASCADE"
		}
		note := fmt.Sprintf("revoked first: through it %s has the privileges of the owner of objects it granted privileges on, so DROP OWNED would not revoke those grants",
			noteRole(role))
		out = append(out, plan.SQL("", q).WithNote(note))
	}
	return out
}

// regrantAfterDrop grants again the declared privileges and memberships
// that dropping role takes from other roles: those granted, directly or
// transitively, by role. Grants on objects role owns survive, since
// REASSIGN OWNED makes the new owner their grantor. Objects in databases
// that are dropped or ignored (not in surviving), and schemas in
// databases where DROP OWNED does not run (not in reachable), are left
// alone.
func (st *state) regrantAfterDrop(role string, surviving, reachable []string) []plan.Statement {
	privs := map[model.Object][]string{}
	var objs []model.Object
	for _, e := range st.acl {
		if e.grantor != role || e.grantee == role || st.owners[e.obj] == role {
			continue
		}
		scope := surviving
		if e.obj.Type == model.ObjectSchema {
			scope = reachable
		}
		if !slices.Contains(scope, e.obj.Database) {
			continue
		}
		if _, ok := privs[e.obj]; !ok {
			objs = append(objs, e.obj)
		}
		if !slices.Contains(privs[e.obj], e.priv) {
			privs[e.obj] = append(privs[e.obj], e.priv)
		}
	}
	slices.SortFunc(objs, func(a, b model.Object) int {
		return cmp.Or(strings.Compare(string(a.Type), string(b.Type)), strings.Compare(a.Database, b.Database), strings.Compare(a.Schema, b.Schema))
	})
	var out []plan.Statement
	for _, obj := range objs {
		ps := slices.Sorted(slices.Values(privs[obj]))
		out = append(out, st.regrantPrivileges(obj, role, st.aclDependents(obj, role, ps), ps)...)
	}
	var granted []string
	for _, e := range st.members {
		// Memberships do not depend on their grantor before 16.
		if st.version >= pg16 && e.grantor == role && !slices.Contains(granted, e.role) {
			granted = append(granted, e.role)
		}
	}
	slices.Sort(granted)
	for _, g := range granted {
		// pruneWarnings names the grants the connected user may not make.
		stmts, _ := st.regrantMembers(g, st.memberDependents(role, g))
		out = append(out, stmts...)
	}
	if len(out) > 0 {
		out[0] = out[0].WithNote("CASCADE: grants made by " + noteRole(role) + " are revoked with it; declared ones are granted again")
	}
	return out
}

// DropSchema implements diff.Dialect. A schema that still contains
// objects is dropped with CASCADE, as DROP DATABASE drops the objects of
// a pruned database, and the plan says so.
func (d *Driver) DropSchema(s model.Schema) []plan.Statement {
	n := 0
	if d.st != nil {
		n = d.st.objects[model.Object{Type: model.ObjectSchema, Database: s.Database, Schema: s.Name}]
	}
	if n == 0 {
		return d.Dialect.DropSchema(s)
	}
	return []plan.Statement{plan.SQL(s.Database, "DROP SCHEMA "+Ident(s.Name)+" CASCADE").
		WithNote(fmt.Sprintf("CASCADE: the schema contains %d objects, which are dropped too", n))}
}

// AlterRole implements diff.Dialect. Changes to roles the connected user
// may not alter are reported instead of planned, since they would stop
// apply part-way.
func (d *Driver) AlterRole(r model.Role, cur model.RoleState, force bool) ([]plan.Statement, []string) {
	if d.st == nil {
		return d.Dialect.AlterRole(r, cur, force)
	}
	stmts, warns := d.Dialect.alterRole(r, cur, force, true)
	inherit, inheritWarns := d.st.inheritOptions(r)
	stmts = append(stmts, inherit...)
	warns = append(warns, inheritWarns...)
	if len(stmts) == 0 || d.st.canAlter(r.ID.Name) {
		return stmts, warns
	}
	return nil, append(warns, fmt.Sprintf("role %q differs from the configuration, but %q may not alter it (it needs ADMIN OPTION on the role, or superuser for superuser roles); not changed", r.ID, d.st.user))
}

// inheritOptions aligns the INHERIT option of the existing memberships of
// r with its declared inherit attribute. From PostgreSQL 16 on rolinherit
// is only the default for new grants; each grant carries its own option.
// Memberships that declare their own inherit option are left to
// AlterMembership.
func (st *state) inheritOptions(r model.Role) ([]plan.Statement, []string) {
	if r.Inherit == nil || st.version < pg16 {
		return nil, nil
	}
	var stmts []plan.Statement
	var warns []string
	for _, e := range st.members {
		role := model.RoleID{Name: e.role}
		if e.member != r.ID.Name || e.inherit == *r.Inherit ||
			(r.MemberOf != nil && !slices.Contains(r.MemberOf, role)) || r.MemberOptions[role].Inherit != nil {
			continue
		}
		by, ok := st.grantedBy(e.grantor)
		if !ok {
			warns = append(warns, fmt.Sprintf("membership of %q in %q granted by %q has inherit = %v, but %q may not change it", e.member, e.role, e.grantor, e.inherit, st.user))
			continue
		}
		stmts = append(stmts, plan.SQL("", grantMembership(e.member, e.role, model.MembershipOptions{Inherit: r.Inherit})+by))
	}
	return stmts, warns
}

// grantedBy returns the GRANTED BY clause that changes the grant made by
// grantor, or false when the connected user may not act as grantor.
func (st *state) grantedBy(grantor string) (string, bool) {
	switch {
	case grantor == "":
		return "", true
	case st.superuser || grantor == st.user:
		return " GRANTED BY " + Ident(grantor), true
	default:
		return "", false
	}
}

// AlterMembership implements diff.Dialect. From PostgreSQL 16 on each
// grantor's grant of a membership carries its own options, so each grant
// is changed.
func (d *Driver) AlterMembership(member, role model.RoleID, want model.MembershipOptions, have model.MembershipState) ([]plan.Statement, []string) {
	if d.st == nil || d.st.version < pg16 {
		return d.Dialect.AlterMembership(member, role, want, have)
	}
	return d.st.alterMembership(member.Name, role.Name, want, have)
}

// alterMembership changes the options of every grant of the membership of
// member in role (PostgreSQL 16+). Revoking ADMIN OPTION cascades to the
// memberships member granted with it; declared ones are granted again.
func (st *state) alterMembership(member, role string, want model.MembershipOptions, have model.MembershipState) ([]plan.Statement, []string) {
	revokeAdmin := want.Admin != nil && !*want.Admin && have.Admin
	var dependents []string
	if revokeAdmin {
		dependents = st.memberDependents(member, role)
	}
	var out []plan.Statement
	var warns []string
	for _, e := range st.members {
		if e.role != role || e.member != member || st.losesMembership(e.grantor, role) {
			// A grant whose grantor loses the membership or its ADMIN
			// OPTION is removed by CASCADE and granted again if declared.
			continue
		}
		var opts model.MembershipOptions
		if want.Inherit != nil && *want.Inherit != e.inherit {
			opts.Inherit = want.Inherit
		}
		if want.Set != nil && *want.Set != e.set {
			opts.Set = want.Set
		}
		if !(revokeAdmin && e.admin) && opts == (model.MembershipOptions{}) {
			continue
		}
		by, ok := st.grantedBy(e.grantor)
		if !ok {
			warns = append(warns, fmt.Sprintf("options of the membership of %q in %q granted by %q differ from the configuration, but %q may not change them", member, role, e.grantor, st.user))
			continue
		}
		if revokeAdmin && e.admin {
			q := "REVOKE ADMIN OPTION FOR " + Ident(role) + " FROM " + Ident(member) + by
			if len(dependents) == 0 {
				out = append(out, plan.SQL("", q))
			} else {
				out = append(out, plan.SQL("", q+" CASCADE").WithNote(cascadeNote("memberships in "+strconv.Quote(role), member, dependents)))
			}
		}
		if opts != (model.MembershipOptions{}) {
			out = append(out, plan.SQL("", grantMembership(member, role, opts)+by))
		}
	}
	if want.Admin != nil && *want.Admin && !have.Admin {
		// The new grant may be a separate row (another grantor), so it
		// carries the declared INHERIT and SET options too.
		out = append(out, plan.SQL("", grantMembership(member, role, want)))
	}
	if revokeAdmin {
		stmts, regrantWarns := st.regrantMembers(role, dependents)
		out = append(out, stmts...)
		warns = append(warns, regrantWarns...)
	}
	return out, warns
}

// Revoke implements diff.Dialect. Each grantor's grant is revoked.
func (d *Driver) Revoke(grantee model.RoleID, obj model.Object, privs []string) ([]plan.Statement, []string) {
	if d.st == nil {
		return d.Dialect.Revoke(grantee, obj, privs)
	}
	return d.st.revoke(grantee.Name, obj, privs, false)
}

// RevokeGrantOption implements diff.Dialect. Each grantor's grant option
// is revoked.
func (d *Driver) RevokeGrantOption(grantee model.RoleID, obj model.Object, privs []string) ([]plan.Statement, []string) {
	if d.st == nil {
		return d.Dialect.RevokeGrantOption(grantee, obj, privs)
	}
	return d.st.revoke(grantee.Name, obj, privs, true)
}

// DefaultPublicPrivileges implements diff.PublicDefaulter for the
// inspected server version.
func (d *Driver) DefaultPublicPrivileges(obj model.Object) []string {
	if d.st == nil {
		return d.Dialect.DefaultPublicPrivileges(obj)
	}
	return defaultPublicPrivileges(obj, d.st.version)
}

// RevokeMembership implements diff.Dialect. From PostgreSQL 16 on a
// membership has one grant per grantor, and REVOKE only removes the
// grant named by GRANTED BY.
func (d *Driver) RevokeMembership(member, role model.RoleID) ([]plan.Statement, []string) {
	if d.st == nil {
		return d.Dialect.RevokeMembership(member, role)
	}
	if d.st.version < pg16 {
		if !d.st.canManageMembership(role.Name, "") {
			return nil, []string{d.st.membershipDenied("revoke", member.Name, role.Name, "")}
		}
		return d.Dialect.RevokeMembership(member, role)
	}
	return d.st.revokeMembership(member.Name, role.Name)
}

// GrantMembership implements diff.Dialect. A grant the connected user may
// not make is reported instead of planned.
func (d *Driver) GrantMembership(member, role model.RoleID, opts model.MembershipOptions) ([]plan.Statement, []string) {
	if d.st != nil && !d.st.canManageMembership(role.Name, d.st.user) {
		return nil, []string{d.st.membershipDenied("grant", member.Name, role.Name, "")}
	}
	return d.Dialect.GrantMembership(member, role, opts)
}

// canManageMembership reports whether the connected user may grant role,
// or revoke the grant of it made by grantor. From PostgreSQL 16 on that
// needs ADMIN OPTION on role and acting as grantor (only a superuser
// may name another grantor in GRANTED BY); before 16, ADMIN OPTION or
// CREATEROLE for a role that is not a superuser. Roles created by the
// plan are granted by their creator, which receives ADMIN OPTION on them.
func (st *state) canManageMembership(role, grantor string) bool {
	if st.superuser {
		return true
	}
	a, known := st.roles[role]
	if st.version >= pg16 {
		return (grantor == "" || grantor == st.user) && (!known || a.admin)
	}
	return !known || a.admin || (st.createRole && !a.superuser)
}

// membershipDenied explains a membership change that canManageMembership
// rejected.
func (st *state) membershipDenied(verb, member, role, grantor string) string {
	what := fmt.Sprintf("membership of %q in %q", member, role)
	if grantor != "" && grantor != st.user {
		what += fmt.Sprintf(" granted by %q", grantor)
	}
	need := "ADMIN OPTION on the role"
	switch {
	case st.version < pg16:
		need = "ADMIN OPTION on the role, or CREATEROLE for a role that is not a superuser"
	case grantor != "" && grantor != st.user:
		need = "superuser, since another role granted it"
	}
	return fmt.Sprintf("%s differs from the configuration, but %q may not %s it (it needs %s); not changed", what, st.user, verb, need)
}

// cascadeNote explains a CASCADE in the plan output: what grantor
// granted to dependents is revoked with it. what names the privileges or
// memberships, such as `memberships in "grp"`.
func cascadeNote(what, grantor string, dependents []string) string {
	quoted := make([]string, len(dependents))
	for i, r := range dependents {
		quoted[i] = noteRole(r)
	}
	return "CASCADE: " + what + " that " + noteRole(grantor) + " granted to " + strings.Join(quoted, ", ") +
		" are revoked too; declared ones are granted again"
}

// noteRole names a role in a plan note: PUBLIC unquoted, any other role
// Go-quoted like objectLabel, so that line breaks and other control
// characters in a name read from the server are escaped.
func noteRole(name string) string {
	if (model.RoleID{Name: name}).IsPublic() {
		return "PUBLIC"
	}
	return strconv.Quote(name)
}

// objectLabel names obj for plan output.
func objectLabel(obj model.Object) string {
	if obj.Type == model.ObjectSchema {
		return fmt.Sprintf("schema %q in database %q", obj.Schema, obj.Database)
	}
	return fmt.Sprintf("database %q", obj.Database)
}

// revoke renders REVOKE [GRANT OPTION FOR] privs ON obj FROM grantee for
// every grantor. PostgreSQL only removes grants made by the role running
// REVOKE (a superuser acts as the owner), so grants from other grantors
// are revoked as that grantor. Grants the grantee passed on depend on its
// grant option: they are revoked with CASCADE and the declared ones are
// granted again. Grants of grantors the connected user may not SET ROLE
// to are reported instead.
func (st *state) revoke(grantee string, obj model.Object, privs []string, optionOnly bool) ([]plan.Statement, []string) {
	owner := st.owners[obj]
	asSelf := func(grantor string) bool {
		return grantor == "" || grantor == owner || (grantor == st.user && !st.superuser)
	}
	byGrantor := map[string][]string{}
	for _, priv := range privs {
		found := false
		for _, e := range st.acl {
			if e.obj == obj && e.grantee == grantee && e.priv == priv && (e.grantable || !optionOnly) {
				g := e.grantor
				switch {
				case asSelf(g):
					g = ""
				case st.losesGrantOption(g, obj, priv):
					// The plan revokes the grant option of g with
					// CASCADE, which removes this grant as well.
					found = true
					continue
				}
				if !slices.Contains(byGrantor[g], priv) {
					byGrantor[g] = append(byGrantor[g], priv)
				}
				found = true
			}
		}
		if !found {
			byGrantor[""] = append(byGrantor[""], priv)
		}
	}
	grantors := make([]string, 0, len(byGrantor))
	for g := range byGrantor {
		grantors = append(grantors, g)
	}
	slices.Sort(grantors)

	db, target := onObject(obj)
	var out, regrants []plan.Statement
	var warns []string
	for _, g := range grantors {
		ps := byGrantor[g]
		if g != "" && !st.canSet(g) {
			what := strings.Join(ps, ", ")
			if optionOnly {
				what = "grant option for " + what
			}
			warns = append(warns, fmt.Sprintf("%s on %s granted by %q to %s differs from the configuration, but %q may not SET ROLE %q to revoke it (it needs superuser, or SET on the grantor); not changed",
				what, objectLabel(obj), g, Grantee(grantee), st.user, g))
			continue
		}
		dependents := st.aclDependents(obj, grantee, ps)
		q := "REVOKE "
		if optionOnly {
			q += "GRANT OPTION FOR "
		}
		q += strings.Join(ps, ", ") + " ON " + target + " FROM " + Grantee(grantee)
		if len(dependents) > 0 {
			q += " CASCADE"
		}
		// Exec runs a statement with AsRole in a transaction of its own,
		// under SET LOCAL ROLE, so the role never outlives it.
		stmt := plan.SQL(db, q).WithRole(g)
		if len(dependents) > 0 {
			stmt = stmt.WithNote(cascadeNote("privileges on "+objectLabel(obj), grantee, dependents))
		}
		out = append(out, stmt)
		regrants = append(regrants, st.regrantPrivileges(obj, grantee, dependents, ps)...)
	}
	return append(out, regrants...), warns
}

// losesGrantOption reports whether the plan revokes priv on obj, or its
// grant option, from the declared role grantor: diff converges privileges
// of declared roles on the objects it revokes on.
func (st *state) losesGrantOption(grantor string, obj model.Object, priv string) bool {
	if !slices.ContainsFunc(st.desired.Roles, func(r model.Role) bool { return r.ID.Name == grantor }) {
		return false
	}
	return !slices.ContainsFunc(st.desired.Privileges, func(p model.Privilege) bool {
		return p.Grantee.Name == grantor && p.Object == obj && p.Name == priv && p.GrantOption
	})
}

// aclDependents returns the roles that hold privs on obj through grants
// made, directly or transitively, by grantee.
func (st *state) aclDependents(obj model.Object, grantee string, privs []string) []string {
	var out []string
	queue := []string{grantee}
	for len(queue) > 0 {
		grantor := queue[0]
		queue = queue[1:]
		for _, e := range st.acl {
			if e.obj == obj && e.grantor == grantor && e.grantee != grantee && slices.Contains(privs, e.priv) && !slices.Contains(out, e.grantee) {
				out = append(out, e.grantee)
				queue = append(queue, e.grantee)
			}
		}
	}
	slices.Sort(out)
	return out
}

// regrantPrivileges grants the declared privileges among privs on obj to
// roles, which lose the grants made, directly or through them, by
// grantor through CASCADE. A privilege a role still holds from another
// grantor that keeps it is not granted again.
func (st *state) regrantPrivileges(obj model.Object, grantor string, roles, privs []string) []plan.Statement {
	removed := append([]string{grantor}, roles...)
	keeps := func(r string, p model.Privilege) bool {
		return slices.ContainsFunc(st.acl, func(e aclEntry) bool {
			return e.obj == obj && e.grantee == r && e.priv == p.Name && (e.grantable || !p.GrantOption) &&
				!slices.Contains(removed, e.grantor) && (e.grantor == st.owners[obj] || !st.losesGrantOption(e.grantor, obj, p.Name))
		})
	}
	var out []plan.Statement
	for _, r := range roles {
		if r == st.owners[obj] {
			continue
		}
		var plain, withOption []string
		for _, p := range st.desired.Privileges {
			if p.Grantee.Name != r || p.Object != obj || !slices.Contains(privs, p.Name) || keeps(r, p) {
				continue
			}
			if p.GrantOption {
				withOption = append(withOption, p.Name)
			} else {
				plain = append(plain, p.Name)
			}
		}
		if len(plain) > 0 {
			out = append(out, Dialect{}.Grant(model.RoleID{Name: r}, obj, plain, false)...)
		}
		if len(withOption) > 0 {
			out = append(out, Dialect{}.Grant(model.RoleID{Name: r}, obj, withOption, true)...)
		}
	}
	return out
}

// revokeMembership renders one REVOKE ... GRANTED BY per grantor of the
// membership of member in role (PostgreSQL 16+). Grants the connected
// user may not revoke are reported instead.
func (st *state) revokeMembership(member, role string) ([]plan.Statement, []string) {
	dependents := st.memberDependents(member, role)
	var out []plan.Statement
	var warns []string
	revoked := false
	for _, e := range st.members {
		if e.role != role || e.member != member {
			continue
		}
		revoked = true
		if st.losesMembership(e.grantor, role) {
			// The plan revokes the grantor's membership with CASCADE,
			// which removes this grant as well.
			continue
		}
		if !st.canManageMembership(role, e.grantor) {
			warns = append(warns, st.membershipDenied("revoke", member, role, e.grantor))
			continue
		}
		q := "REVOKE " + Ident(role) + " FROM " + Ident(member)
		if e.grantor != "" {
			q += " GRANTED BY " + Ident(e.grantor)
		}
		stmt := plan.SQL("", q)
		if len(dependents) > 0 {
			stmt = plan.SQL("", q+" CASCADE").WithNote(cascadeNote("memberships in "+strconv.Quote(role), member, dependents))
		}
		out = append(out, stmt)
	}
	if !revoked {
		if !st.canManageMembership(role, "") {
			return nil, []string{st.membershipDenied("revoke", member, role, "")}
		}
		out = []plan.Statement{plan.SQL("", "REVOKE "+Ident(role)+" FROM "+Ident(member))}
	}
	if len(out) == 0 {
		// Nothing is revoked, so nothing cascades.
		return nil, warns
	}
	stmts, regrantWarns := st.regrantMembers(role, dependents)
	return append(out, stmts...), append(warns, regrantWarns...)
}

// regrantMembers grants role again to the dependents that declare the
// membership, which they lose through CASCADE. When the connected user
// may not grant role, it warns instead.
func (st *state) regrantMembers(role string, dependents []string) ([]plan.Statement, []string) {
	id := model.RoleID{Name: role}
	var out []plan.Statement
	var warns []string
	for _, dep := range dependents {
		i := slices.IndexFunc(st.desired.Roles, func(r model.Role) bool {
			return r.ID.Name == dep && slices.Contains(r.MemberOf, id)
		})
		switch {
		case i < 0:
		case !st.canManageMembership(role, st.user):
			warns = append(warns, fmt.Sprintf("the plan revokes the declared membership of %q in %q with CASCADE, but %q may not grant it again (it needs ADMIN OPTION on the role); it stays revoked until granted", dep, role, st.user))
		default:
			out = append(out, newMembership(dep, role, st.desired.Roles[i].MemberOptions[id]))
		}
	}
	return out, warns
}

// losesMembership reports whether the plan revokes the membership of the
// declared role grantor in role, or its ADMIN OPTION on role, with
// CASCADE. The connected user keeps both (see diff).
func (st *state) losesMembership(grantor, role string) bool {
	if grantor == st.user {
		return false
	}
	id := model.RoleID{Name: role}
	return slices.ContainsFunc(st.desired.Roles, func(r model.Role) bool {
		if r.ID.Name != grantor || r.MemberOf == nil {
			return false
		}
		if !slices.Contains(r.MemberOf, id) {
			return true
		}
		admin := r.MemberOptions[id].Admin
		return admin != nil && !*admin && slices.ContainsFunc(st.members, func(e memberEntry) bool {
			return e.member == grantor && e.role == role && e.admin
		})
	})
}

// memberDependents returns the members of role whose grants were made,
// directly or transitively, by member.
func (st *state) memberDependents(member, role string) []string {
	var out []string
	queue := []string{member}
	for len(queue) > 0 {
		grantor := queue[0]
		queue = queue[1:]
		for _, e := range st.members {
			if e.role == role && e.grantor == grantor && e.member != member && !slices.Contains(out, e.member) {
				out = append(out, e.member)
				queue = append(queue, e.member)
			}
		}
	}
	slices.Sort(out)
	return out
}
