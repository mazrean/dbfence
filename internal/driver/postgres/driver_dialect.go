package postgres

import (
	"fmt"
	"slices"
	"strings"

	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
)

// The Driver overrides some Dialect methods with variants that use the
// state captured by Inspect. Without a prior Inspect they behave like
// Dialect.

// DropRole implements diff.Dialect. Databases that cannot be connected to
// are skipped.
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
	return d.Dialect.DropRole(id, reachable)
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
	return []plan.Statement{plan.SQL(s.Database, fmt.Sprintf("-- CASCADE: the schema contains %d objects, which are dropped too\nDROP SCHEMA %s CASCADE", n, Ident(s.Name)))}
}

// AlterRole implements diff.Dialect. Changes to roles the connected user
// may not alter are reported instead of planned, since they would stop
// apply part-way.
func (d *Driver) AlterRole(r model.Role, cur model.RoleState, force bool) ([]plan.Statement, []string) {
	stmts, warns := d.Dialect.AlterRole(r, cur, force)
	if d.st == nil {
		return stmts, warns
	}
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
func (st *state) inheritOptions(r model.Role) ([]plan.Statement, []string) {
	if r.Inherit == nil || st.version < pg16 {
		return nil, nil
	}
	var stmts []plan.Statement
	var warns []string
	for _, e := range st.members {
		if e.member != r.ID.Name || e.inherit == *r.Inherit ||
			(r.MemberOf != nil && !slices.Contains(r.MemberOf, model.RoleID{Name: e.role})) {
			continue
		}
		q := "GRANT " + Ident(e.role) + " TO " + Ident(e.member) + " WITH INHERIT " + flag(*r.Inherit, "TRUE", "FALSE")
		switch {
		case e.grantor == "":
		case st.superuser || e.grantor == st.user:
			q += " GRANTED BY " + Ident(e.grantor)
		default:
			warns = append(warns, fmt.Sprintf("membership of %q in %q granted by %q has inherit = %v, but %q may not change it", e.member, e.role, e.grantor, e.inherit, st.user))
			continue
		}
		stmts = append(stmts, plan.SQL("", q))
	}
	return stmts, warns
}

// Revoke implements diff.Dialect. Each grantor's grant is revoked.
func (d *Driver) Revoke(grantee model.RoleID, obj model.Object, privs []string) []plan.Statement {
	if d.st == nil {
		return d.Dialect.Revoke(grantee, obj, privs)
	}
	return d.st.revoke(grantee.Name, obj, privs, false)
}

// RevokeGrantOption implements diff.Dialect. Each grantor's grant option
// is revoked.
func (d *Driver) RevokeGrantOption(grantee model.RoleID, obj model.Object, privs []string) []plan.Statement {
	if d.st == nil {
		return d.Dialect.RevokeGrantOption(grantee, obj, privs)
	}
	return d.st.revoke(grantee.Name, obj, privs, true)
}

// RevokeMembership implements diff.Dialect. From PostgreSQL 16 on a
// membership has one grant per grantor, and REVOKE only removes the
// grant named by GRANTED BY.
func (d *Driver) RevokeMembership(member, role model.RoleID) []plan.Statement {
	if d.st == nil || d.st.version < pg16 {
		return d.Dialect.RevokeMembership(member, role)
	}
	return d.st.revokeMembership(member.Name, role.Name)
}

// cascadeNote explains a CASCADE in the plan output.
func cascadeNote(what string, dependents []string) string {
	quoted := make([]string, len(dependents))
	for i, r := range dependents {
		quoted[i] = Ident(r)
	}
	return "-- CASCADE: " + what + " granted on by the grantee to " + strings.Join(quoted, ", ") +
		" are revoked too; declared ones are granted again\n"
}

// revoke renders REVOKE [GRANT OPTION FOR] privs ON obj FROM grantee for
// every grantor. PostgreSQL only removes grants made by the role running
// REVOKE (a superuser acts as the owner), so grants from other grantors
// are revoked as that grantor. Grants the grantee passed on depend on its
// grant option: they are revoked with CASCADE and the declared ones are
// granted again.
func (st *state) revoke(grantee string, obj model.Object, privs []string, optionOnly bool) []plan.Statement {
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
	for _, g := range grantors {
		ps := byGrantor[g]
		dependents := st.aclDependents(obj, grantee, ps)
		q := "REVOKE "
		if optionOnly {
			q += "GRANT OPTION FOR "
		}
		q += strings.Join(ps, ", ") + " ON " + target + " FROM " + Ident(grantee)
		if len(dependents) > 0 {
			q += " CASCADE"
		}
		if g != "" {
			// One simple-protocol query runs as one implicit transaction,
			// so a failing REVOKE also rolls back the SET ROLE.
			q = "SET ROLE " + Ident(g) + "; " + q + "; RESET ROLE"
		}
		if len(dependents) > 0 {
			q = cascadeNote("privileges", dependents) + q
		}
		out = append(out, plan.SQL(db, q))
		regrants = append(regrants, st.regrantPrivileges(obj, dependents, ps)...)
	}
	return append(out, regrants...)
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
// roles, which lose them through CASCADE.
func (st *state) regrantPrivileges(obj model.Object, roles, privs []string) []plan.Statement {
	var out []plan.Statement
	for _, r := range roles {
		if r == st.owners[obj] {
			continue
		}
		var plain, withOption []string
		for _, p := range st.desired.Privileges {
			if p.Grantee.Name != r || p.Object != obj || !slices.Contains(privs, p.Name) {
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
// membership of member in role (PostgreSQL 16+).
func (st *state) revokeMembership(member, role string) []plan.Statement {
	dependents := st.memberDependents(member, role)
	var out []plan.Statement
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
		q := "REVOKE " + Ident(role) + " FROM " + Ident(member)
		if e.grantor != "" {
			q += " GRANTED BY " + Ident(e.grantor)
		}
		if len(dependents) > 0 {
			q = cascadeNote("memberships", dependents) + q + " CASCADE"
		}
		out = append(out, plan.SQL("", q))
	}
	if !revoked {
		out = Dialect{}.RevokeMembership(model.RoleID{Name: member}, model.RoleID{Name: role})
	}
	for _, dep := range dependents {
		if slices.ContainsFunc(st.desired.Roles, func(r model.Role) bool {
			return r.ID.Name == dep && slices.Contains(r.MemberOf, model.RoleID{Name: role})
		}) {
			out = append(out, Dialect{}.GrantMembership(model.RoleID{Name: dep}, model.RoleID{Name: role})...)
		}
	}
	return out
}

// losesMembership reports whether the plan revokes the membership of the
// declared role grantor in role.
func (st *state) losesMembership(grantor, role string) bool {
	return slices.ContainsFunc(st.desired.Roles, func(r model.Role) bool {
		return r.ID.Name == grantor && r.MemberOf != nil && !slices.Contains(r.MemberOf, model.RoleID{Name: role})
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
