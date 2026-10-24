package plan

import (
	"slices"

	"github.com/mazrean/dbfence/internal/model"
)

// Select returns the plan of the changes of p that act on one of addrs,
// together with the changes that create the roles, databases and schemas
// those name, in the order of p. Changes are kept or left out whole, so
// that statements planned together, such as a CASCADE revoke and its
// re-grants, stay together. The warnings of p are kept.
//
// A change acts on a role address when one of its statements acts on the
// role itself (create, alter, drop, default roles) or grants or revokes a
// membership of it as the member or a privilege to it; on a database or
// schema address when one acts on the object itself or grants or revokes
// a privilege on it.
func (p *Plan) Select(addrs []model.Address) *Plan {
	keep := make([]bool, len(p.Changes))
	var need names
	for i, c := range p.Changes {
		if slices.ContainsFunc(c.Statements, func(s Statement) bool { return slices.ContainsFunc(addrs, s.actsOn) }) {
			keep[i] = true
			need.add(c)
		}
	}
	for changed := true; changed; {
		changed = false
		for i, c := range p.Changes {
			if !keep[i] && slices.ContainsFunc(c.Statements, need.created) {
				keep[i], changed = true, true
				need.add(c)
			}
		}
	}
	out := &Plan{Warnings: slices.Clone(p.Warnings)}
	for i, c := range p.Changes {
		if keep[i] {
			out.Changes = append(out.Changes, c)
		}
	}
	return out
}

// actsOn reports whether s acts on the object a names (see Select).
func (s Statement) actsOn(a model.Address) bool {
	t := s.target
	if a.Role != (model.RoleID{}) {
		if t.Grantee != (model.RoleID{}) {
			return t.Grantee == a.Role
		}
		return t.Object == ObjectRole && t.Role == a.Role
	}
	want := ObjectDatabase
	if a.Schema != "" {
		want = ObjectSchema
	}
	return t.Object == want && t.Pattern == "" && t.Database == a.Database && t.Schema == a.Schema
}

// names are the roles, databases and schemas that selected statements
// name.
type names struct {
	roles     []model.RoleID
	databases []string
	schemas   []model.Object
}

func (n *names) add(c Change) {
	for _, s := range c.Statements {
		t := s.target
		n.roles = append(n.roles, t.Role, t.Grantee, t.Grantor, model.RoleID{Name: t.Owner}, model.RoleID{Name: s.AsRole})
		n.roles = append(n.roles, s.defaults...)
		n.databases = append(n.databases, t.Database, s.Database)
		if t.Schema != "" {
			n.schemas = append(n.schemas, model.Object{Type: model.ObjectSchema, Database: t.Database, Schema: t.Schema})
		}
	}
}

// created reports whether s creates an object that n names.
func (n *names) created(s Statement) bool {
	t := s.target
	switch s.kind {
	case KindCreateRole:
		return t.Role != (model.RoleID{}) && slices.Contains(n.roles, t.Role)
	case KindCreateDatabase:
		return t.Database != "" && slices.Contains(n.databases, t.Database)
	case KindCreateSchema:
		return slices.Contains(n.schemas, model.Object{Type: model.ObjectSchema, Database: t.Database, Schema: t.Schema})
	case KindOther, KindAlterRole, KindDropRole, KindGrant, KindRevoke, KindGrantMembership, KindRevokeMembership,
		KindSetDefaultRole, KindAlterDatabase, KindDropDatabase, KindAlterSchema, KindDropSchema, KindReassign, KindDropOwned:
		// Only creates are pulled in.
	}
	return false
}
