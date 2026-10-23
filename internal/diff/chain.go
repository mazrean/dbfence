package diff

import (
	"maps"
	"slices"

	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
)

// edge is a membership of member in role.
type edge struct{ member, role model.RoleID }

// chain tracks the memberships through which the connected user has
// roles, so that no revoke of another role's membership takes one of them
// away from it.
type chain struct {
	edges  map[edge]bool
	relied map[model.RoleID]bool
	user   model.RoleID
}

func newChain(cur *model.Current) *chain {
	c := &chain{edges: map[edge]bool{}, user: cur.CurrentUser}
	for _, r := range cur.Roles {
		for _, m := range r.MemberOf {
			c.edges[edge{r.ID, m}] = true
		}
	}
	c.relied = c.reach(c.edges)
	return c
}

// reach returns the roles the connected user is a member of, directly or
// transitively, through edges.
func (c *chain) reach(edges map[edge]bool) map[model.RoleID]bool {
	seen := map[model.RoleID]bool{}
	queue := []model.RoleID{c.user}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for e := range edges {
			if e.member == id && !seen[e.role] {
				seen[e.role] = true
				queue = append(queue, e.role)
			}
		}
	}
	return seen
}

// cut applies the membership grants and revokes of stmts in order and
// returns the first role the connected user has now that a revoke among
// them would take away. Only when there is none are the changes kept, and
// ok is true. Revokes of only the ADMIN OPTION keep the membership.
func (c *chain) cut(stmts []plan.Statement) (lost model.RoleID, ok bool) {
	edges := make(map[edge]bool, len(c.edges))
	for e := range c.edges {
		edges[e] = true
	}
	for _, s := range stmts {
		t := s.Target()
		e := edge{t.Grantee, t.Role}
		switch {
		case s.Kind() == plan.KindGrantMembership:
			edges[e] = true
		case s.Kind() == plan.KindRevokeMembership && !t.Option:
			delete(edges, e)
			reach := c.reach(edges)
			for _, id := range model.SortRoleIDs(slices.Collect(maps.Keys(c.relied))) {
				if !reach[id] {
					return id, false
				}
			}
		}
	}
	c.edges = edges
	return model.RoleID{}, true
}
