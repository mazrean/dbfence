package config

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/mazrean/dbfence/internal/model"
)

// validate checks cross-block consistency of the decoded configuration.
func validate(d *decoded) hcl.Diagnostics {
	var diags hcl.Diagnostics

	dbs := map[string]resource{}
	for _, db := range d.databases {
		if prev, dup := dbs[db.db.Name]; dup {
			diags = append(diags, errAt(db.res.nameRange, "Duplicate database",
				fmt.Sprintf("database %q (block %q) is declared more than once; database %q at %s already declares it.",
					db.db.Name, db.res.block.Labels[0], prev.block.Labels[0], loc(prev.block.DefRange))))
			continue
		}
		dbs[db.db.Name] = db.res
	}

	roles := map[model.RoleID]resource{}
	for _, r := range d.roles {
		if prev, dup := roles[r.role.ID]; dup {
			diags = append(diags, errAt(r.res.nameRange, "Duplicate role",
				fmt.Sprintf("role %q (%s %q) is declared more than once; %s %q at %s already declares it.",
					r.role.ID, r.typ, r.res.block.Labels[0], prev.block.Type, prev.block.Labels[0], loc(prev.block.DefRange))))
			continue
		}
		roles[r.role.ID] = r.res
	}

	diags = append(diags, validateMemberships(d, roles)...)

	schemas := map[[2]string]resource{}
	for _, s := range d.schemas {
		if _, ok := dbs[s.schema.Database]; !ok {
			diags = append(diags, errAt(attrRange(s.res.attrs, "database", s.res.block.DefRange), "Undeclared database",
				fmt.Sprintf("schema %q belongs to database %q, which is not declared.", s.schema.Name, s.schema.Database)))
		}
		key := [2]string{s.schema.Database, s.schema.Name}
		if prev, dup := schemas[key]; dup {
			diags = append(diags, errAt(s.res.nameRange, "Duplicate schema",
				fmt.Sprintf("schema %q in database %q (block %q) is declared more than once; schema %q at %s already declares it.",
					s.schema.Name, s.schema.Database, s.res.block.Labels[0], prev.block.Labels[0], loc(prev.block.DefRange))))
			continue
		}
		schemas[key] = s.res
	}

	diags = append(diags, validateGrants(d, dbs, roles, schemas)...)
	return diags
}

func validateGrants(d *decoded, dbs map[string]resource, roles map[model.RoleID]resource, schemas map[[2]string]resource) hcl.Diagnostics {
	var diags hcl.Diagnostics
	type target struct {
		grantee model.RoleID
		object  model.Object
	}
	seen := map[model.PrivilegeKey]int{}
	option := map[target]int{}
	for i, g := range d.grants {
		if _, ok := dbs[g.object.Database]; !ok {
			diags = append(diags, errAt(attrRange(g.attrs, "database", g.block.DefRange), "Undeclared database",
				fmt.Sprintf("grant to %q targets database %q, which is not declared.", g.grantee, g.object.Database)))
		}
		if _, ok := schemas[[2]string{g.object.Database, g.object.Schema}]; g.object.Type == model.ObjectSchema && !ok {
			diags = append(diags, errAt(attrRange(g.attrs, "schema", g.block.DefRange), "Undeclared schema",
				fmt.Sprintf("grant to %q targets schema %q, which is not declared.", g.grantee, g.object)))
		}
		if _, ok := roles[g.grantee]; !ok {
			diags = append(diags, errAt(attrRange(g.attrs, "role", g.block.DefRange), "Undeclared role",
				fmt.Sprintf("grant targets role %q, which is not declared.%s", g.grantee, otherHosts(roles, g.grantee, "user"))))
		}

		// MySQL keeps WITH GRANT OPTION per account and database, not per
		// privilege, so blocks for the same level must agree on it.
		t := target{grantee: g.grantee, object: g.object}
		if j, ok := option[t]; !ok {
			option[t] = i
		} else if d.engine == model.EngineMySQL && d.grants[j].option != g.option {
			diags = append(diags, errAt(attrRange(g.attrs, "with_grant_option", g.block.DefRange), "Conflicting grant option",
				fmt.Sprintf("MySQL keeps the grant option per account and database, so every grant block for %q on database %q must use the same with_grant_option; the grant block at %s uses %t.",
					g.grantee, g.object.Database, loc(d.grants[j].block.DefRange), d.grants[j].option)))
		}

		// Report overlapping privileges once per earlier block.
		overlaps := map[int][]string{}
		var order []int
		for _, n := range g.names {
			k := model.PrivilegeKey{Grantee: g.grantee, Object: g.object, Name: n}
			j, dup := seen[k]
			if !dup {
				seen[k] = i
				continue
			}
			if _, ok := overlaps[j]; !ok {
				order = append(order, j)
			}
			overlaps[j] = append(overlaps[j], n)
		}
		for _, j := range order {
			subject := "privilege %s is"
			if len(overlaps[j]) > 1 {
				subject = "privileges %s are"
			}
			detail := fmt.Sprintf(subject+" already granted on %s to %q by the grant block at %s.",
				strings.Join(overlaps[j], ", "), g.object, g.grantee, loc(d.grants[j].block.DefRange))
			if d.engine == model.EnginePostgres && d.grants[j].option != g.option {
				detail += " To give only some privileges the grant option, list them in their own grant block and remove them from the other one."
			}
			diags = append(diags, errAt(attrRange(g.attrs, "privileges", g.block.DefRange), "Duplicate privilege", detail))
		}
	}
	return diags
}

// validateMemberships rejects membership cycles among declared roles and,
// on MySQL, host-less member_of entries that miss the declared account.
func validateMemberships(d *decoded, roles map[model.RoleID]resource) hcl.Diagnostics {
	var diags hcl.Diagnostics
	byID := map[model.RoleID]*decodedRole{}
	for i := range d.roles {
		if _, dup := byID[d.roles[i].role.ID]; !dup {
			byID[d.roles[i].role.ID] = &d.roles[i]
		}
	}
	for _, r := range d.roles {
		for _, id := range r.hostless {
			if _, ok := roles[id]; !ok {
				if hint := otherHosts(roles, id, "role"); hint != "" {
					diags = append(diags, errAt(attrRange(r.res.attrs, "member_of", r.res.block.DefRange), "Undeclared role",
						fmt.Sprintf("member_of entry %q resolves to %q, which is not declared.%s", id.Name, id, hint)))
				}
			}
		}
	}

	const (
		unvisited = iota
		visiting
		done
	)
	state := map[model.RoleID]int{}
	var path []model.RoleID
	var visit func(r *decodedRole)
	visit = func(r *decodedRole) {
		state[r.role.ID] = visiting
		path = append(path, r.role.ID)
		for _, m := range r.role.MemberOf {
			parent, ok := byID[m]
			if !ok || m == r.role.ID {
				continue
			}
			switch state[m] {
			case unvisited:
				visit(parent)
			case visiting:
				start := slices.Index(path, m)
				names := make([]string, 0, len(path)-start+1)
				for _, id := range slices.Concat(path[start:], []model.RoleID{m}) {
					names = append(names, strconv.Quote(id.String()))
				}
				diags = append(diags, errAt(attrRange(r.res.attrs, "member_of", r.res.block.DefRange), "Membership cycle",
					fmt.Sprintf("role memberships form a cycle: %s.", strings.Join(names, " -> "))))
			}
		}
		path = path[:len(path)-1]
		state[r.role.ID] = done
	}
	for i := range d.roles {
		if state[d.roles[i].role.ID] == unvisited {
			visit(&d.roles[i])
		}
	}
	return diags
}

// otherHosts hints at declared MySQL accounts with the same name as id but
// another host.
func otherHosts(roles map[model.RoleID]resource, id model.RoleID, ref string) string {
	if id.Host == "" {
		return ""
	}
	var found []string
	for other, res := range roles {
		if other.Name == id.Name && other != id {
			found = append(found, fmt.Sprintf("%q (%s %q)", other, res.block.Type, res.block.Labels[0]))
		}
	}
	if len(found) == 0 {
		return ""
	}
	slices.Sort(found)
	return fmt.Sprintf(" Declared accounts named %q: %s; reference one with %s.<label>.id.", id.Name, strings.Join(found, ", "), ref)
}
