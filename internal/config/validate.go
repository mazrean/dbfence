package config

import (
	"fmt"
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
				fmt.Sprintf("grant targets role %q, which is not declared.", g.grantee)))
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
