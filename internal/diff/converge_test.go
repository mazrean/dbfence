package diff_test

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/driver/postgres"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
)

// simDialect is a PostgreSQL dialect whose statements are references to
// model-level operations, so that a plan can be applied to a
// model.Current. It models the server behavior the diff depends on:
// CREATE DATABASE copies the public schema, the first GRANT on an object
// materializes the owner's privileges and ALTER ... OWNER TO moves the
// old owner's ACL entries to the new owner.
type simDialect struct {
	ops []func(*model.Current) error
	postgres.Dialect
}

func (d *simDialect) op(f func(*model.Current) error) []plan.Statement {
	d.ops = append(d.ops, f)
	return []plan.Statement{plan.SQL("", "op "+strconv.Itoa(len(d.ops)-1))}
}

// apply runs the statements of p against cur.
func (d *simDialect) apply(t *testing.T, p *plan.Plan, cur *model.Current) {
	t.Helper()
	for _, s := range p.Statements() {
		i, err := strconv.Atoi(strings.TrimPrefix(s.SQL(), "op "))
		if err != nil {
			t.Fatalf("unexpected statement %q", s.SQL())
		}
		if err := d.ops[i](cur); err != nil {
			t.Fatalf("apply: %v", err)
		}
	}
}

func roleIndex(cur *model.Current, id model.RoleID) int {
	return slices.IndexFunc(cur.Roles, func(r model.RoleState) bool { return r.ID == id })
}

func setAttrs(st *model.RoleState, r model.Role) {
	set := func(dst *bool, src *bool) {
		if src != nil {
			*dst = *src
		}
	}
	set(&st.Login, r.Login)
	set(&st.Superuser, r.Superuser)
	set(&st.CreateDB, r.CreateDB)
	set(&st.CreateRole, r.CreateRole)
	set(&st.Inherit, r.Inherit)
	set(&st.Replication, r.Replication)
	set(&st.BypassRLS, r.BypassRLS)
	if r.ConnectionLimit != nil {
		st.ConnectionLimit = *r.ConnectionLimit
	}
}

func orName(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (d *simDialect) CreateRole(r model.Role) []plan.Statement {
	return d.op(func(cur *model.Current) error {
		if roleIndex(cur, r.ID) >= 0 {
			return fmt.Errorf("role %q already exists", r.ID)
		}
		st := model.RoleState{ID: r.ID, PasswordReadable: true}
		setAttrs(&st, r)
		cur.Roles = append(cur.Roles, st)
		return nil
	})
}

func (d *simDialect) EnsureRole(r model.Role) []plan.Statement { return d.CreateRole(r) }

func (d *simDialect) AlterRole(r model.Role, st model.RoleState, force bool) ([]plan.Statement, []string) {
	stmts, warns := d.Dialect.AlterRole(r, st, force)
	if len(stmts) == 0 {
		return nil, warns
	}
	return d.op(func(cur *model.Current) error {
		setAttrs(&cur.Roles[roleIndex(cur, r.ID)], r)
		return nil
	}), warns
}

func (d *simDialect) DropRole(id model.RoleID, databases []string) []plan.Statement {
	return d.op(func(cur *model.Current) error {
		owns := func(owner string, db string) bool { return owner == id.Name && !slices.Contains(databases, db) }
		for _, db := range cur.Databases {
			if db.Owner == id.Name && len(databases) == 0 {
				return fmt.Errorf("role %q owns database %q", id, db.Name)
			}
		}
		for _, s := range cur.Schemas {
			if owns(s.Owner, s.Database) {
				return fmt.Errorf("role %q owns schema %q in %q", id, s.Name, s.Database)
			}
		}
		for i := range cur.Databases {
			if cur.Databases[i].Owner == id.Name {
				cur.Databases[i].Owner = cur.CurrentUser.Name
			}
		}
		for i := range cur.Schemas {
			if cur.Schemas[i].Owner == id.Name {
				cur.Schemas[i].Owner = cur.CurrentUser.Name
			}
		}
		cur.Privileges = slices.DeleteFunc(cur.Privileges, func(p model.Privilege) bool { return p.Grantee == id })
		cur.Roles = slices.DeleteFunc(cur.Roles, func(r model.RoleState) bool { return r.ID == id })
		for i := range cur.Roles {
			cur.Roles[i].MemberOf = slices.DeleteFunc(cur.Roles[i].MemberOf, func(m model.RoleID) bool { return m == id })
		}
		return nil
	})
}

func (d *simDialect) GrantMembership(member, role model.RoleID, opts model.MembershipOptions) ([]plan.Statement, []string) {
	return d.op(func(cur *model.Current) error {
		i := roleIndex(cur, member)
		if i < 0 || roleIndex(cur, role) < 0 {
			return fmt.Errorf("grant %q to %q: role missing", role, member)
		}
		r := &cur.Roles[i]
		if !slices.Contains(r.MemberOf, role) {
			r.MemberOf = append(r.MemberOf, role)
			// A new grant inherits by default if the member does.
			setMemberOptions(r, role, model.MembershipState{Inherit: r.Inherit, Set: true}, opts)
		}
		return nil
	}), nil
}

func setMemberOptions(r *model.RoleState, role model.RoleID, st model.MembershipState, opts model.MembershipOptions) {
	if opts.Admin != nil {
		st.Admin = *opts.Admin
	}
	if opts.Inherit != nil {
		st.Inherit = *opts.Inherit
	}
	if opts.Set != nil {
		st.Set = *opts.Set
	}
	if r.MemberOptions == nil {
		r.MemberOptions = map[model.RoleID]model.MembershipState{}
	}
	r.MemberOptions[role] = st
}

func (d *simDialect) AlterMembership(member, role model.RoleID, want model.MembershipOptions, have model.MembershipState) ([]plan.Statement, []string) {
	return d.op(func(cur *model.Current) error {
		r := &cur.Roles[roleIndex(cur, member)]
		setMemberOptions(r, role, r.MemberOptions[role], want)
		return nil
	}), nil
}

func (d *simDialect) RevokeMembership(member, role model.RoleID) ([]plan.Statement, []string) {
	return d.op(func(cur *model.Current) error {
		i := roleIndex(cur, member)
		cur.Roles[i].MemberOf = slices.DeleteFunc(cur.Roles[i].MemberOf, func(m model.RoleID) bool { return m == role })
		delete(cur.Roles[i].MemberOptions, role)
		return nil
	}), nil
}

func (d *simDialect) requireRole(cur *model.Current, name string) error {
	if name != "" && roleIndex(cur, model.RoleID{Name: name}) < 0 {
		return fmt.Errorf("role %q does not exist", name)
	}
	return nil
}

func (d *simDialect) CreateDatabase(db model.Database) []plan.Statement {
	return d.op(func(cur *model.Current) error {
		if slices.ContainsFunc(cur.Databases, func(c model.Database) bool { return c.Name == db.Name }) {
			return fmt.Errorf("database %q already exists", db.Name)
		}
		if err := d.requireRole(cur, db.Owner); err != nil {
			return err
		}
		db.Owner = orName(db.Owner, cur.CurrentUser.Name)
		cur.Databases = append(cur.Databases, db)
		cur.Schemas = append(cur.Schemas, model.Schema{Database: db.Name, Name: "public", Owner: "pg_database_owner"})
		cur.InspectedDatabases = append(cur.InspectedDatabases, db.Name)
		return nil
	})
}

// newOwner applies aclnewowner: ACL entries of the old owner move to the
// new owner and merge with its existing entries.
func newOwner(cur *model.Current, obj model.Object, from, to string) {
	var out []model.Privilege
	for _, p := range cur.Privileges {
		if p.Object == obj && p.Grantee == (model.RoleID{Name: from}) {
			p.Grantee = model.RoleID{Name: to}
		}
		if i := slices.IndexFunc(out, func(o model.Privilege) bool { return o.Key() == p.Key() }); i >= 0 {
			out[i].GrantOption = out[i].GrantOption || p.GrantOption
			continue
		}
		out = append(out, p)
	}
	cur.Privileges = out
}

func (d *simDialect) AlterDatabase(db, st model.Database) ([]plan.Statement, []string) {
	stmts, warns := d.Dialect.AlterDatabase(db, st)
	if len(stmts) == 0 {
		return nil, warns
	}
	return d.op(func(cur *model.Current) error {
		if err := d.requireRole(cur, db.Owner); err != nil {
			return err
		}
		i := slices.IndexFunc(cur.Databases, func(c model.Database) bool { return c.Name == db.Name })
		newOwner(cur, dbObj(db.Name), cur.Databases[i].Owner, db.Owner)
		cur.Databases[i].Owner = db.Owner
		return nil
	}), warns
}

func (d *simDialect) DropDatabase(name string) []plan.Statement {
	return d.op(func(cur *model.Current) error {
		if name == cur.CurrentDatabase {
			return fmt.Errorf("cannot drop the currently open database %q", name)
		}
		cur.Databases = slices.DeleteFunc(cur.Databases, func(c model.Database) bool { return c.Name == name })
		cur.Schemas = slices.DeleteFunc(cur.Schemas, func(s model.Schema) bool { return s.Database == name })
		cur.Privileges = slices.DeleteFunc(cur.Privileges, func(p model.Privilege) bool { return p.Object.Database == name })
		cur.InspectedDatabases = slices.DeleteFunc(cur.InspectedDatabases, func(n string) bool { return n == name })
		return nil
	})
}

func schemaIndex(cur *model.Current, db, name string) int {
	return slices.IndexFunc(cur.Schemas, func(c model.Schema) bool { return c.Database == db && c.Name == name })
}

func (d *simDialect) CreateSchema(s model.Schema) []plan.Statement {
	return d.op(func(cur *model.Current) error {
		if schemaIndex(cur, s.Database, s.Name) >= 0 {
			return fmt.Errorf("schema %q already exists in %q", s.Name, s.Database)
		}
		if err := d.requireRole(cur, s.Owner); err != nil {
			return err
		}
		s.Owner = orName(s.Owner, cur.CurrentUser.Name)
		cur.Schemas = append(cur.Schemas, s)
		return nil
	})
}

func (d *simDialect) AlterSchema(s, st model.Schema) []plan.Statement {
	if len(d.Dialect.AlterSchema(s, st)) == 0 {
		return nil
	}
	return d.op(func(cur *model.Current) error {
		i := schemaIndex(cur, s.Database, s.Name)
		if i < 0 {
			return fmt.Errorf("schema %q does not exist in %q", s.Name, s.Database)
		}
		obj := model.Object{Type: model.ObjectSchema, Database: s.Database, Schema: s.Name}
		newOwner(cur, obj, cur.Schemas[i].Owner, s.Owner)
		cur.Schemas[i].Owner = s.Owner
		return nil
	})
}

func (d *simDialect) DropSchema(s model.Schema) []plan.Statement {
	return d.op(func(cur *model.Current) error {
		cur.Schemas = slices.DeleteFunc(cur.Schemas, func(c model.Schema) bool { return c.Database == s.Database && c.Name == s.Name })
		cur.Privileges = slices.DeleteFunc(cur.Privileges, func(p model.Privilege) bool {
			return p.Object.Type == model.ObjectSchema && p.Object.Database == s.Database && p.Object.Schema == s.Name
		})
		return nil
	})
}

// materialize turns a NULL ACL into the owner's explicit privileges, as
// the first GRANT or REVOKE on an object does.
func materialize(cur *model.Current, obj model.Object) {
	if slices.ContainsFunc(cur.Privileges, func(p model.Privilege) bool { return p.Object == obj }) {
		return
	}
	var owner string
	privs := []string{"CONNECT", "CREATE", "TEMPORARY"}
	if obj.Type == model.ObjectSchema {
		owner = cur.Schemas[schemaIndex(cur, obj.Database, obj.Schema)].Owner
		privs = []string{"CREATE", "USAGE"}
	} else {
		owner = cur.Databases[slices.IndexFunc(cur.Databases, func(c model.Database) bool { return c.Name == obj.Database })].Owner
	}
	for _, n := range privs {
		cur.Privileges = append(cur.Privileges, model.Privilege{Grantee: model.RoleID{Name: owner}, Object: obj, Name: n, GrantOption: true})
	}
}

func (d *simDialect) Grant(grantee model.RoleID, obj model.Object, privs []string, grantOption bool) []plan.Statement {
	return d.op(func(cur *model.Current) error {
		materialize(cur, obj)
		for _, n := range privs {
			p := model.Privilege{Grantee: grantee, Object: obj, Name: n, GrantOption: grantOption}
			if i := slices.IndexFunc(cur.Privileges, func(c model.Privilege) bool { return c.Key() == p.Key() }); i >= 0 {
				cur.Privileges[i].GrantOption = cur.Privileges[i].GrantOption || grantOption
				continue
			}
			cur.Privileges = append(cur.Privileges, p)
		}
		return nil
	})
}

func (d *simDialect) Revoke(grantee model.RoleID, obj model.Object, privs []string) ([]plan.Statement, []string) {
	return d.op(func(cur *model.Current) error {
		materialize(cur, obj)
		cur.Privileges = slices.DeleteFunc(cur.Privileges, func(p model.Privilege) bool {
			return p.Grantee == grantee && p.Object == obj && slices.Contains(privs, p.Name)
		})
		return nil
	}), nil
}

func (d *simDialect) RevokeGrantOption(grantee model.RoleID, obj model.Object, privs []string) ([]plan.Statement, []string) {
	return d.op(func(cur *model.Current) error {
		for i, p := range cur.Privileges {
			if p.Grantee == grantee && p.Object == obj && slices.Contains(privs, p.Name) {
				cur.Privileges[i].GrantOption = false
			}
		}
		return nil
	}), nil
}

// convergeDesired is a configuration exercising owners, memberships,
// schemas including public, and grants on both object types.
func convergeDesired(dbOwner, apiOwner string) *model.Desired {
	api := model.Object{Type: model.ObjectSchema, Database: "app", Schema: "api"}
	public := model.Object{Type: model.ObjectSchema, Database: "app", Schema: "public"}
	return &model.Desired{
		Engine: model.EnginePostgres,
		Roles: []model.Role{
			{ID: pgID("app_owner"), Login: new(false)},
			{ID: pgID("readonly"), Login: new(false)},
			{ID: pgID("app"), Login: new(true), MemberOf: []model.RoleID{pgID("readonly")}},
		},
		Databases: []model.Database{{Name: "app", Owner: dbOwner}},
		Schemas: []model.Schema{
			{Database: "app", Name: "api", Owner: apiOwner},
			{Database: "app", Name: "public", Owner: "app_owner"},
		},
		Privileges: []model.Privilege{
			{Grantee: pgID("app"), Object: dbObj("app"), Name: "CONNECT"},
			{Grantee: pgID("app"), Object: dbObj("app"), Name: "TEMPORARY"},
			{Grantee: pgID("readonly"), Object: api, Name: "USAGE"},
			{Grantee: pgID("app_owner"), Object: dbObj("app"), Name: "CONNECT"},
			{Grantee: pgID("readonly"), Object: public, Name: "USAGE", GrantOption: true},
		},
	}
}

// withOptions declares options on the membership of app in readonly.
func withOptions(admin, inherit, set *bool) *model.Desired {
	d := convergeDesired("app_owner", "app_owner")
	d.Roles[2].MemberOptions = map[model.RoleID]model.MembershipOptions{pgID("readonly"): {Admin: admin, Inherit: inherit, Set: set}}
	return d
}

func emptyCurrent() *model.Current {
	return &model.Current{
		CurrentUser:     pgID("admin"),
		CurrentDatabase: "postgres",
		Roles:           []model.RoleState{{ID: pgID("admin"), Login: true, Superuser: true}},
		Databases:       []model.Database{{Name: "postgres", Owner: "admin"}},
	}
}

// TestComputeConverges applies each plan to the model and checks that
// planning again yields no changes.
func TestComputeConverges(t *testing.T) {
	t.Parallel()
	legacy := func() *model.Current {
		c := emptyCurrent()
		c.Roles = append(c.Roles,
			model.RoleState{ID: pgID("legacy_owner")}, model.RoleState{ID: pgID("legacy_grp")},
			model.RoleState{ID: pgID("dba")}, model.RoleState{ID: pgID("stray"), Login: true})
		c.Roles[0].MemberOf = []model.RoleID{pgID("dba")}
		c.Databases = append(c.Databases, model.Database{Name: "conn"}, model.Database{Name: "junk", Owner: "stray"})
		return c
	}
	withLegacy := func() *model.Desired {
		d := convergeDesired("legacy_owner", "app_owner")
		d.Roles[2].MemberOf = append(d.Roles[2].MemberOf, pgID("legacy_grp"))
		return d
	}
	tests := []struct {
		current func() *model.Current
		name    string
		steps   []*model.Desired
		opts    diff.Options
	}{
		{name: "bootstrap", current: emptyCurrent, steps: []*model.Desired{convergeDesired("app_owner", "app_owner")}},
		{
			name:    "owner moves to a grantee and back",
			current: emptyCurrent,
			steps: []*model.Desired{
				convergeDesired("app_owner", "app_owner"),
				convergeDesired("app", "readonly"),
				convergeDesired("app_owner", "app_owner"),
				convergeDesired("readonly", "app"),
			},
		},
		{name: "prune keeps referenced roles", current: legacy, steps: []*model.Desired{withLegacy()}, opts: diff.Options{Prune: true}},
		{
			name:    "membership options",
			current: emptyCurrent,
			steps:   []*model.Desired{withOptions(new(true), new(false), nil), withOptions(new(false), new(true), new(false)), withOptions(nil, nil, nil)},
		},
		{name: "empty", current: emptyCurrent, steps: []*model.Desired{{Engine: model.EnginePostgres}}, opts: diff.Options{Prune: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cur := tt.current()
			for i, desired := range tt.steps {
				d := &simDialect{}
				p, err := diff.Compute(desired, cur, d, tt.opts)
				if err != nil {
					t.Fatalf("step %d: %v", i, err)
				}
				d.apply(t, p, cur)
				again, err := diff.Compute(desired, cur, &simDialect{}, tt.opts)
				if err != nil {
					t.Fatalf("step %d: second plan: %v", i, err)
				}
				if !again.Empty() {
					t.Errorf("step %d: second plan is not empty: %v", i, resources(again))
				}
			}
		})
	}
}

// TestComputeShuffled checks that the plan does not depend on the order
// in which the current state was read.
func TestComputeShuffled(t *testing.T) {
	t.Parallel()
	base := emptyCurrent()
	base.Roles = append(base.Roles,
		model.RoleState{ID: pgID("app"), MemberOf: []model.RoleID{pgID("x"), pgID("y"), pgID("readonly")}},
		model.RoleState{ID: pgID("x")}, model.RoleState{ID: pgID("y")}, model.RoleState{ID: pgID("s1")}, model.RoleState{ID: pgID("s2")})
	base.Databases = append(base.Databases, model.Database{Name: "app", Owner: "x"}, model.Database{Name: "l1"}, model.Database{Name: "l2"})
	base.Schemas = []model.Schema{{Database: "app", Name: "api", Owner: "x"}, {Database: "app", Name: "j1"}, {Database: "app", Name: "j2"}}
	base.InspectedDatabases = []string{"app"}
	api := model.Object{Type: model.ObjectSchema, Database: "app", Schema: "api"}
	for _, g := range []string{"x", "app", "y"} {
		for _, n := range []string{"CONNECT", "CREATE", "TEMPORARY"} {
			base.Privileges = append(base.Privileges, model.Privilege{Grantee: pgID(g), Object: dbObj("app"), Name: n, GrantOption: g == "x"})
		}
		base.Privileges = append(base.Privileges, model.Privilege{Grantee: pgID(g), Object: api, Name: "CREATE"})
	}
	desired := convergeDesired("app_owner", "app_owner")
	desired.Roles = append(desired.Roles, model.Role{ID: pgID("x")}, model.Role{ID: pgID("y")})

	run := func(cur *model.Current) []string {
		p, err := diff.Compute(desired, cur, postgres.Dialect{}, diff.Options{Prune: true})
		if err != nil {
			t.Fatal(err)
		}
		return append(statements(p), p.Warnings...)
	}
	want := run(base)
	r := rand.New(rand.NewPCG(1, 2))
	for range 20 {
		cur := *base
		cur.Roles = slices.Clone(base.Roles)
		cur.Databases = slices.Clone(base.Databases)
		cur.Schemas = slices.Clone(base.Schemas)
		cur.Privileges = slices.Clone(base.Privileges)
		r.Shuffle(len(cur.Roles), func(i, j int) { cur.Roles[i], cur.Roles[j] = cur.Roles[j], cur.Roles[i] })
		r.Shuffle(len(cur.Databases), func(i, j int) { cur.Databases[i], cur.Databases[j] = cur.Databases[j], cur.Databases[i] })
		r.Shuffle(len(cur.Schemas), func(i, j int) { cur.Schemas[i], cur.Schemas[j] = cur.Schemas[j], cur.Schemas[i] })
		r.Shuffle(len(cur.Privileges), func(i, j int) { cur.Privileges[i], cur.Privileges[j] = cur.Privileges[j], cur.Privileges[i] })
		if d := cmp.Diff(want, run(&cur)); d != "" {
			t.Fatalf("plan depends on input order (-want +got):\n%s", d)
		}
	}
}
