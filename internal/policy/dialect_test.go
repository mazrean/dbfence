package policy_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/driver/mysql"
	"github.com/mazrean/dbfence/internal/driver/postgres"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
	"github.com/mazrean/dbfence/internal/policy"
)

func my(name string) model.RoleID { return model.RoleID{Name: name, Host: "%"} }

// myCurrent is a MySQL server where the connected account dbfence has
// dba_role and app_role, with dba_role as its default role.
func myCurrent() *model.Current {
	return &model.Current{
		CurrentUser: my("dbfence"),
		Roles: []model.RoleState{
			{ID: my("dbfence"), Login: true, MemberOf: []model.RoleID{my("dba_role"), my("app_role")}, DefaultRoles: []model.RoleID{my("dba_role")}},
			{ID: my("dba_role")},
			{ID: my("app_role")},
			{ID: my("app"), Login: true, MemberOf: []model.RoleID{my("app_role")}, DefaultRoles: []model.RoleID{my("app_role")}},
		},
	}
}

// Statements built by the engine dialects, as diff would plan them, that
// the check must refuse or pass.
func TestVerifyDialectStatements(t *testing.T) {
	t.Parallel()
	myd, pgd := mysql.Dialect{}, postgres.Dialect{}
	roleState := func(c *model.Current, id model.RoleID) model.RoleState {
		if i := slices.IndexFunc(c.Roles, func(r model.RoleState) bool { return r.ID == id }); i >= 0 {
			return c.Roles[i]
		}
		return model.RoleState{ID: id}
	}
	setDefaults := func(c *model.Current, id model.RoleID, roles ...model.RoleID) []plan.Statement {
		return myd.SetDefaultRoles(model.Role{ID: id, MemberOf: roles}, roleState(c, id))
	}
	withoutReassign := func(stmts []plan.Statement) []plan.Statement {
		return slices.DeleteFunc(stmts, func(s plan.Statement) bool { return s.Kind() == plan.KindReassign })
	}
	no := false
	first := func(stmts []plan.Statement, _ []string) []plan.Statement { return stmts }
	inheriting := pgCurrent()
	inheriting.Roles[0].MemberOptions = map[model.RoleID]model.MembershipState{pg("ops"): {Inherit: true, Set: true}}
	// admin -> ops -> base, every membership with INHERIT and SET.
	chained := pgCurrent()
	chained.Roles[0].MemberOptions = map[model.RoleID]model.MembershipState{pg("ops"): {Inherit: true, Set: true}}
	chained.Roles[1].MemberOptions = map[model.RoleID]model.MembershipState{pg("base"): {Inherit: true, Set: true}}
	// The connected user is no superuser; CONNECT on the database it is
	// connected to is held by holders.
	postgresDB := model.Object{Type: model.ObjectDatabase, Database: "postgres"}
	connecting := func(holders ...model.RoleID) *model.Current {
		c := pgCurrent()
		for _, h := range holders {
			c.Privileges = append(c.Privileges, model.Privilege{Grantee: h, Object: postgresDB, Name: "CONNECT"})
		}
		return c
	}
	// admin inherits from ops, and ops from base, which holds CONNECT.
	inheritsConnect := connecting(pg("base"))
	inheritsConnect.Roles[0].Inherit, inheritsConnect.Roles[1].Inherit = true, true
	inheritsConnect.Roles[0].MemberOptions = map[model.RoleID]model.MembershipState{pg("ops"): {Inherit: true}}
	inheritsConnect.Roles[1].MemberOptions = map[model.RoleID]model.MembershipState{pg("base"): {Inherit: true}}
	// admin owns the database it is connected to; ALTER DATABASE ... OWNER
	// TO moves its CONNECT to the new owner.
	ownedConnecting := func(holders ...model.RoleID) *model.Current {
		c := connecting(holders...)
		c.Databases[0].Owner = "admin"
		return c
	}
	postgresTo := func(owner string) []plan.Statement {
		return first(pgd.AlterDatabase(model.Database{Name: "postgres", Owner: owner}, model.Database{Name: "postgres", Owner: "admin"}))
	}
	unknownDefaults := myCurrent()
	unknownDefaults.Roles[0].DefaultRoles, unknownDefaults.Roles[0].DefaultRolesUnknown = nil, true
	tests := []struct {
		current *model.Current
		desired *model.Desired
		name    string
		want    []string
		stmts   []plan.Statement
		pg      bool
	}{
		{
			name:  "default role none on the connected account",
			stmts: setDefaults(myCurrent(), my("dbfence")),
			want:  []string{`removes "dba_role"@"%" from the default roles of the connected user "dbfence"@"%"`},
		},
		{
			name:  "default roles of the connected account narrowed",
			stmts: setDefaults(myCurrent(), my("dbfence"), my("app_role")),
			want:  []string{`removes "dba_role"@"%" from the default roles`},
		},
		{name: "default roles of the connected account kept", stmts: setDefaults(myCurrent(), my("dbfence"), my("app_role"), my("dba_role"))},
		{name: "default role none on another account", stmts: setDefaults(myCurrent(), my("app"))},
		{
			name:    "unknown default roles of the connected account",
			current: unknownDefaults,
			stmts:   setDefaults(unknownDefaults, my("dbfence"), my("dba_role")),
			want:    []string{`removes "app_role"@"%" from the default roles`},
		},
		{
			name:    "unknown default roles of the connected account keep its memberships",
			current: unknownDefaults,
			stmts:   setDefaults(unknownDefaults, my("dbfence"), my("dba_role"), my("app_role")),
		},
		{
			name:    "connected account missing from the role list",
			current: &model.Current{CurrentUser: my("dbfence")},
			stmts:   setDefaults(myCurrent(), my("dbfence"), my("dba_role"), my("app_role")),
			want:    []string{"current default roles are unknown"},
		},
		{
			name:  "drop owned without reassign owned",
			pg:    true,
			stmts: withoutReassign(pgd.DropRole(pg("stray"), []string{"app"})),
			want:  []string{`drops the objects role "stray" owns in database "app"`},
		},
		{
			name:  "revoke on the chain of the connected user",
			pg:    true,
			stmts: first(pgd.RevokeMembership(pg("ops"), pg("base"))),
			want:  []string{`revokes the membership of "ops" in "base", through which the connected user "admin" has "base"`},
		},
		{
			name: "mysql admin option dropped on the chain of the connected account",
			current: &model.Current{CurrentUser: my("dbfence"), Roles: []model.RoleState{
				{ID: my("dbfence"), MemberOf: []model.RoleID{my("ops")}, DefaultRoles: []model.RoleID{my("ops")}},
				{ID: my("ops"), MemberOf: []model.RoleID{my("dba_role")}},
				{ID: my("dba_role")},
			}},
			stmts: first(myd.AlterMembership(my("ops"), my("dba_role"), model.MembershipOptions{Admin: &no}, model.MembershipState{Admin: true})),
			want:  []string{`revokes the membership of "ops"@"%" in "dba_role"@"%"`},
		},
		{
			name: "noinherit on the connected user",
			pg:   true,
			stmts: first(pgd.AlterRole(model.Role{ID: pg("admin"), Inherit: &no},
				model.RoleState{ID: pg("admin"), Login: true, Inherit: true}, false)),
			want: []string{`sets NOINHERIT on the connected user "admin"`},
		},
		{
			name:  "noinherit on another role",
			pg:    true,
			stmts: first(pgd.AlterRole(model.Role{ID: pg("ops"), Inherit: &no}, model.RoleState{ID: pg("ops"), Inherit: true}, false)),
		},
		{
			name:    "inherit and set false on a membership of the connected user",
			pg:      true,
			current: inheriting,
			stmts:   first(pgd.AlterMembership(pg("admin"), pg("ops"), model.MembershipOptions{Inherit: &no, Set: &no}, model.MembershipState{Inherit: true, Set: true})),
			want: []string{
				`sets INHERIT FALSE on the membership of the connected user "admin" in "ops"`,
				`sets SET FALSE on the membership of the connected user "admin" in "ops"`,
			},
		},
		{
			name:  "inherit and set false on a membership of the connected user without them",
			pg:    true,
			stmts: first(pgd.AlterMembership(pg("admin"), pg("ops"), model.MembershipOptions{Inherit: &no, Set: &no}, model.MembershipState{Inherit: true, Set: true})),
		},
		{
			name:  "inherit false on a new membership of the connected user",
			pg:    true,
			stmts: first(pgd.GrantMembership(pg("admin"), pg("app"), model.MembershipOptions{Inherit: &no, Set: &no})),
		},
		{
			name: "inherit false on a membership of the connected user while memberships are unreadable",
			pg:   true,
			current: func() *model.Current {
				c := pgCurrent()
				c.Unreadable.Memberships = true
				return c
			}(),
			stmts: first(pgd.GrantMembership(pg("admin"), pg("app"), model.MembershipOptions{Inherit: &no})),
			want:  []string{`sets INHERIT FALSE on the membership of the connected user "admin" in "app"`},
		},
		{
			name:    "inherit false on a membership of another role",
			pg:      true,
			current: inheriting,
			stmts:   first(pgd.AlterMembership(pg("ops"), pg("base"), model.MembershipOptions{Inherit: &no}, model.MembershipState{Inherit: true})),
		},
		{
			name:    "inherit and set false on a membership along the chain of the connected user",
			pg:      true,
			current: chained,
			stmts:   first(pgd.AlterMembership(pg("ops"), pg("base"), model.MembershipOptions{Inherit: &no, Set: &no}, model.MembershipState{Inherit: true, Set: true})),
			want: []string{
				`sets INHERIT FALSE on the membership of "ops" in "base", through which the connected user "admin" has its roles`,
				`sets SET FALSE on the membership of "ops" in "base", through which the connected user "admin" has its roles`,
			},
		},
		{
			name:    "inherit false on a new membership of a role along the chain",
			pg:      true,
			current: chained,
			stmts:   first(pgd.GrantMembership(pg("ops"), pg("app"), model.MembershipOptions{Inherit: &no, Set: &no})),
		},
		{
			name:    "noinherit on a role along the chain of the connected user",
			pg:      true,
			current: chained,
			stmts:   first(pgd.AlterRole(model.Role{ID: pg("ops"), Inherit: &no}, model.RoleState{ID: pg("ops"), Inherit: true}, false)),
			want:    []string{`sets NOINHERIT on "ops", through which the connected user "admin" has its roles`},
		},
		{
			name:    "noinherit on the end of the chain of the connected user",
			pg:      true,
			current: chained,
			stmts:   first(pgd.AlterRole(model.Role{ID: pg("base"), Inherit: &no}, model.RoleState{ID: pg("base"), Inherit: true}, false)),
		},
		{
			name:    "revoke CONNECT on the connected database from PUBLIC",
			pg:      true,
			current: connecting(model.PublicRole),
			stmts:   first(pgd.Revoke(model.PublicRole, postgresDB, []string{"CONNECT", "TEMPORARY"})),
			want:    []string{`revokes CONNECT on the database "postgres" dbfence is connected to from PUBLIC, through which the connected user "admin" connects to it`},
		},
		{
			name:    "revoke CONNECT on the connected database from the connected user",
			pg:      true,
			current: connecting(pg("admin")),
			stmts:   first(pgd.Revoke(pg("admin"), postgresDB, []string{"CONNECT"})),
			want:    []string{`revokes CONNECT on the database "postgres" dbfence is connected to from "admin"`},
		},
		{
			name:    "revoke CONNECT on the connected database from a role the connected user inherits from",
			pg:      true,
			current: inheritsConnect,
			stmts:   first(pgd.Revoke(pg("base"), postgresDB, []string{"CONNECT"})),
			want:    []string{`revokes CONNECT on the database "postgres" dbfence is connected to from "base"`},
		},
		{
			name: "revoke CONNECT on the connected database while privileges are unreadable",
			pg:   true,
			current: func() *model.Current {
				c := pgCurrent()
				c.Unreadable.Privileges = true
				return c
			}(),
			stmts: first(pgd.Revoke(model.PublicRole, postgresDB, []string{"CONNECT"})),
			want:  []string{`revokes CONNECT on the database "postgres" dbfence is connected to from PUBLIC`},
		},
		{
			name:    "revoke CONNECT on the connected database after granting it to the connected user",
			pg:      true,
			current: connecting(model.PublicRole),
			stmts: slices.Concat(pgd.Grant(pg("admin"), postgresDB, []string{"CONNECT"}, false),
				first(pgd.Revoke(model.PublicRole, postgresDB, []string{"CONNECT"}))),
		},
		{
			name:    "revoke CONNECT on the connected database from PUBLIC while the connected user has it",
			pg:      true,
			current: connecting(model.PublicRole, pg("admin")),
			stmts:   first(pgd.Revoke(model.PublicRole, postgresDB, []string{"CONNECT"})),
		},
		{
			name:    "revoke TEMPORARY on the connected database from PUBLIC",
			pg:      true,
			current: connecting(model.PublicRole),
			stmts:   first(pgd.Revoke(model.PublicRole, postgresDB, []string{"TEMPORARY"})),
		},
		{
			name:    "revoke CONNECT on another database from PUBLIC",
			pg:      true,
			current: connecting(model.PublicRole),
			stmts:   first(pgd.Revoke(model.PublicRole, model.Object{Type: model.ObjectDatabase, Database: "app"}, []string{"CONNECT"})),
		},
		{
			name: "revoke CONNECT on the connected database from PUBLIC with a superuser",
			pg:   true,
			current: func() *model.Current {
				c := connecting(model.PublicRole)
				c.Roles[0].Superuser = true
				return c
			}(),
			stmts: first(pgd.Revoke(model.PublicRole, postgresDB, []string{"CONNECT"})),
		},
		{
			name:    "owner change of the connected database that moves the only CONNECT of the connected user",
			pg:      true,
			current: ownedConnecting(pg("admin")),
			stmts:   postgresTo("owner"),
			want:    []string{`changes the owner of the database "postgres" dbfence is connected to from "admin" to "owner", which moves the CONNECT through which the connected user "admin" connects to it`},
		},
		{
			name: "owner change of the connected database while privileges are unreadable",
			pg:   true,
			current: func() *model.Current {
				c := ownedConnecting()
				c.Unreadable.Privileges = true
				return c
			}(),
			stmts: postgresTo("owner"),
			want:  []string{`changes the owner of the database "postgres" dbfence is connected to from "admin" to "owner"`},
		},
		{
			name:    "owner change of the connected database while PUBLIC has CONNECT",
			pg:      true,
			current: ownedConnecting(pg("admin"), model.PublicRole),
			stmts:   postgresTo("owner"),
		},
		{
			name: "owner change of the connected database to a role the connected user inherits from",
			pg:   true,
			current: func() *model.Current {
				c := ownedConnecting(pg("admin"))
				c.Roles[0].Inherit, c.Roles[1].Inherit = true, true
				c.Roles[0].MemberOptions = map[model.RoleID]model.MembershipState{pg("ops"): {Inherit: true}}
				c.Roles[1].MemberOptions = map[model.RoleID]model.MembershipState{pg("base"): {Inherit: true}}
				return c
			}(),
			stmts: postgresTo("base"),
		},
		{
			name: "owner change of the connected database with a superuser",
			pg:   true,
			current: func() *model.Current {
				c := ownedConnecting(pg("admin"))
				c.Roles[0].Superuser = true
				return c
			}(),
			stmts: postgresTo("owner"),
		},
		{
			name:    "owner change of the connected database whose owner does not give the connected user CONNECT",
			pg:      true,
			current: ownedConnecting(pg("ops")),
			stmts:   postgresTo("owner"),
		},
		{name: "drop role", pg: true, stmts: pgd.DropRole(pg("stray"), []string{"app", "postgres"})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var system policy.System = myd
			cur, desired := myCurrent(), &model.Desired{Engine: model.EngineMySQL}
			if tt.pg {
				system, cur, desired = pgd, pgCurrent(), pgDesired()
			}
			if tt.current != nil {
				cur = tt.current
			}
			if tt.desired != nil {
				desired = tt.desired
			}
			p := &plan.Plan{Changes: []plan.Change{{Action: plan.ActionUpdate, Resource: "test", Statements: tt.stmts}}}
			got := policy.Verify(p, cur, desired, policy.Options{System: system, Prune: true})
			if len(got) != len(tt.want) {
				t.Fatalf("violations = %v, want %d matching %q", got, len(tt.want), tt.want)
			}
			for i, w := range tt.want {
				if s := got[i].String(); !strings.Contains(s, w) {
					t.Errorf("violation %d = %q, want substring %q", i, s, w)
				}
			}
		})
	}
}
