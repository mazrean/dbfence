package policy_test

import (
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/driver/mysql"
	"github.com/mazrean/dbfence/internal/driver/postgres"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
	"github.com/mazrean/dbfence/internal/policy"
)

func pg(name string) model.RoleID { return model.RoleID{Name: name} }

func pgCurrent() *model.Current {
	return &model.Current{
		CurrentUser:     pg("admin"),
		CurrentDatabase: "postgres",
		Roles: []model.RoleState{
			{ID: pg("admin"), Login: true, MemberOf: []model.RoleID{pg("ops")}},
			{ID: pg("ops"), MemberOf: []model.RoleID{pg("base")}},
			{ID: pg("base")},
			{ID: pg("app")},
			{ID: pg("owner")},
			{ID: pg("stray")},
			{ID: pg("legacy_x")},
			{ID: pg("pg_monitor")},
			{ID: pg("keeper")},
			{ID: pg("schema_keeper")},
			{ID: pg("other_keeper")},
		},
		Databases: []model.Database{
			{Name: "postgres"}, {Name: "app"}, {Name: "stray_db"}, {Name: "gone"},
			{Name: "legacy_db", Owner: "keeper"}, {Name: "template1"},
		},
		Schemas: []model.Schema{
			{Database: "app", Name: "public"}, {Database: "app", Name: "core"},
			{Database: "app", Name: "old"}, {Database: "app", Name: "legacy_s", Owner: "schema_keeper"},
		},
		OtherSchemas: []model.Schema{{Database: "stray_db", Name: "legacy_o", Owner: "other_keeper"}},
	}
}

func pgDesired() *model.Desired {
	return &model.Desired{
		Engine:     model.EnginePostgres,
		Roles:      []model.Role{{ID: pg("app"), MemberOf: []model.RoleID{pg("base")}}},
		Databases:  []model.Database{{Name: "app", Owner: "owner"}},
		Schemas:    []model.Schema{{Database: "app", Name: "core"}},
		Privileges: []model.Privilege{{Grantee: pg("app"), Object: model.Object{Type: model.ObjectDatabase, Database: "app"}, Name: "CONNECT"}},
		Ignore:     model.Ignore{Roles: []string{"legacy_.*"}, Databases: []string{"legacy_.*"}, Schemas: []string{"legacy_.*"}},
	}
}

func dropRole(id model.RoleID) plan.Statement {
	return plan.New("", plan.KindDropRole, plan.RoleTarget(id), plan.Keyword("DROP ROLE x"))
}

func reassign(id model.RoleID, db string) plan.Statement {
	t := plan.RoleTarget(id)
	t.Database = db
	return plan.New(db, plan.KindReassign, t, plan.Keyword("REASSIGN OWNED BY x TO CURRENT_USER"))
}

func dropOwned(id model.RoleID, db string) plan.Statement {
	t := plan.RoleTarget(id)
	t.Database = db
	return plan.New(db, plan.KindDropOwned, t, plan.Keyword("DROP OWNED BY x"))
}

func dropDatabase(name string) plan.Statement {
	return plan.New("", plan.KindDropDatabase, plan.ObjectTarget(model.Object{Type: model.ObjectDatabase, Database: name}), plan.Keyword("DROP DATABASE x"))
}

func dropSchema(db, name string) plan.Statement {
	return plan.New(db, plan.KindDropSchema, plan.ObjectTarget(model.Object{Type: model.ObjectSchema, Database: db, Schema: name}), plan.Keyword("DROP SCHEMA x"))
}

func alterRole(id model.RoleID, c plan.RoleChange) plan.Statement {
	return plan.New("", plan.KindAlterRole, plan.RoleTarget(id), plan.Keyword("ALTER ROLE x")).WithRoleChange(c)
}

func revokeMembership(member, role model.RoleID, adminOnly bool) plan.Statement {
	return plan.New("", plan.KindRevokeMembership, plan.MembershipTarget(member, role).WithOption(adminOnly), plan.Keyword("REVOKE x FROM y"))
}

func grantMembership(member, role model.RoleID) plan.Statement {
	return plan.New("", plan.KindGrantMembership, plan.MembershipTarget(member, role), plan.Keyword("GRANT x TO y"))
}

func zero() *int { n := 0; return &n }

func TestVerify(t *testing.T) {
	t.Parallel()
	tests := []struct {
		current *model.Current
		desired *model.Desired
		system  policy.System
		name    string
		// want lists a substring of each violation, in order; none means
		// the plan passes.
		want    []string
		stmts   []plan.Statement
		noPrune bool
	}{
		{
			name: "safe pruning plan",
			stmts: []plan.Statement{
				reassign(pg("stray"), "postgres"), dropOwned(pg("stray"), "postgres"),
				reassign(pg("stray"), "app"), dropOwned(pg("stray"), "app"), dropRole(pg("stray")),
				dropDatabase("stray_db"), dropSchema("app", "old"),
				alterRole(pg("admin"), plan.RoleChange{SetsPassword: true}),
				revokeMembership(pg("app"), pg("ops"), false),
			},
		},
		{
			name: "drop owned whose CASCADE reaches the connected user",
			stmts: []plan.Statement{
				reassign(pg("stray"), "postgres"),
				dropOwned(pg("stray"), "postgres").WithDependents([]model.RoleID{pg("admin")}),
			},
			want: []string{`grants "stray" made to the connected user "admin"`},
		},
		{
			name: "drop owned whose CASCADE reaches a role granted to the connected user",
			stmts: []plan.Statement{
				reassign(pg("stray"), "postgres"),
				dropOwned(pg("stray"), "postgres").WithDependents([]model.RoleID{pg("app"), pg("base")}),
			},
			want: []string{`grants "stray" made to "base"`},
		},
		{
			name: "drop owned whose CASCADE reaches PUBLIC",
			stmts: []plan.Statement{
				reassign(pg("stray"), "postgres"),
				dropOwned(pg("stray"), "postgres").WithDependents([]model.RoleID{model.PublicRole}),
			},
			want: []string{`grants "stray" made to PUBLIC`},
		},
		{
			name: "drop owned whose CASCADE reaches other roles",
			stmts: []plan.Statement{
				reassign(pg("stray"), "postgres"),
				dropOwned(pg("stray"), "postgres").WithDependents([]model.RoleID{pg("app")}),
			},
		},
		{name: "drop without prune", noPrune: true, stmts: []plan.Statement{dropRole(pg("stray"))}, want: []string{"without --prune"}},
		{name: "schema drop without prune", noPrune: true, stmts: []plan.Statement{dropSchema("app", "old")}, want: []string{"without --prune"}},
		{name: "connected user", stmts: []plan.Statement{dropRole(pg("admin"))}, want: []string{`drops the connected user "admin"`}},
		{name: "reassign of the connected user", stmts: []plan.Statement{reassign(pg("admin"), "app")}, want: []string{`drops the connected user "admin"`}},
		{
			name:  "drop owned of a built-in role",
			stmts: []plan.Statement{reassign(pg("pg_monitor"), "app"), dropOwned(pg("pg_monitor"), "app")},
			want:  []string{`built-in role "pg_monitor"`, `built-in role "pg_monitor"`},
		},
		{name: "ignored role", stmts: []plan.Statement{dropRole(pg("legacy_x"))}, want: []string{`ignored role "legacy_x"`}},
		{name: "declared role", stmts: []plan.Statement{dropRole(pg("app"))}, want: []string{`declared role "app"`, "references"}},
		{name: "referenced owner", stmts: []plan.Statement{dropRole(pg("owner"))}, want: []string{`"owner", which the configuration references`}},
		{name: "referenced member_of", stmts: []plan.Statement{dropRole(pg("base"))}, want: []string{"references", "granted to the connected user"}},
		{name: "granted to the connected user", stmts: []plan.Statement{dropRole(pg("ops"))}, want: []string{`"ops", which is granted to the connected user`}},
		{name: "missing role", stmts: []plan.Statement{dropRole(pg("ghost"))}, want: []string{"does not exist"}},
		{name: "owner of an ignored database", stmts: []plan.Statement{dropRole(pg("keeper"))}, want: []string{`ignored database "legacy_db"`}},
		{name: "owner of an ignored schema", stmts: []plan.Statement{dropRole(pg("schema_keeper"))}, want: []string{`ignored schema "legacy_s"`}},
		{name: "owner of an ignored schema elsewhere", stmts: []plan.Statement{dropRole(pg("other_keeper"))}, want: []string{`ignored schema "legacy_o" in database "stray_db"`}},
		{
			name:  "owner of an ignored schema in a dropped database",
			stmts: []plan.Statement{dropDatabase("stray_db"), dropRole(pg("other_keeper"))},
		},
		{
			name: "roles unreadable",
			current: func() *model.Current {
				c := pgCurrent()
				c.Unreadable.Roles = true
				return c
			}(),
			stmts: []plan.Statement{dropRole(pg("stray"))},
			want:  []string{"role list is unreadable"},
		},
		{name: "drop owned without reassign", stmts: []plan.Statement{dropOwned(pg("stray"), "app")}, want: []string{`no REASSIGN OWNED of the role runs there first`}},
		{
			name:  "drop owned before reassign",
			stmts: []plan.Statement{dropOwned(pg("stray"), "app"), reassign(pg("stray"), "app")},
			want:  []string{`owns in database "app": no REASSIGN OWNED`},
		},
		{
			name:  "drop owned after reassign in another database",
			stmts: []plan.Statement{reassign(pg("stray"), "postgres"), dropOwned(pg("stray"), "app")},
			want:  []string{`owns in database "app": no REASSIGN OWNED`},
		},
		{
			name:  "drop owned after reassign of another role",
			stmts: []plan.Statement{reassign(pg("app"), "app"), dropOwned(pg("stray"), "app")},
			want:  []string{"declared role", "references", `role "stray" owns in database "app"`},
		},
		{
			name: "drop owned on another database than its target",
			stmts: []plan.Statement{
				reassign(pg("stray"), "app"),
				plan.New("postgres", plan.KindDropOwned, plan.Target{Object: plan.ObjectRole, Role: pg("stray"), Database: "app"}, plan.Keyword("DROP OWNED BY x")),
			},
			want: []string{`runs on database "postgres", but its target is in database "app"`},
		},
		{name: "reassign in an ignored database", stmts: []plan.Statement{reassign(pg("stray"), "legacy_db")}, want: []string{`ignored database "legacy_db"`}},
		{name: "reassign in a dropped database", stmts: []plan.Statement{dropDatabase("gone"), reassign(pg("stray"), "gone")}, want: []string{"which the plan drops"}},
		{name: "reassign in a missing database", stmts: []plan.Statement{reassign(pg("stray"), "nowhere")}, want: []string{"does not exist"}},
		{name: "connected database", stmts: []plan.Statement{dropDatabase("postgres")}, want: []string{`connected to`, `built-in database "postgres"`}},
		{name: "built-in database", stmts: []plan.Statement{dropDatabase("template1")}, want: []string{`built-in database "template1"`}},
		{name: "ignored database", stmts: []plan.Statement{dropDatabase("legacy_db")}, want: []string{`ignored database "legacy_db"`}},
		{name: "declared database", stmts: []plan.Statement{dropDatabase("app")}, want: []string{`declared database "app"`}},
		{name: "missing database", stmts: []plan.Statement{dropDatabase("nowhere")}, want: []string{"does not exist"}},
		{
			name: "database entangled with unmanaged objects",
			current: func() *model.Current {
				c := pgCurrent()
				c.Entangle(model.Object{Type: model.ObjectDatabase, Database: "stray_db"}, `it is owned by role "bad\x01", which dbfence does not manage`)
				return c
			}(),
			stmts: []plan.Statement{dropDatabase("stray_db")},
			want:  []string{`drops database "stray_db", although it is owned by role "bad\x01"`},
		},
		{
			name: "schema entangled with unmanaged objects",
			current: func() *model.Current {
				c := pgCurrent()
				c.Entangle(model.Object{Type: model.ObjectSchema, Database: "app", Schema: "old"}, `it grants USAGE to role "bad\x01", which dbfence does not manage`)
				return c
			}(),
			stmts: []plan.Statement{dropSchema("app", "old")},
			want:  []string{`drops schema "old" in database "app", although it grants USAGE to role "bad\x01"`},
		},
		{name: "built-in schema", stmts: []plan.Statement{dropSchema("app", "public")}, want: []string{`built-in schema "public"`}},
		{name: "ignored schema", stmts: []plan.Statement{dropSchema("app", "legacy_s")}, want: []string{`ignored schema "legacy_s"`}},
		{name: "declared schema", stmts: []plan.Statement{dropSchema("app", "core")}, want: []string{`declared schema "core"`}},
		{name: "missing schema", stmts: []plan.Statement{dropSchema("app", "nowhere")}, want: []string{"does not exist"}},
		{
			name: "ignored schema by database",
			desired: func() *model.Desired {
				d := pgDesired()
				d.Ignore.Schemas = []string{`app\.old`}
				return d
			}(),
			stmts: []plan.Statement{dropSchema("app", "old")},
			want:  []string{`ignored schema "old"`},
		},
		{name: "nologin", stmts: []plan.Statement{alterRole(pg("admin"), plan.RoleChange{DisablesLogin: true})}, want: []string{"disables login"}},
		{name: "nosuperuser", stmts: []plan.Statement{alterRole(pg("admin"), plan.RoleChange{RemovesSuperuser: true})}, want: []string{"removes superuser"}},
		{name: "account lock", stmts: []plan.Statement{alterRole(pg("admin"), plan.RoleChange{LocksAccount: true})}, want: []string{"locks the account"}},
		{
			name:  "lock on create",
			stmts: []plan.Statement{plan.New("", plan.KindCreateRole, plan.RoleTarget(pg("admin")), plan.Keyword("CREATE ROLE x")).WithRoleChange(plan.RoleChange{LocksAccount: true})},
			want:  []string{"locks the account"},
		},
		{name: "connection limit 0", stmts: []plan.Statement{alterRole(pg("admin"), plan.RoleChange{ConnectionLimit: zero()})}, want: []string{"connection limit 0"}},
		{
			name: "connection limit 0 on a superuser",
			current: func() *model.Current {
				c := pgCurrent()
				c.Roles[0].Superuser = true
				return c
			}(),
			stmts: []plan.Statement{alterRole(pg("admin"), plan.RoleChange{ConnectionLimit: zero()})},
		},
		{name: "lock out of another role", stmts: []plan.Statement{alterRole(pg("app"), plan.RoleChange{DisablesLogin: true, ConnectionLimit: zero()})}},
		{name: "membership of the connected user", stmts: []plan.Statement{revokeMembership(pg("admin"), pg("ops"), false)}, want: []string{`connected user "admin" in "ops"`}},
		{name: "admin option of the connected user", stmts: []plan.Statement{revokeMembership(pg("admin"), pg("ops"), true)}, want: []string{"ADMIN OPTION"}},
		{
			name:  "membership on the chain of the connected user",
			stmts: []plan.Statement{revokeMembership(pg("ops"), pg("base"), false)},
			want:  []string{`revokes the membership of "ops" in "base", through which the connected user "admin" has "base"`},
		},
		{name: "admin option on the chain of the connected user", stmts: []plan.Statement{revokeMembership(pg("ops"), pg("base"), true)}},
		{
			name:  "membership on the chain after another path is granted",
			stmts: []plan.Statement{grantMembership(pg("admin"), pg("base")), revokeMembership(pg("ops"), pg("base"), false)},
		},
		{
			name:  "membership on the chain revoked and granted again",
			stmts: []plan.Statement{revokeMembership(pg("ops"), pg("base"), false), grantMembership(pg("ops"), pg("base"))},
			want:  []string{`through which the connected user "admin" has "base"`},
		},
		{
			name: "the last of two paths of the connected user",
			current: func() *model.Current {
				c := pgCurrent()
				c.Roles[0].MemberOf = append(c.Roles[0].MemberOf, pg("app"))
				c.Roles[3].MemberOf = []model.RoleID{pg("base")}
				return c
			}(),
			stmts: []plan.Statement{revokeMembership(pg("ops"), pg("base"), false), revokeMembership(pg("app"), pg("base"), false)},
			want:  []string{`revokes the membership of "app" in "base"`},
		},
		{name: "membership in the connected user", stmts: []plan.Statement{revokeMembership(pg("app"), pg("admin"), false)}},
		{name: "drop of an unmanaged name", stmts: []plan.Statement{dropRole(pg("evil\n"))}, want: []string{"does not exist", `names role "evil\n", which dbfence does not manage`}},
		{
			name:  "grant to an unmanaged grantee",
			stmts: []plan.Statement{plan.New("", plan.KindGrant, plan.PrivilegeTarget(pg("x\x1b"), model.Object{Type: model.ObjectDatabase, Database: "app"}), plan.Keyword("GRANT x"))},
			want:  []string{`names role "x\x1b"`},
		},
		{
			name:  "membership in a role with a long name",
			stmts: []plan.Statement{revokeMembership(pg("app"), pg(strings.Repeat("r", 64)), false)},
			want:  []string{"64 bytes long"},
		},
		{
			name:  "revoke run as an unmanaged grantor",
			stmts: []plan.Statement{plan.New("", plan.KindRevoke, plan.PrivilegeTarget(pg("app"), model.Object{Type: model.ObjectDatabase, Database: "app"}), plan.Keyword("REVOKE x")).WithRole("g\u0085")},
			want:  []string{`runs as role "g\u0085"`},
		},
		{
			name:  "unmanaged schema and database",
			stmts: []plan.Statement{plan.New("", plan.KindAlterSchema, plan.ObjectTarget(model.Object{Type: model.ObjectSchema, Database: "d\x00", Schema: "s\x7f"}), plan.Keyword("ALTER SCHEMA x"))},
			want:  []string{`database "d\x00"`, `schema "s\x7f"`},
		},
		{
			name: "revoke granted by an unmanaged grantor",
			stmts: []plan.Statement{plan.New("", plan.KindRevokeMembership,
				plan.Target{Object: plan.ObjectRole, Role: pg("base"), Grantee: pg("app"), Grantor: pg("evil\n")}, plan.Keyword("REVOKE x"))},
			want: []string{`names grantor "evil\n" in GRANTED BY`},
		},
		{
			name: "owner with an unmanaged name",
			stmts: []plan.Statement{plan.New("", plan.KindAlterDatabase,
				plan.ObjectTarget(model.Object{Type: model.ObjectDatabase, Database: "app"}).WithOwner("o\x1b"), plan.Keyword("ALTER DATABASE x"))},
			want: []string{`makes role "o\x1b" an owner`},
		},
		{
			name:    "mysql default role with an unmanaged name",
			current: &model.Current{CurrentUser: model.RoleID{Name: "root", Host: "%"}},
			desired: &model.Desired{Engine: model.EngineMySQL},
			system:  mysql.Dialect{},
			stmts: []plan.Statement{plan.New("", plan.KindSetDefaultRole, plan.RoleTarget(model.RoleID{Name: "u", Host: "%"}), plan.Keyword("SET DEFAULT ROLE x")).
				WithDefaultRoles([]model.RoleID{{Name: "r\n", Host: "%"}})},
			want: []string{`names role "r\n"@"%"`},
		},
		{
			name:    "mysql account with an unmanaged host",
			current: &model.Current{CurrentUser: model.RoleID{Name: "root", Host: "%"}},
			desired: &model.Desired{Engine: model.EngineMySQL},
			system:  mysql.Dialect{},
			stmts: []plan.Statement{plan.New("", plan.KindGrant, plan.PrivilegeTarget(model.RoleID{Name: "u", Host: "h\n"},
				model.Object{Type: model.ObjectDatabase, Database: "app", Pattern: strings.Repeat("p", 65)}), plan.Keyword("GRANT x"))},
			want: []string{`its host contains control characters`, `database pattern`},
		},
		{
			name:    "invalid ignore pattern",
			desired: &model.Desired{Engine: model.EnginePostgres, Ignore: model.Ignore{Roles: []string{"("}}},
			want:    []string{"cannot verify the plan"},
		},
		{
			name:    "mysql account ignored by name@host",
			current: &model.Current{CurrentUser: model.RoleID{Name: "root", Host: "%"}, Roles: []model.RoleState{{ID: model.RoleID{Name: "svc", Host: "10.0.0.1"}}}},
			desired: &model.Desired{Engine: model.EngineMySQL, Ignore: model.Ignore{Roles: []string{`svc@10\..*`}}},
			system:  mysql.Dialect{},
			stmts:   []plan.Statement{dropRole(model.RoleID{Name: "svc", Host: "10.0.0.1"})},
			want:    []string{`ignored role "svc"@"10.0.0.1"`},
		},
		{
			name:    "mysql account with an empty host ignored by name@",
			current: &model.Current{CurrentUser: model.RoleID{Name: "root", Host: "%"}, Roles: []model.RoleState{{ID: model.RoleID{Name: "svc"}}}},
			desired: &model.Desired{Engine: model.EngineMySQL, Ignore: model.Ignore{Roles: []string{`svc@`}}},
			system:  mysql.Dialect{},
			stmts:   []plan.Statement{dropRole(model.RoleID{Name: "svc"})},
			want:    []string{`ignored role "svc"`},
		},
		{
			name:    "mysql connected account",
			current: &model.Current{CurrentUser: model.RoleID{Name: "dba", Host: "%"}, Roles: []model.RoleState{{ID: model.RoleID{Name: "dba", Host: "%"}}}},
			desired: &model.Desired{Engine: model.EngineMySQL},
			system:  mysql.Dialect{},
			stmts:   []plan.Statement{dropRole(model.RoleID{Name: "dba", Host: "%"})},
			want:    []string{"connected user"},
		},
		{
			name:    "mysql system database",
			current: &model.Current{CurrentUser: model.RoleID{Name: "root", Host: "%"}, Databases: []model.Database{{Name: "sys"}}},
			desired: &model.Desired{Engine: model.EngineMySQL},
			system:  mysql.Dialect{},
			stmts:   []plan.Statement{dropDatabase("sys")},
			want:    []string{`built-in database "sys"`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cur, desired, system := tt.current, tt.desired, tt.system
			if cur == nil {
				cur = pgCurrent()
			}
			if desired == nil {
				desired = pgDesired()
			}
			if system == nil {
				system = postgres.Dialect{}
			}
			p := &plan.Plan{Changes: []plan.Change{{Action: plan.ActionDrop, Resource: "test", Statements: tt.stmts}}}
			got := policy.Verify(p, cur, desired, policy.Options{System: system, Prune: !tt.noPrune})
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

func TestViolationString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		want string
		v    policy.Violation
	}{
		{
			name: "statement",
			v:    policy.Violation{Resource: `user "admin"`, Kind: plan.KindDropRole, Reason: `drops the connected user "admin"`},
			want: `drops the connected user "admin" (drop-role statement of user "admin")`,
		},
		{name: "plan", v: policy.Violation{Reason: "cannot verify the plan"}, want: "cannot verify the plan"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.v.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}
