package diff_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/driver/mysql"
	"github.com/mazrean/dbfence/internal/driver/postgres"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/password"
)

// TestComputeOrder checks the relative order of plan phases.
func TestComputeOrder(t *testing.T) {
	t.Parallel()
	tests := []struct {
		desired *model.Desired
		current *model.Current
		name    string
		want    []string
	}{
		{
			// A non-superuser admin must be a member of the owner role
			// before the database is created for it or handed over to it.
			name: "membership before database",
			desired: &model.Desired{
				Engine: model.EnginePostgres,
				Roles: []model.Role{
					{ID: pgID("app"), Login: new(false)},
					{ID: pgID("admin"), Login: new(true), MemberOf: []model.RoleID{pgID("app")}},
				},
				Databases: []model.Database{{Name: "app", Owner: "app"}, {Name: "old", Owner: "app"}},
			},
			current: &model.Current{
				CurrentUser: pgID("admin"),
				Roles:       []model.RoleState{{ID: pgID("admin"), Login: true, CreateRole: true}},
				Databases:   []model.Database{{Name: "old", Owner: "admin"}},
			},
			want: []string{
				`CREATE ROLE "app" WITH NOLOGIN`,
				`GRANT "app" TO "admin"`,
				`CREATE DATABASE "app" OWNER "app"`,
				`ALTER DATABASE "old" OWNER TO "app"`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := compute(t, tt.desired, tt.current, postgres.Dialect{}, diff.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(tt.want, statements(p)); d != "" {
				t.Errorf("statements (-want +got):\n%s", d)
			}
		})
	}
}

// TestComputeCurrentUser checks that a declared connected user is not
// locked out.
func TestComputeCurrentUser(t *testing.T) {
	t.Parallel()
	myAdmin := model.RoleID{Name: "admin", Host: "%"}
	tests := []struct {
		dialect   diff.Dialect
		name      string
		role      model.Role
		want      []string
		wantWarns []string
		state     model.RoleState
	}{
		{
			name:    "postgres login, superuser and memberships",
			dialect: postgres.Dialect{},
			role:    model.Role{ID: pgID("admin"), Login: new(false), Superuser: new(false), CreateDB: new(true), MemberOf: []model.RoleID{}},
			state:   model.RoleState{ID: pgID("admin"), Login: true, Superuser: true, MemberOf: []model.RoleID{pgID("rds_superuser")}},
			want:    []string{`ALTER ROLE "admin" WITH CREATEDB`},
			wantWarns: []string{
				`not disabling login of the connected user "admin": it would lock dbfence out`,
				`not removing superuser from the connected user "admin": dbfence may rely on it`,
				`not revoking membership of the connected user "admin" in "rds_superuser": dbfence may rely on it`,
			},
		},
		{
			name:      "postgres connection limit 0 on a non-superuser",
			dialect:   postgres.Dialect{},
			role:      model.Role{ID: pgID("admin"), Login: new(true), ConnectionLimit: new(0), CreateDB: new(true)},
			state:     model.RoleState{ID: pgID("admin"), Login: true, ConnectionLimit: -1},
			want:      []string{`ALTER ROLE "admin" WITH CREATEDB`},
			wantWarns: []string{`not setting connection limit 0 on the connected user "admin": it would lock dbfence out`},
		},
		{
			name:      "postgres connection limit 0 on a superuser",
			dialect:   postgres.Dialect{},
			role:      model.Role{ID: pgID("admin"), Login: new(true), ConnectionLimit: new(0)},
			state:     model.RoleState{ID: pgID("admin"), Login: true, Superuser: true, ConnectionLimit: -1},
			want:      []string{`ALTER ROLE "admin" WITH CONNECTION LIMIT 0`},
			wantWarns: []string{},
		},
		{
			name:      "postgres connection limit 1 is applied",
			dialect:   postgres.Dialect{},
			role:      model.Role{ID: pgID("admin"), Login: new(true), ConnectionLimit: new(1)},
			state:     model.RoleState{ID: pgID("admin"), Login: true, ConnectionLimit: -1},
			want:      []string{`ALTER ROLE "admin" WITH CONNECTION LIMIT 1`},
			wantWarns: []string{},
		},
		{
			name:      "mysql account lock",
			dialect:   mysql.Dialect{},
			role:      model.Role{ID: myAdmin, Login: new(false)},
			state:     model.RoleState{ID: myAdmin, Login: true},
			want:      []string{},
			wantWarns: []string{`not disabling login of the connected user "admin"@"%": it would lock dbfence out`},
		},
		{
			name:      "mysql secondary password of the connected user is kept",
			dialect:   mysql.Dialect{},
			role:      model.Role{ID: myAdmin, Login: new(true), Password: new("pw")},
			state:     model.RoleState{ID: myAdmin, Login: true, AuthPlugin: password.PluginNative, PasswordHash: []byte(password.MySQLNative("pw")), RetainedPassword: true},
			want:      []string{},
			wantWarns: []string{`not discarding the secondary password of the connected user "admin"@"%": dbfence may be using it`},
		},
		{
			name:      "login already declared",
			dialect:   postgres.Dialect{},
			role:      model.Role{ID: pgID("admin"), Login: new(true), MemberOf: []model.RoleID{pgID("x")}},
			state:     model.RoleState{ID: pgID("admin"), Login: true},
			want:      []string{`GRANT "x" TO "admin"`},
			wantWarns: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			engine := model.EnginePostgres
			if tt.state.ID.Host != "" {
				engine = model.EngineMySQL
			}
			d := &model.Desired{Engine: engine, Roles: []model.Role{tt.role}}
			cur := &model.Current{CurrentUser: tt.state.ID, Roles: []model.RoleState{tt.state, {ID: pgID("x")}}}
			p, err := compute(t, d, cur, tt.dialect, diff.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(tt.want, statements(p)); d != "" {
				t.Errorf("statements (-want +got):\n%s", d)
			}
			var warns []string
			for _, w := range p.Warnings {
				if !strings.HasPrefix(w, "unmanaged") {
					warns = append(warns, w)
				}
			}
			if d := cmp.Diff(tt.wantWarns, append([]string{}, warns...)); d != "" {
				t.Errorf("warnings (-want +got):\n%s", d)
			}
		})
	}
}

// TestComputeTemplateSchema checks that the public schema of a database
// created by the plan is not created again.
func TestComputeTemplateSchema(t *testing.T) {
	t.Parallel()
	public := model.Object{Type: model.ObjectSchema, Database: "app", Schema: "public"}
	tests := []struct {
		name   string
		schema model.Schema
		want   []string
	}{
		{
			name:   "owner declared",
			schema: model.Schema{Database: "app", Name: "public", Owner: "o"},
			want: []string{
				`CREATE ROLE "o" WITH NOLOGIN`,
				`CREATE ROLE "r" WITH NOLOGIN`,
				`CREATE DATABASE "app"`,
				`app: ALTER SCHEMA "public" OWNER TO "o"`,
				`app: GRANT USAGE ON SCHEMA "public" TO "r"`,
			},
		},
		{
			name:   "owner not declared",
			schema: model.Schema{Database: "app", Name: "public"},
			want: []string{
				`CREATE ROLE "o" WITH NOLOGIN`,
				`CREATE ROLE "r" WITH NOLOGIN`,
				`CREATE DATABASE "app"`,
				`app: GRANT USAGE ON SCHEMA "public" TO "r"`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := &model.Desired{
				Engine:     model.EnginePostgres,
				Roles:      []model.Role{{ID: pgID("o"), Login: new(false)}, {ID: pgID("r"), Login: new(false)}},
				Databases:  []model.Database{{Name: "app"}},
				Schemas:    []model.Schema{tt.schema},
				Privileges: []model.Privilege{{Grantee: pgID("r"), Object: public, Name: "USAGE"}},
			}
			cur := &model.Current{
				CurrentUser: pgID("admin"),
				Roles:       []model.RoleState{{ID: pgID("admin"), Login: true}},
				Databases:   []model.Database{{Name: "postgres", Owner: "admin"}},
			}
			p, err := compute(t, d, cur, postgres.Dialect{}, diff.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(tt.want, statements(p)); d != "" {
				t.Errorf("statements (-want +got):\n%s", d)
			}
		})
	}
}

// TestComputePruneProtection checks objects that --prune must keep.
func TestComputePruneProtection(t *testing.T) {
	t.Parallel()
	pgCur := func(roles []model.RoleState, dbs []model.Database) *model.Current {
		return &model.Current{
			CurrentUser: pgID("admin"),
			Roles:       append([]model.RoleState{{ID: pgID("admin"), Login: true}}, roles...),
			Databases:   append([]model.Database{{Name: "postgres", Owner: "admin"}}, dbs...),
		}
	}
	myAdmin := model.RoleID{Name: "admin", Host: "%"}
	myID := func(n string) model.RoleID { return model.RoleID{Name: n, Host: "%"} }
	tests := []struct {
		desired   *model.Desired
		current   *model.Current
		dialect   diff.Dialect
		name      string
		want      []string
		wantWarns []string
		noPrune   bool
	}{
		{
			name: "roles referenced by the configuration",
			desired: &model.Desired{
				Engine:    model.EnginePostgres,
				Roles:     []model.Role{{ID: pgID("app"), Login: new(true), MemberOf: []model.RoleID{pgID("legacy_grp")}}},
				Databases: []model.Database{{Name: "app", Owner: "legacy_owner"}},
				Schemas:   []model.Schema{{Database: "app", Name: "api", Owner: "schema_owner"}},
			},
			current: pgCur([]model.RoleState{
				{ID: pgID("app"), Login: true, MemberOf: []model.RoleID{pgID("legacy_grp")}},
				{ID: pgID("legacy_grp")}, {ID: pgID("legacy_owner")}, {ID: pgID("schema_owner")}, {ID: pgID("stray")},
			}, []model.Database{{Name: "app", Owner: "legacy_owner"}}),
			dialect: postgres.Dialect{},
			want: []string{
				`app: CREATE SCHEMA "api" AUTHORIZATION "schema_owner"`,
				`app: REASSIGN OWNED BY "stray" TO CURRENT_USER`,
				`app: DROP OWNED BY "stray"`,
				`postgres: REASSIGN OWNED BY "stray" TO CURRENT_USER`,
				`postgres: DROP OWNED BY "stray"`,
				`DROP ROLE "stray"`,
			},
			wantWarns: []string{
				`user "admin" is the connected user; not pruned`,
				`role "legacy_grp" is referenced by the configuration but not declared (declare it to manage it); not pruned`,
				`role "legacy_owner" is referenced by the configuration but not declared (declare it to manage it); not pruned`,
				`role "schema_owner" is referenced by the configuration but not declared (declare it to manage it); not pruned`,
			},
		},
		{
			name: "referenced roles are not reported as unmanaged",
			desired: &model.Desired{
				Engine:    model.EnginePostgres,
				Databases: []model.Database{{Name: "app", Owner: "legacy_owner"}},
			},
			current:   pgCur([]model.RoleState{{ID: pgID("legacy_owner")}}, []model.Database{{Name: "app", Owner: "legacy_owner"}}),
			dialect:   postgres.Dialect{},
			noPrune:   true,
			want:      []string{},
			wantWarns: []string{},
		},
		{
			name:    "roles granted to the connected user",
			desired: &model.Desired{Engine: model.EngineMySQL},
			current: &model.Current{
				CurrentUser: myAdmin,
				Roles: []model.RoleState{
					{ID: myAdmin, Login: true, MemberOf: []model.RoleID{myID("dba")}},
					{ID: myID("dba"), MemberOf: []model.RoleID{myID("super")}},
					{ID: myID("super"), MemberOf: []model.RoleID{myID("dba")}},
					{ID: myID("stale")},
				},
			},
			dialect: mysql.Dialect{},
			want:    []string{`DROP USER 'stale'@'%'`},
			wantWarns: []string{
				`user "admin"@"%" is the connected user; not pruned`,
				`role "dba"@"%" is granted to the connected user "admin"@"%"; not pruned`,
				`role "super"@"%" is granted to the connected user "admin"@"%"; not pruned`,
			},
		},
		{
			name:    "owners of ignored objects and ignored databases",
			desired: &model.Desired{Engine: model.EnginePostgres, Ignore: model.Ignore{Databases: []string{"keep.*"}, Schemas: []string{"vendor"}}},
			current: func() *model.Current {
				c := pgCur([]model.RoleState{{ID: pgID("legacy_owner")}, {ID: pgID("vendor_owner")}, {ID: pgID("stray")}},
					[]model.Database{{Name: "keepme", Owner: "legacy_owner"}, {Name: "app", Owner: "admin"}})
				c.Schemas = []model.Schema{{Database: "app", Name: "vendor", Owner: "vendor_owner"}}
				c.InspectedDatabases = []string{"app"}
				return c
			}(),
			dialect: postgres.Dialect{},
			want: []string{
				`DROP DATABASE "app"`,
				`postgres: REASSIGN OWNED BY "stray" TO CURRENT_USER`,
				`postgres: DROP OWNED BY "stray"`,
				`DROP ROLE "stray"`,
			},
			wantWarns: []string{
				`user "admin" is the connected user; not pruned`,
				`role "legacy_owner" owns the ignored database "keepme"; not pruned`,
				`role "vendor_owner" owns the ignored schema "vendor" in database "app"; not pruned`,
			},
		},
		{
			// A declared database is managed even when an ignore pattern
			// matches it, so pruned roles are reassigned there too.
			name:    "declared database matching an ignore pattern",
			desired: &model.Desired{Engine: model.EnginePostgres, Databases: []model.Database{{Name: "keepme", Owner: "admin"}}, Ignore: model.Ignore{Databases: []string{"keep.*"}}},
			current: pgCur([]model.RoleState{{ID: pgID("stray")}}, []model.Database{{Name: "keepme", Owner: "admin"}}),
			dialect: postgres.Dialect{},
			want: []string{
				`keepme: REASSIGN OWNED BY "stray" TO CURRENT_USER`,
				`keepme: DROP OWNED BY "stray"`,
				`postgres: REASSIGN OWNED BY "stray" TO CURRENT_USER`,
				`postgres: DROP OWNED BY "stray"`,
				`DROP ROLE "stray"`,
			},
			wantWarns: []string{`user "admin" is the connected user; not pruned`},
		},
		{
			name:    "owner of a schema ignored by its qualified name",
			desired: &model.Desired{Engine: model.EnginePostgres, Databases: []model.Database{{Name: "app", Owner: "admin"}}, Ignore: model.Ignore{Schemas: []string{`app\.vendor`}}},
			current: func() *model.Current {
				c := pgCur([]model.RoleState{{ID: pgID("vendor_owner")}}, []model.Database{{Name: "app", Owner: "admin"}})
				c.Schemas = []model.Schema{{Database: "app", Name: "vendor", Owner: "vendor_owner"}}
				c.InspectedDatabases = []string{"app"}
				return c
			}(),
			dialect:   postgres.Dialect{},
			want:      []string{},
			wantWarns: []string{`user "admin" is the connected user; not pruned`, `role "vendor_owner" owns the ignored schema "vendor" in database "app"; not pruned`},
		},
		{
			name:    "connected database",
			desired: &model.Desired{Engine: model.EnginePostgres},
			current: func() *model.Current {
				c := pgCur(nil, []model.Database{{Name: "conn_db", Owner: "admin"}, {Name: "legacy", Owner: "admin"}})
				c.CurrentDatabase = "conn_db"
				return c
			}(),
			dialect: postgres.Dialect{},
			want:    []string{`DROP DATABASE "legacy"`},
			wantWarns: []string{
				`database "conn_db" is the database dbfence is connected to; not pruned`,
				`user "admin" is the connected user; not pruned`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := compute(t, tt.desired, tt.current, tt.dialect, diff.Options{Prune: !tt.noPrune})
			if err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(tt.want, statements(p)); d != "" {
				t.Errorf("statements (-want +got):\n%s", d)
			}
			if d := cmp.Diff(tt.wantWarns, append([]string{}, p.Warnings...)); d != "" {
				t.Errorf("warnings (-want +got):\n%s", d)
			}
		})
	}
}

// TestComputeConnectedUserDefaultRoles checks that SET DEFAULT ROLE for
// the connected MySQL account keeps the roles whose memberships dbfence
// does not revoke, so that later sessions still have their privileges.
func TestComputeConnectedUserDefaultRoles(t *testing.T) {
	t.Parallel()
	dba := model.RoleID{Name: "dba", Host: "%"}
	role := func(n string) model.RoleID { return model.RoleID{Name: n, Host: "%"} }
	tests := []struct {
		opts       map[model.RoleID]model.MembershipOptions
		name       string
		memberOf   []model.RoleID
		want       []string
		warns      []string
		current    model.RoleState
		unreadable model.Unreadable
	}{
		{
			name:     "empty member_of keeps every default role",
			memberOf: []model.RoleID{},
			current: model.RoleState{ID: dba, Login: true, MemberOf: []model.RoleID{role("dbarole")}, DefaultRoles: []model.RoleID{role("dbarole")},
				MemberOptions: map[model.RoleID]model.MembershipState{role("dbarole"): {Inherit: true, Set: true}}},
			want: []string{},
		},
		{
			name:     "subset keeps the undeclared role active",
			memberOf: []model.RoleID{role("dbarole")},
			opts:     map[model.RoleID]model.MembershipOptions{role("dbarole"): {Admin: new(false)}},
			current: model.RoleState{ID: dba, Login: true, MemberOf: []model.RoleID{role("dbarole"), role("extra")},
				DefaultRoles: []model.RoleID{role("dbarole"), role("extra")},
				MemberOptions: map[model.RoleID]model.MembershipState{
					role("dbarole"): {Admin: true, Inherit: true, Set: true}, role("extra"): {Inherit: true, Set: true},
				}},
			want: []string{},
		},
		{
			name:     "a newly declared role is added to the kept ones",
			memberOf: []model.RoleID{role("extra")},
			current: model.RoleState{ID: dba, Login: true, MemberOf: []model.RoleID{role("dbarole")}, DefaultRoles: []model.RoleID{role("dbarole")},
				MemberOptions: map[model.RoleID]model.MembershipState{role("dbarole"): {Inherit: true, Set: true}}},
			want: []string{
				`GRANT 'extra'@'%' TO 'dba'@'%'`,
				`SET DEFAULT ROLE 'dbarole'@'%', 'extra'@'%' TO 'dba'@'%'`,
			},
		},
		{
			name:       "unknown memberships and default roles are not replaced",
			memberOf:   []model.RoleID{role("extra")},
			current:    model.RoleState{ID: dba, Login: true, DefaultRolesUnknown: true},
			unreadable: model.Unreadable{Memberships: true},
			want:       []string{`GRANT 'extra'@'%' TO 'dba'@'%'`},
			warns:      []string{`not setting default roles of the connected user "dba"@"%": its current default roles are unknown and could be narrowed`},
		},
		{
			name:       "unknown memberships keep the known default roles",
			memberOf:   []model.RoleID{role("extra")},
			current:    model.RoleState{ID: dba, Login: true, DefaultRoles: []model.RoleID{role("dbarole")}},
			unreadable: model.Unreadable{Memberships: true},
			want: []string{
				`GRANT 'extra'@'%' TO 'dba'@'%'`,
				`SET DEFAULT ROLE 'dbarole'@'%', 'extra'@'%' TO 'dba'@'%'`,
			},
		},
		{
			name:       "unreadable role list is not replaced",
			memberOf:   []model.RoleID{role("extra")},
			unreadable: model.Unreadable{Roles: true, RoleAttributes: true},
			want: []string{
				`CREATE USER IF NOT EXISTS 'dba'@'%'`,
				`CREATE USER IF NOT EXISTS 'dbarole'@'%'`,
				`CREATE USER IF NOT EXISTS 'extra'@'%'`,
				`GRANT 'extra'@'%' TO 'dba'@'%'`,
			},
			warns: []string{`not setting default roles of the connected user "dba"@"%": its current default roles are unknown and could be narrowed`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			desired := &model.Desired{Engine: model.EngineMySQL, Roles: []model.Role{
				{ID: dba, Login: new(true), MemberOf: tt.memberOf, MemberOptions: tt.opts},
				{ID: role("dbarole")}, {ID: role("extra")},
			}}
			cur := &model.Current{CurrentUser: dba, Unreadable: tt.unreadable}
			if !tt.unreadable.Roles {
				cur.Roles = []model.RoleState{tt.current, {ID: role("dbarole")}, {ID: role("extra")}}
			}
			p, err := compute(t, desired, cur, mysql.Dialect{}, diff.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(tt.want, statements(p), cmpopts.EquateEmpty()); d != "" {
				t.Errorf("statements (-want +got):\n%s", d)
			}
			var warns []string
			for _, w := range p.Warnings {
				if strings.HasPrefix(w, "not setting default roles") {
					warns = append(warns, w)
				}
			}
			if d := cmp.Diff(tt.warns, warns, cmpopts.EquateEmpty()); d != "" {
				t.Errorf("warnings (-want +got):\n%s", d)
			}
		})
	}
}

// TestComputePruneOtherSchemaOwners checks that --prune keeps the owners
// of ignored schemas in undeclared databases where REASSIGN OWNED runs.
func TestComputePruneOtherSchemaOwners(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		other     []model.Schema
		want      []string
		wantWarns []string
	}{
		{
			name:      "ignored schema in an undeclared database",
			other:     []model.Schema{{Database: "postgres", Name: "monitoring", Owner: "monitor"}},
			want:      []string{`DROP DATABASE "old"`},
			wantWarns: []string{`role "monitor" owns the ignored schema "monitoring" in database "postgres"; not pruned`},
		},
		{
			name:  "schema that is not ignored",
			other: []model.Schema{{Database: "postgres", Name: "reports", Owner: "monitor"}},
			want: []string{
				`DROP DATABASE "old"`,
				`app: REASSIGN OWNED BY "monitor" TO CURRENT_USER`,
				`app: DROP OWNED BY "monitor"`,
				`postgres: REASSIGN OWNED BY "monitor" TO CURRENT_USER`,
				`postgres: DROP OWNED BY "monitor"`,
				`DROP ROLE "monitor"`,
			},
		},
		{
			name:  "ignored schema in a pruned database",
			other: []model.Schema{{Database: "old", Name: "monitoring", Owner: "monitor"}},
			want: []string{
				`DROP DATABASE "old"`,
				`app: REASSIGN OWNED BY "monitor" TO CURRENT_USER`,
				`app: DROP OWNED BY "monitor"`,
				`postgres: REASSIGN OWNED BY "monitor" TO CURRENT_USER`,
				`postgres: DROP OWNED BY "monitor"`,
				`DROP ROLE "monitor"`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			desired := &model.Desired{
				Engine:    model.EnginePostgres,
				Roles:     []model.Role{{ID: pgID("admin"), Login: new(true)}},
				Databases: []model.Database{{Name: "app", Owner: "admin"}},
				Ignore:    model.Ignore{Schemas: []string{"monitoring"}},
			}
			current := &model.Current{
				CurrentUser:        pgID("admin"),
				CurrentDatabase:    "postgres",
				Roles:              []model.RoleState{{ID: pgID("admin"), Login: true}, {ID: pgID("monitor")}},
				Databases:          []model.Database{{Name: "app", Owner: "admin"}, {Name: "old", Owner: "admin"}, {Name: "postgres", Owner: "admin"}},
				InspectedDatabases: []string{"app"},
				OtherSchemas:       tt.other,
			}
			p, err := compute(t, desired, current, postgres.Dialect{}, diff.Options{Prune: true})
			if err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(tt.want, statements(p), cmpopts.EquateEmpty()); d != "" {
				t.Errorf("statements (-want +got):\n%s", d)
			}
			var warns []string
			for _, w := range p.Warnings {
				if strings.Contains(w, `"monitor"`) {
					warns = append(warns, w)
				}
			}
			if d := cmp.Diff(tt.wantWarns, warns, cmpopts.EquateEmpty()); d != "" {
				t.Errorf("warnings (-want +got):\n%s", d)
			}
		})
	}
}

// TestComputePruneEntangled checks that --prune keeps the databases and
// schemas model.Current.Entangled names, with a warning, and drops the
// others.
func TestComputePruneEntangled(t *testing.T) {
	t.Parallel()
	db := func(name string) model.Object { return model.Object{Type: model.ObjectDatabase, Database: name} }
	sch := func(d, name string) model.Object { return model.Object{Type: model.ObjectSchema, Database: d, Schema: name} }
	tests := []struct {
		entangled map[model.Object]string
		name      string
		want      []string
		wantWarns []string
	}{
		{
			name: "nothing entangled",
			want: []string{`app: DROP SCHEMA "old"`, `DROP DATABASE "old"`},
		},
		{
			name:      "database",
			entangled: map[model.Object]string{db("old"): "it is owned by role X"},
			want:      []string{`app: DROP SCHEMA "old"`},
			wantWarns: []string{`database "old": it is owned by role X, so it is not pruned; handle it manually`},
		},
		{
			name:      "schema",
			entangled: map[model.Object]string{sch("app", "old"): "it grants USAGE to role X"},
			want:      []string{`DROP DATABASE "old"`},
			wantWarns: []string{`schema "old" in database "app": it grants USAGE to role X, so it is not pruned; handle it manually`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			desired := &model.Desired{Engine: model.EnginePostgres, Databases: []model.Database{{Name: "app", Owner: "admin"}}}
			current := &model.Current{
				CurrentUser:        pgID("admin"),
				CurrentDatabase:    "postgres",
				Roles:              []model.RoleState{{ID: pgID("admin"), Login: true, Superuser: true}},
				Databases:          []model.Database{{Name: "app", Owner: "admin"}, {Name: "old", Owner: "admin"}, {Name: "postgres", Owner: "admin"}},
				Schemas:            []model.Schema{{Database: "app", Name: "old", Owner: "admin"}},
				InspectedDatabases: []string{"app"},
				Entangled:          tt.entangled,
			}
			p, err := compute(t, desired, current, postgres.Dialect{}, diff.Options{Prune: true})
			if err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(tt.want, statements(p), cmpopts.EquateEmpty()); d != "" {
				t.Errorf("statements (-want +got):\n%s", d)
			}
			var warns []string
			for _, w := range p.Warnings {
				if strings.Contains(w, "it is not pruned") {
					warns = append(warns, w)
				}
			}
			if d := cmp.Diff(tt.wantWarns, warns, cmpopts.EquateEmpty()); d != "" {
				t.Errorf("warnings (-want +got):\n%s", d)
			}
		})
	}
}
