package diff_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/driver/mysql"
	"github.com/mazrean/dbfence/internal/driver/postgres"
	"github.com/mazrean/dbfence/internal/model"
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
			p, err := diff.Compute(tt.desired, tt.current, postgres.Dialect{}, diff.Options{})
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
				`postgres: REASSIGN OWNED BY "stray" TO CURRENT_USER`,
				`postgres: DROP OWNED BY "stray"`,
				`app: REASSIGN OWNED BY "stray" TO CURRENT_USER`,
				`app: DROP OWNED BY "stray"`,
				`DROP ROLE "stray"`,
			},
			wantWarns: []string{
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
				`role "dba@%" is granted to the connected user "admin@%"; not pruned`,
				`role "super@%" is granted to the connected user "admin@%"; not pruned`,
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
				`role "legacy_owner" owns the ignored database "keepme"; not pruned`,
				`role "vendor_owner" owns the ignored schema "vendor" in database "app"; not pruned`,
			},
		},
		{
			name:    "connected database",
			desired: &model.Desired{Engine: model.EnginePostgres},
			current: func() *model.Current {
				c := pgCur(nil, []model.Database{{Name: "conn_db", Owner: "admin"}, {Name: "legacy", Owner: "admin"}})
				c.CurrentDatabase = "conn_db"
				return c
			}(),
			dialect:   postgres.Dialect{},
			want:      []string{`DROP DATABASE "legacy"`},
			wantWarns: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := diff.Compute(tt.desired, tt.current, tt.dialect, diff.Options{Prune: !tt.noPrune})
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
