package diff_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/driver/postgres"
	"github.com/mazrean/dbfence/internal/model"
)

// TestComputePublic checks that privileges of PUBLIC are managed only on
// objects named by a PUBLIC grant, including objects the plan creates.
func TestComputePublic(t *testing.T) {
	t.Parallel()
	api := model.Object{Type: model.ObjectSchema, Database: "app", Schema: "api"}
	public := model.Object{Type: model.ObjectSchema, Database: "app", Schema: "public"}
	pub := func(obj model.Object, names ...string) []model.Privilege {
		var out []model.Privilege
		for _, n := range names {
			out = append(out, model.Privilege{Grantee: model.PublicRole, Object: obj, Name: n})
		}
		return out
	}
	desired := func(objs []model.Object, privs ...model.Privilege) *model.Desired {
		return &model.Desired{
			Engine:        model.EnginePostgres,
			Roles:         []model.Role{{ID: pgID("app")}},
			Databases:     []model.Database{{Name: "app", Owner: "admin"}},
			Schemas:       []model.Schema{{Database: "app", Name: "api"}, {Database: "app", Name: "public"}},
			Privileges:    privs,
			PublicObjects: objs,
		}
	}
	existing := func(privs ...model.Privilege) *model.Current {
		return &model.Current{
			CurrentUser:        pgID("admin"),
			Roles:              []model.RoleState{{ID: pgID("admin"), Login: true}, {ID: pgID("app")}},
			Databases:          []model.Database{{Name: "app", Owner: "admin"}},
			Schemas:            []model.Schema{{Database: "app", Name: "api", Owner: "admin"}, {Database: "app", Name: "public", Owner: "pg_database_owner"}},
			Privileges:         privs,
			InspectedDatabases: []string{"app"},
		}
	}
	fresh := &model.Current{
		CurrentUser: pgID("admin"),
		Roles:       []model.RoleState{{ID: pgID("admin"), Login: true}, {ID: pgID("app")}},
	}
	defaults := append(pub(dbObj("app"), "CONNECT", "TEMPORARY"), pub(public, "USAGE")...)
	tests := []struct {
		desired   *model.Desired
		current   *model.Current
		name      string
		want      []string
		wantWarns []string
	}{
		{
			name:      "not managed without a PUBLIC grant",
			desired:   desired(nil),
			current:   existing(defaults...),
			wantWarns: []string{},
		},
		{
			name:    "privileges = [] revokes everything",
			desired: desired([]model.Object{dbObj("app"), public}),
			current: existing(defaults...),
			want: []string{
				`REVOKE CONNECT, TEMPORARY ON DATABASE "app" FROM PUBLIC`,
				`app: REVOKE USAGE ON SCHEMA "public" FROM PUBLIC`,
			},
			wantWarns: []string{},
		},
		{
			name:      "undeclared privileges are revoked, declared ones granted",
			desired:   desired([]model.Object{dbObj("app"), api}, append(pub(dbObj("app"), "CONNECT"), pub(api, "USAGE")...)...),
			current:   existing(defaults...),
			want:      []string{`app: GRANT USAGE ON SCHEMA "api" TO PUBLIC`, `REVOKE TEMPORARY ON DATABASE "app" FROM PUBLIC`},
			wantWarns: []string{},
		},
		{
			name:      "matching",
			desired:   desired([]model.Object{dbObj("app")}, pub(dbObj("app"), "CONNECT", "TEMPORARY")...),
			current:   existing(defaults...),
			wantWarns: []string{},
		},
		{
			name:    "new database starts with the defaults",
			desired: desired([]model.Object{dbObj("app"), public, api}),
			current: fresh,
			want: []string{
				`CREATE DATABASE "app" OWNER "admin"`,
				`app: CREATE SCHEMA "api"`,
				`REVOKE CONNECT, TEMPORARY ON DATABASE "app" FROM PUBLIC`,
				`app: REVOKE USAGE ON SCHEMA "public" FROM PUBLIC`,
			},
			wantWarns: []string{},
		},
		{
			name:    "new database keeps declared defaults",
			desired: desired([]model.Object{dbObj("app"), public}, append(pub(dbObj("app"), "CONNECT"), pub(public, "USAGE")...)...),
			current: fresh,
			want: []string{
				`CREATE DATABASE "app" OWNER "admin"`,
				`app: CREATE SCHEMA "api"`,
				`REVOKE TEMPORARY ON DATABASE "app" FROM PUBLIC`,
			},
			wantWarns: []string{},
		},
		{
			name:    "revoking from a role warns when PUBLIC keeps it",
			desired: desired(nil),
			current: existing(append(defaults, model.Privilege{Grantee: pgID("app"), Object: dbObj("app"), Name: "CONNECT"})...),
			want:    []string{`REVOKE CONNECT ON DATABASE "app" FROM "app"`},
			wantWarns: []string{
				`"app" keeps CONNECT on database "app" through PUBLIC; add a grant block with role = "PUBLIC" to manage the privileges of PUBLIC there`,
			},
		},
		{
			name:      "no warning where PUBLIC is managed",
			desired:   desired([]model.Object{dbObj("app")}, pub(dbObj("app"), "CONNECT", "TEMPORARY")...),
			current:   existing(append(defaults, model.Privilege{Grantee: pgID("app"), Object: dbObj("app"), Name: "CONNECT"})...),
			want:      []string{`REVOKE CONNECT ON DATABASE "app" FROM "app"`},
			wantWarns: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := compute(t, tt.desired, tt.current, postgres.Dialect{}, diff.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(tt.want, statements(p), cmpopts.EquateEmpty()); d != "" {
				t.Errorf("statements (-want +got):\n%s", d)
			}
			if d := cmp.Diff(tt.wantWarns, append([]string{}, p.Warnings...)); d != "" {
				t.Errorf("warnings (-want +got):\n%s", d)
			}
		})
	}
}
