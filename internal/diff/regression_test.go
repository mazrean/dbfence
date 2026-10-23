package diff_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mazrean/dbfence/internal/diff"
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
