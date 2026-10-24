package diff_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/driver/postgres"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/policy"
)

// Select keeps the changes of the selected objects and the creation of
// the objects they name; every selected plan must pass the safety check.
func TestSelect(t *testing.T) {
	t.Parallel()
	created := &model.Current{CurrentUser: pgID("postgres"), Roles: []model.RoleState{{ID: pgID("postgres")}}, Databases: []model.Database{{Name: "postgres"}}}
	drifted := pgMatching(t)
	drifted.Roles[4].Login = false
	drifted.Roles[4].MemberOf = []model.RoleID{pgID("owner"), pgID("postgres")}
	drifted.Databases[1].Owner = "app"
	drifted.Privileges = append(drifted.Privileges, model.Privilege{Grantee: pgID("app"), Object: dbObj("app"), Name: "TEMPORARY"})
	tests := []struct {
		current *model.Current
		name    string
		addrs   []model.Address
		want    []string
	}{
		{
			name:    "role without dependencies",
			current: created,
			addrs:   []model.Address{{Role: pgID("owner")}},
			want:    []string{`CREATE ROLE "owner" WITH NOLOGIN`},
		},
		{
			name:    "user with its memberships, grants and what they need",
			current: created,
			addrs:   []model.Address{{Role: pgID("app")}},
			want: []string{
				`CREATE ROLE "owner" WITH NOLOGIN`,
				`CREATE ROLE "app" WITH LOGIN PASSWORD '<redacted>'`,
				`GRANT "owner" TO "app"`,
				`CREATE DATABASE "app" OWNER "owner"`,
				`app: CREATE SCHEMA "api" AUTHORIZATION "owner"`,
				`GRANT CONNECT ON DATABASE "app" TO "app"`,
				`app: GRANT USAGE ON SCHEMA "api" TO "app"`,
			},
		},
		{
			name:    "database with its grants, not the grantee's memberships",
			current: created,
			addrs:   []model.Address{{Database: "app"}},
			want: []string{
				`CREATE ROLE "owner" WITH NOLOGIN`,
				`CREATE ROLE "app" WITH LOGIN PASSWORD '<redacted>'`,
				`CREATE DATABASE "app" OWNER "owner"`,
				`GRANT CONNECT ON DATABASE "app" TO "app"`,
			},
		},
		{
			name:    "schema pulls in its database",
			current: created,
			addrs:   []model.Address{{Database: "app", Schema: "api"}},
			want: []string{
				`CREATE ROLE "owner" WITH NOLOGIN`,
				`CREATE ROLE "app" WITH LOGIN PASSWORD '<redacted>'`,
				`CREATE DATABASE "app" OWNER "owner"`,
				`app: CREATE SCHEMA "api" AUTHORIZATION "owner"`,
				`app: GRANT USAGE ON SCHEMA "api" TO "app"`,
			},
		},
		{
			name:    "existing objects are not pulled in",
			current: drifted,
			addrs:   []model.Address{{Database: "app"}},
			want: []string{
				`ALTER DATABASE "app" OWNER TO "owner"`,
				// The owner change takes the privileges of the old owner
				// "app" with it, so CONNECT is granted again.
				`GRANT CONNECT ON DATABASE "app" TO "app"`,
			},
		},
		{
			name:    "drift of a role",
			current: drifted,
			addrs:   []model.Address{{Role: pgID("app")}},
			want: []string{
				`ALTER ROLE "app" WITH LOGIN`,
				`REVOKE "postgres" FROM "app"`,
				`GRANT CONNECT ON DATABASE "app" TO "app"`,
			},
		},
		{
			name:    "nothing selected",
			current: drifted,
			addrs:   []model.Address{{Role: pgID("owner")}},
			want:    []string{},
		},
		{
			name:    "several addresses",
			current: created,
			addrs:   []model.Address{{Role: pgID("owner")}, {Database: "app"}},
			want: []string{
				`CREATE ROLE "owner" WITH NOLOGIN`,
				`CREATE ROLE "app" WITH LOGIN PASSWORD '<redacted>'`,
				`CREATE DATABASE "app" OWNER "owner"`,
				`GRANT CONNECT ON DATABASE "app" TO "app"`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := pgDesired()
			p, err := compute(t, d, tt.current, postgres.Dialect{}, diff.Options{})
			if err != nil {
				t.Fatal(err)
			}
			sel := p.Select(tt.addrs)
			if diff := cmp.Diff(tt.want, statements(sel)); diff != "" {
				t.Errorf("statements (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(p.Warnings, sel.Warnings); diff != "" {
				t.Errorf("warnings (-want +got):\n%s", diff)
			}
			for _, v := range policy.Verify(sel, tt.current, d, policy.Options{System: postgres.Dialect{}}) {
				t.Errorf("safety check: %s", v)
			}
		})
	}
}
