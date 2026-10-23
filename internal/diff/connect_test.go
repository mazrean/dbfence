package diff_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/driver/postgres"
	"github.com/mazrean/dbfence/internal/model"
)

// dbfence connects to database "postgres" on every run: a revoke of
// CONNECT there that leaves the connected user, not a superuser, without
// it would lock dbfence out, so it is not planned.
func TestComputeKeepsConnect(t *testing.T) {
	t.Parallel()
	admin, ops := pgID("admin"), pgID("ops")
	priv := func(grantee model.RoleID, db string, names ...string) []model.Privilege {
		var out []model.Privilege
		for _, n := range names {
			out = append(out, model.Privilege{Grantee: grantee, Object: dbObj(db), Name: n})
		}
		return out
	}
	warn := func(grantee string) string {
		return `not revoking CONNECT on database "postgres" from ` + grantee + `: the connected user "admin" connects to it through it, and could not connect again`
	}
	tests := []struct {
		name      string
		current   []model.Privilege
		declare   []model.Privilege
		public    []model.Object
		roles     []model.Role
		want      []string
		warns     []string
		superuser bool
		noInherit bool
	}{
		{
			name:    "from PUBLIC",
			current: priv(model.PublicRole, "postgres", "CONNECT", "TEMPORARY"),
			public:  []model.Object{dbObj("postgres")},
			want:    []string{`REVOKE TEMPORARY ON DATABASE "postgres" FROM PUBLIC`},
			warns:   []string{warn("PUBLIC")},
		},
		{
			name:    "from the connected user",
			current: priv(admin, "postgres", "CONNECT"),
			declare: priv(admin, "postgres", "TEMPORARY"),
			roles:   []model.Role{{ID: admin}},
			want:    []string{`GRANT TEMPORARY ON DATABASE "postgres" TO "admin"`},
			warns:   []string{warn(`"admin"`)},
		},
		{
			name:    "from a role the connected user inherits from",
			current: priv(ops, "postgres", "CONNECT"),
			roles:   []model.Role{{ID: ops}},
			warns:   []string{warn(`"ops"`)},
		},
		{
			name:      "from a role the connected user does not inherit from",
			current:   append(priv(ops, "postgres", "CONNECT"), priv(model.PublicRole, "postgres", "CONNECT")...),
			public:    []model.Object{dbObj("postgres")},
			noInherit: true,
			want:      []string{`REVOKE CONNECT ON DATABASE "postgres" FROM "ops"`},
			warns:     []string{warn("PUBLIC")},
		},
		{
			name:    "from PUBLIC while the connected user has it itself",
			current: append(priv(model.PublicRole, "postgres", "CONNECT"), priv(admin, "postgres", "CONNECT")...),
			public:  []model.Object{dbObj("postgres")},
			want:    []string{`REVOKE CONNECT ON DATABASE "postgres" FROM PUBLIC`},
		},
		{
			name:    "from PUBLIC while it is granted to the connected user",
			current: priv(model.PublicRole, "postgres", "CONNECT"),
			declare: priv(admin, "postgres", "CONNECT"),
			public:  []model.Object{dbObj("postgres")},
			roles:   []model.Role{{ID: admin}},
			want: []string{
				`GRANT CONNECT ON DATABASE "postgres" TO "admin"`,
				`REVOKE CONNECT ON DATABASE "postgres" FROM PUBLIC`,
			},
		},
		{
			name:      "from PUBLIC with a superuser",
			current:   priv(model.PublicRole, "postgres", "CONNECT"),
			public:    []model.Object{dbObj("postgres")},
			superuser: true,
			want:      []string{`REVOKE CONNECT ON DATABASE "postgres" FROM PUBLIC`},
		},
		{
			name:    "from PUBLIC on another database",
			current: priv(model.PublicRole, "app", "CONNECT"),
			public:  []model.Object{dbObj("app")},
			want:    []string{`REVOKE CONNECT ON DATABASE "app" FROM PUBLIC`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.noInherit {
				tt.roles = append(tt.roles, model.Role{ID: ops})
			}
			cur := &model.Current{
				CurrentUser: admin, CurrentDatabase: "postgres",
				Roles: []model.RoleState{
					{ID: admin, Login: true, Inherit: !tt.noInherit, Superuser: tt.superuser, MemberOf: []model.RoleID{ops},
						MemberOptions: map[model.RoleID]model.MembershipState{ops: {Inherit: true, Set: true}}},
					{ID: ops, Inherit: true},
				},
				Databases:          []model.Database{{Name: "postgres", Owner: "postgres"}, {Name: "app", Owner: "postgres"}},
				Privileges:         tt.current,
				InspectedDatabases: []string{"postgres", "app"},
			}
			desired := &model.Desired{
				Engine:        model.EnginePostgres,
				Roles:         tt.roles,
				Databases:     []model.Database{{Name: "postgres"}, {Name: "app"}},
				Privileges:    tt.declare,
				PublicObjects: tt.public,
			}
			p, err := compute(t, desired, cur, postgres.Dialect{}, diff.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(tt.want, statements(p), cmpopts.EquateEmpty()); d != "" {
				t.Errorf("statements (-want +got):\n%s", d)
			}
			warns := slices.DeleteFunc(slices.Clone(p.Warnings), func(w string) bool {
				return !strings.HasPrefix(w, "not revoking CONNECT")
			})
			if d := cmp.Diff(tt.warns, warns, cmpopts.EquateEmpty()); d != "" {
				t.Errorf("warnings (-want +got):\n%s", d)
			}
		})
	}
}
