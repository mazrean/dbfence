package diff_test

import (
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/driver/postgres"
	"github.com/mazrean/dbfence/internal/model"
)

// TestComputeOwnerACL checks privileges against the ACL as it will be
// after the planned owner changes (PostgreSQL aclnewowner).
func TestComputeOwnerACL(t *testing.T) {
	t.Parallel()
	api := model.Object{Type: model.ObjectSchema, Database: "app", Schema: "api"}
	priv := func(grantee string, obj model.Object, name string, opt bool) model.Privilege {
		return model.Privilege{Grantee: pgID(grantee), Object: obj, Name: name, GrantOption: opt}
	}
	desired := func(dbOwner, schemaOwner string, privs ...model.Privilege) *model.Desired {
		return &model.Desired{
			Engine:     model.EnginePostgres,
			Roles:      []model.Role{{ID: pgID("alice")}, {ID: pgID("bob")}},
			Databases:  []model.Database{{Name: "app", Owner: dbOwner}},
			Schemas:    []model.Schema{{Database: "app", Name: "api", Owner: schemaOwner}},
			Privileges: privs,
		}
	}
	current := func(dbOwner, schemaOwner string, privs ...model.Privilege) *model.Current {
		return &model.Current{
			CurrentUser:        pgID("admin"),
			Roles:              []model.RoleState{{ID: pgID("admin"), Login: true}, {ID: pgID("alice")}, {ID: pgID("bob")}},
			Databases:          []model.Database{{Name: "app", Owner: dbOwner}},
			Schemas:            []model.Schema{{Database: "app", Name: "api", Owner: schemaOwner}},
			Privileges:         privs,
			InspectedDatabases: []string{"app"},
		}
	}
	ownerACL := []model.Privilege{
		priv("alice", dbObj("app"), "CONNECT", true), priv("alice", dbObj("app"), "CREATE", true), priv("alice", dbObj("app"), "TEMPORARY", true),
		priv("alice", api, "CREATE", true), priv("alice", api, "USAGE", true),
	}
	tests := []struct {
		desired   *model.Desired
		current   *model.Current
		name      string
		want      []string
		wantWarns []string
	}{
		{
			name:    "declared grant for the old owner",
			desired: desired("bob", "bob", priv("alice", dbObj("app"), "CONNECT", false), priv("alice", api, "USAGE", false)),
			current: current("alice", "alice", ownerACL...),
			want: []string{
				`ALTER DATABASE "app" OWNER TO "bob"`,
				`app: ALTER SCHEMA "api" OWNER TO "bob"`,
				`GRANT CONNECT ON DATABASE "app" TO "alice"`,
				`app: GRANT USAGE ON SCHEMA "api" TO "alice"`,
			},
			wantWarns: []string{},
		},
		{
			name:    "no revokes from the old owner",
			desired: desired("bob", "bob"),
			current: current("alice", "alice", ownerACL...),
			want: []string{
				`ALTER DATABASE "app" OWNER TO "bob"`,
				`app: ALTER SCHEMA "api" OWNER TO "bob"`,
			},
			wantWarns: []string{},
		},
		{
			name:    "new owner had declared grants",
			desired: desired("bob", "bob", priv("bob", dbObj("app"), "CONNECT", false)),
			current: current("alice", "alice", append(slices.Clone(ownerACL), priv("bob", dbObj("app"), "CONNECT", false))...),
			want: []string{
				`ALTER DATABASE "app" OWNER TO "bob"`,
				`app: ALTER SCHEMA "api" OWNER TO "bob"`,
			},
			wantWarns: []string{`grant to "bob" on database "app" has no effect: "bob" owns it and holds every privilege implicitly`},
		},
		{
			name:      "owner unchanged",
			desired:   desired("alice", "", priv("bob", api, "USAGE", false)),
			current:   current("alice", "alice", append(slices.Clone(ownerACL), priv("bob", api, "USAGE", false), priv("bob", api, "CREATE", false))...),
			want:      []string{`app: REVOKE CREATE ON SCHEMA "api" FROM "bob"`},
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
			if d := cmp.Diff(tt.want, statements(p)); d != "" {
				t.Errorf("statements (-want +got):\n%s", d)
			}
			if d := cmp.Diff(tt.wantWarns, append([]string{}, p.Warnings...)); d != "" {
				t.Errorf("warnings (-want +got):\n%s", d)
			}
		})
	}
}

// TestComputeGrantorRows checks that one ACL row per grantor yields the
// same plan regardless of row order.
func TestComputeGrantorRows(t *testing.T) {
	t.Parallel()
	d := &model.Desired{
		Engine:     model.EnginePostgres,
		Roles:      []model.Role{{ID: pgID("b")}},
		Databases:  []model.Database{{Name: "app", Owner: "admin"}},
		Privileges: []model.Privilege{{Grantee: pgID("b"), Object: dbObj("app"), Name: "CONNECT"}},
	}
	rows := []model.Privilege{
		{Grantee: pgID("b"), Object: dbObj("app"), Name: "CONNECT", GrantOption: true},
		{Grantee: pgID("b"), Object: dbObj("app"), Name: "CONNECT"},
	}
	for _, order := range [][]model.Privilege{rows, {rows[1], rows[0]}} {
		cur := &model.Current{
			CurrentUser: pgID("admin"),
			Roles:       []model.RoleState{{ID: pgID("admin"), Login: true}, {ID: pgID("b")}},
			Databases:   []model.Database{{Name: "app", Owner: "admin"}},
			Privileges:  order,
		}
		p, err := compute(t, d, cur, postgres.Dialect{}, diff.Options{})
		if err != nil {
			t.Fatal(err)
		}
		want := []string{`REVOKE GRANT OPTION FOR CONNECT ON DATABASE "app" FROM "b"`}
		if d := cmp.Diff(want, statements(p)); d != "" {
			t.Errorf("statements (-want +got):\n%s", d)
		}
	}
}
