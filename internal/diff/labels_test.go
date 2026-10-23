package diff_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/driver/mysql"
	"github.com/mazrean/dbfence/internal/driver/postgres"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
)

func resources(p *plan.Plan) []string {
	out := []string{}
	for _, c := range p.Changes {
		out = append(out, fmt.Sprintf("[%s] %s", c.Action, c.Resource))
	}
	return out
}

// TestComputeLabels checks the change headers of the plan.
func TestComputeLabels(t *testing.T) {
	t.Parallel()
	team := model.RoleID{Name: "team@ops", Host: "%"}
	m := model.RoleID{Name: "m@x", Host: "localhost"}
	tests := []struct {
		desired *model.Desired
		current *model.Current
		dialect diff.Dialect
		name    string
		want    []string
	}{
		{
			name: "postgres users, roles and schema targets",
			desired: &model.Desired{
				Engine:    model.EnginePostgres,
				Roles:     []model.Role{{ID: pgID("ro"), Login: new(false)}, {ID: pgID("app"), Login: new(true), MemberOf: []model.RoleID{pgID("ro")}}},
				Databases: []model.Database{{Name: "app"}},
				Schemas:   []model.Schema{{Database: "app", Name: "api"}},
				Privileges: []model.Privilege{
					{Grantee: pgID("ro"), Object: model.Object{Type: model.ObjectSchema, Database: "app", Schema: "api"}, Name: "USAGE"},
					{Grantee: pgID("app"), Object: dbObj("app"), Name: "CONNECT"},
				},
			},
			current: &model.Current{
				CurrentUser: pgID("admin"),
				Roles:       []model.RoleState{{ID: pgID("admin"), Login: true}, {ID: pgID("stray"), Login: true}},
			},
			dialect: postgres.Dialect{},
			want: []string{
				`[create] role "ro"`,
				`[create] user "app"`,
				`[grant] membership of "app" in "ro"`,
				`[create] database "app"`,
				`[create] schema "api" in database "app"`,
				`[grant] CONNECT on database "app" to "app"`,
				`[grant] USAGE on schema "api" in database "app" to "ro"`,
				`[drop] user "stray"`,
			},
		},
		{
			name: "mysql accounts with @ in the name",
			desired: &model.Desired{
				Engine: model.EngineMySQL,
				Roles:  []model.Role{{ID: team, Login: new(false)}, {ID: m, Login: new(true), MemberOf: []model.RoleID{team}}},
			},
			current: &model.Current{
				CurrentUser: model.RoleID{Name: "root", Host: "localhost"},
				Roles:       []model.RoleState{{ID: model.RoleID{Name: "root", Host: "localhost"}, Login: true}},
			},
			dialect: mysql.Dialect{},
			want: []string{
				`[create] role "team@ops"@"%"`,
				`[create] user "m@x"@"localhost"`,
				`[grant] membership of "m@x"@"localhost" in "team@ops"@"%"`,
				`[update] default roles of user "m@x"@"localhost"`,
			},
		},
		{
			// The unescaped wildcard row is revoked and the literal grant
			// added; the headers must tell them apart.
			name: "mysql wildcard grant replaced by a literal one",
			desired: &model.Desired{
				Engine:     model.EngineMySQL,
				Roles:      []model.Role{{ID: team, Login: new(false)}},
				Databases:  []model.Database{{Name: "my_app"}},
				Privileges: []model.Privilege{{Grantee: team, Object: dbObj("my_app"), Name: "SELECT"}},
			},
			current: &model.Current{
				CurrentUser: model.RoleID{Name: "root", Host: "localhost"},
				Roles:       []model.RoleState{{ID: model.RoleID{Name: "root", Host: "localhost"}, Login: true}, {ID: team}},
				Databases:   []model.Database{{Name: "my_app"}},
				Privileges: []model.Privilege{{
					Grantee: team, Name: "SELECT",
					Object: model.Object{Type: model.ObjectDatabase, Database: "my_app", Pattern: "my_app"},
				}},
			},
			dialect: mysql.Dialect{},
			want: []string{
				`[grant] SELECT on database "my_app" to "team@ops"@"%"`,
				`[revoke] SELECT on database pattern "my_app" from "team@ops"@"%"`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := diff.Compute(tt.desired, tt.current, tt.dialect, diff.Options{Prune: true})
			if err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(tt.want, resources(p)); d != "" {
				t.Errorf("resources (-want +got):\n%s", d)
			}
		})
	}
}

// TestComputeDeterministicOrder checks that groups whose names join to
// the same string are still ordered deterministically.
func TestComputeDeterministicOrder(t *testing.T) {
	t.Parallel()
	usage := func(db, schema string) model.Privilege {
		return model.Privilege{Grantee: pgID("alice"), Object: model.Object{Type: model.ObjectSchema, Database: db, Schema: schema}, Name: "USAGE"}
	}
	d := &model.Desired{
		Engine:     model.EnginePostgres,
		Roles:      []model.Role{{ID: pgID("alice"), Login: new(false)}},
		Databases:  []model.Database{{Name: "c"}, {Name: "c.a"}},
		Schemas:    []model.Schema{{Database: "c", Name: "a.b"}, {Database: "c.a", Name: "b"}},
		Privileges: []model.Privilege{usage("c.a", "b"), usage("c", "a.b")},
	}
	cur := &model.Current{
		CurrentUser:        pgID("admin"),
		Roles:              []model.RoleState{{ID: pgID("admin"), Login: true}, {ID: pgID("alice")}},
		Databases:          []model.Database{{Name: "c", Owner: "admin"}, {Name: "c.a", Owner: "admin"}},
		Schemas:            []model.Schema{{Database: "c", Name: "a.b", Owner: "admin"}, {Database: "c.a", Name: "b", Owner: "admin"}},
		InspectedDatabases: []string{"c", "c.a"},
	}
	want := []string{
		`c: GRANT USAGE ON SCHEMA "a.b" TO "alice"`,
		`c.a: GRANT USAGE ON SCHEMA "b" TO "alice"`,
	}
	for range 50 {
		p, err := diff.Compute(d, cur, postgres.Dialect{}, diff.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if d := cmp.Diff(want, statements(p)); d != "" {
			t.Fatalf("statements (-want +got):\n%s", d)
		}
	}
}
