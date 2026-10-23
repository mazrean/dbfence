package postgres

import (
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
)

func sqlOf(stmts []plan.Statement) string {
	out := make([]string, len(stmts))
	for i, s := range stmts {
		out[i] = s.SQL()
		if s.Database != "" {
			out[i] = s.Database + ": " + out[i]
		}
	}
	return strings.Join(out, "\n")
}

func TestStateRevoke(t *testing.T) {
	t.Parallel()
	schema := model.Object{Type: model.ObjectSchema, Database: "app", Schema: "api"}
	db := model.Object{Type: model.ObjectDatabase, Database: "app"}
	entry := func(obj model.Object, grantee, grantor, priv string, grantable bool) aclEntry {
		return aclEntry{obj: obj, grantee: grantee, grantor: grantor, priv: priv, grantable: grantable}
	}
	tests := []struct {
		name       string
		want       string
		grantee    string
		obj        model.Object
		acl        []aclEntry
		desired    []model.Privilege
		privs      []string
		optionOnly bool
	}{
		{
			name:    "owner grant",
			acl:     []aclEntry{entry(db, "b", "owner", "CONNECT", false)},
			obj:     db,
			grantee: "b", privs: []string{"CONNECT"},
			want: `REVOKE CONNECT ON DATABASE "app" FROM "b"`,
		},
		{
			name: "grant by another grantor is revoked as that grantor",
			acl: []aclEntry{
				entry(schema, "ro", "owner", "USAGE", true),
				entry(schema, "app", "ro", "USAGE", false),
			},
			obj:     schema,
			grantee: "app", privs: []string{"USAGE"},
			want: `app: SET ROLE "ro"; REVOKE USAGE ON SCHEMA "api" FROM "app"; RESET ROLE`,
		},
		{
			name: "two grantors",
			acl: []aclEntry{
				entry(db, "b", "owner", "CONNECT", false),
				entry(db, "b", "a", "CONNECT", true),
			},
			obj:     db,
			grantee: "b", privs: []string{"CONNECT"}, optionOnly: true,
			want: `SET ROLE "a"; REVOKE GRANT OPTION FOR CONNECT ON DATABASE "app" FROM "b"; RESET ROLE`,
		},
		{
			name: "dependent grants cascade and declared ones are granted again",
			acl: []aclEntry{
				entry(schema, "ro", "owner", "USAGE", true),
				entry(schema, "app", "ro", "USAGE", true),
				entry(schema, "x", "app", "USAGE", false),
				entry(schema, "other", "ro", "CREATE", false),
			},
			desired: []model.Privilege{
				{Grantee: pg("app"), Object: schema, Name: "USAGE"},
				{Grantee: pg("x"), Object: schema, Name: "USAGE", GrantOption: true},
			},
			obj:     schema,
			grantee: "ro", privs: []string{"USAGE"}, optionOnly: true,
			want: "app: -- CASCADE: privileges granted on by the grantee to \"app\", \"x\" are revoked too; declared ones are granted again\n" +
				`REVOKE GRANT OPTION FOR USAGE ON SCHEMA "api" FROM "ro" CASCADE` + "\n" +
				`app: GRANT USAGE ON SCHEMA "api" TO "app"` + "\n" +
				`app: GRANT USAGE ON SCHEMA "api" TO "x" WITH GRANT OPTION`,
		},
		{
			name: "grant covered by the cascade of its grantor is skipped",
			acl: []aclEntry{
				entry(schema, "ro", "owner", "USAGE", true),
				entry(schema, "x", "ro", "USAGE", false),
				entry(schema, "x", "owner", "USAGE", false),
			},
			desired: []model.Privilege{{Grantee: pg("ro"), Object: schema, Name: "USAGE"}},
			obj:     schema,
			grantee: "x", privs: []string{"USAGE"},
			want: `app: REVOKE USAGE ON SCHEMA "api" FROM "x"`,
		},
		{
			name:    "unknown grantor falls back to a plain revoke",
			obj:     db,
			grantee: "b", privs: []string{"CREATE", "TEMPORARY"},
			want: `REVOKE CREATE, TEMPORARY ON DATABASE "app" FROM "b"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			st := &state{
				desired: &model.Desired{Privileges: tt.desired, Roles: rolesOf(tt.desired)},
				owners:  map[model.Object]string{db: "owner", schema: "owner"},
				acl:     tt.acl,
				user:    "postgres", superuser: true,
			}
			if got := sqlOf(st.revoke(tt.grantee, tt.obj, tt.privs, tt.optionOnly)); got != tt.want {
				t.Errorf("got\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}

// rolesOf declares the grantees of privs.
func rolesOf(privs []model.Privilege) []model.Role {
	var out []model.Role
	for _, p := range privs {
		out = append(out, model.Role{ID: p.Grantee})
	}
	return out
}

func TestStateRevokeMembership(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		want    string
		members []memberEntry
		desired []model.Role
	}{
		{
			name:    "one grant per grantor",
			members: []memberEntry{{role: "grp", member: "u", grantor: "mgr"}, {role: "grp", member: "u", grantor: "postgres"}},
			want:    `REVOKE "grp" FROM "u" GRANTED BY "mgr"` + "\n" + `REVOKE "grp" FROM "u" GRANTED BY "postgres"`,
		},
		{
			name: "dependent memberships cascade",
			members: []memberEntry{
				{role: "grp", member: "u", grantor: "postgres", admin: true},
				{role: "grp", member: "v", grantor: "u"},
				{role: "other", member: "w", grantor: "u"},
			},
			desired: []model.Role{{ID: pg("v"), MemberOf: []model.RoleID{pg("grp")}}},
			want: "-- CASCADE: memberships granted on by the grantee to \"v\" are revoked too; declared ones are granted again\n" +
				`REVOKE "grp" FROM "u" GRANTED BY "postgres" CASCADE` + "\n" + `GRANT "grp" TO "v"`,
		},
		{
			name: "grant covered by the cascade of its grantor is skipped",
			members: []memberEntry{
				{role: "grp", member: "u", grantor: "boss"},
				{role: "grp", member: "u", grantor: "postgres"},
			},
			desired: []model.Role{{ID: pg("boss"), MemberOf: []model.RoleID{}}},
			want:    `REVOKE "grp" FROM "u" GRANTED BY "postgres"`,
		},
		{
			name: "not inspected",
			want: `REVOKE "grp" FROM "u"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			st := &state{desired: &model.Desired{Roles: tt.desired}, members: tt.members, version: 170000}
			if got := sqlOf(st.revokeMembership("u", "grp")); got != tt.want {
				t.Errorf("got\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}

func TestDriverWithoutInspectBehavesLikeDialect(t *testing.T) {
	t.Parallel()
	d := &Driver{}
	obj := model.Object{Type: model.ObjectDatabase, Database: "app"}
	if got, want := sqlOf(d.Revoke(pg("a"), obj, []string{"CONNECT"})), sqlOf(Dialect{}.Revoke(pg("a"), obj, []string{"CONNECT"})); got != want {
		t.Errorf("Revoke = %s, want %s", got, want)
	}
	if got := sqlOf(d.RevokeMembership(pg("u"), pg("g"))); got != `REVOKE "g" FROM "u"` {
		t.Errorf("RevokeMembership = %s", got)
	}
	// Before PostgreSQL 16 there is a single grant without GRANTED BY.
	d.st = &state{version: 150000, members: []memberEntry{{role: "g", member: "u", grantor: "x"}}}
	if got := sqlOf(d.RevokeMembership(pg("u"), pg("g"))); got != `REVOKE "g" FROM "u"` {
		t.Errorf("RevokeMembership on 15 = %s", got)
	}
}
