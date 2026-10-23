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
			name:    "PUBLIC is rendered unquoted",
			acl:     []aclEntry{entry(db, "public", "owner", "CONNECT", false), entry(db, "public", "owner", "TEMPORARY", false)},
			obj:     db,
			grantee: "public", privs: []string{"CONNECT", "TEMPORARY"},
			want: `REVOKE CONNECT, TEMPORARY ON DATABASE "app" FROM PUBLIC`,
		},
		{
			name: "PUBLIC grant by another grantor",
			acl: []aclEntry{
				entry(schema, "ro", "owner", "USAGE", true),
				entry(schema, "public", "ro", "USAGE", false),
			},
			obj:     schema,
			grantee: "public", privs: []string{"USAGE"},
			want: `app: SET ROLE "ro"; REVOKE USAGE ON SCHEMA "api" FROM PUBLIC; RESET ROLE`,
		},
		{
			name: "PUBLIC as a dependent of a cascade is granted again",
			acl: []aclEntry{
				entry(schema, "ro", "owner", "USAGE", true),
				entry(schema, "public", "ro", "USAGE", false),
			},
			desired: []model.Privilege{{Grantee: model.PublicRole, Object: schema, Name: "USAGE"}},
			obj:     schema,
			grantee: "ro", privs: []string{"USAGE"}, optionOnly: true,
			want: "app: -- CASCADE: privileges granted on by the grantee to PUBLIC are revoked too; declared ones are granted again\n" +
				`REVOKE GRANT OPTION FOR USAGE ON SCHEMA "api" FROM "ro" CASCADE` + "\n" +
				`app: GRANT USAGE ON SCHEMA "api" TO PUBLIC`,
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

func TestNonSuperuserChecks(t *testing.T) {
	t.Parallel()
	roles := map[string]roleAccess{
		"settable": {set: true, use: true},
		"admined":  {admin: true},
		"foreign":  {},
		"super":    {superuser: true, admin: true},
	}
	tests := []struct {
		name      string
		selfGrant string
		role      string
		version   int
		wantSet   bool
		wantAlter bool
	}{
		{name: "settable", version: 170000, role: "settable", wantSet: true},
		{name: "admin only", version: 170000, role: "admined", wantAlter: true},
		{name: "foreign role", version: 170000, role: "foreign"},
		{name: "superuser role", version: 170000, role: "super"},
		{name: "new role with self grant", version: 170000, role: "new", selfGrant: "set, inherit", wantSet: true, wantAlter: true},
		{name: "new role without self grant", version: 170000, role: "new", wantAlter: true},
		{name: "self", version: 170000, role: "admin", wantSet: true, wantAlter: true},
		{name: "CREATEROLE alters any role before 16", version: 150000, role: "foreign", wantAlter: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			st := &state{user: "admin", version: tt.version, createRole: true, roles: roles, createroleSelfGrant: tt.selfGrant}
			if got := st.canSet(tt.role); got != tt.wantSet {
				t.Errorf("canSet = %v, want %v", got, tt.wantSet)
			}
			if got := st.canAlter(tt.role); got != tt.wantAlter {
				t.Errorf("canAlter = %v, want %v", got, tt.wantAlter)
			}
		})
	}
}

func TestNonSuperuserWarnings(t *testing.T) {
	t.Parallel()
	st := &state{
		user: "admin", version: 170000,
		roles: map[string]roleAccess{"mine": {set: true, use: true}, "theirs": {}, "kept": {}, "ignored": {}},
		owners: map[model.Object]string{
			{Type: model.ObjectSchema, Database: "app", Schema: "s"}: "theirs",
		},
		desired: &model.Desired{
			Roles:     []model.Role{{ID: pg("kept")}},
			Databases: []model.Database{{Name: "app", Owner: "theirs"}, {Name: "ok", Owner: "mine"}, {Name: "same", Owner: "theirs"}},
			Schemas:   []model.Schema{{Database: "app", Name: "s", Owner: "theirs"}, {Database: "app", Name: "new", Owner: "kept"}},
			Ignore:    model.Ignore{Roles: []string{"ign.*"}},
		},
	}
	cur := &model.Current{
		Databases: []model.Database{{Name: "same", Owner: "theirs"}},
		Roles:     []model.RoleState{{ID: pg("admin")}, {ID: pg("mine")}, {ID: pg("theirs")}, {ID: pg("kept")}, {ID: pg("ignored")}, {ID: pg("pg_monitor")}},
	}
	got := strings.Join(append(st.ownerWarnings(cur), st.pruneWarnings(cur)...), "\n")
	for _, want := range []string{
		`database "app": "admin" cannot SET ROLE "theirs"`,
		`schema "new" in database "app": "admin" cannot SET ROLE "kept"`,
		`role "theirs": "admin" does not have its privileges`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	for _, unwanted := range []string{`database "ok"`, `database "same"`, `schema "s"`, `role "mine"`, `role "kept"`, `role "ignored"`, "pg_monitor"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("unexpected %q in\n%s", unwanted, got)
		}
	}
}

func TestInheritOptions(t *testing.T) {
	t.Parallel()
	no, yes := false, true
	members := []memberEntry{
		{role: "g1", member: "u", grantor: "postgres", inherit: true},
		{role: "g2", member: "u", grantor: "postgres", inherit: false},
		{role: "g3", member: "u", grantor: "other", inherit: true},
		{role: "g4", member: "u", grantor: "postgres", inherit: true},
		{role: "g1", member: "v", grantor: "postgres", inherit: true},
	}
	tests := []struct {
		name      string
		want      string
		role      model.Role
		version   int
		superuser bool
		wantWarn  bool
	}{
		{
			name: "noinherit", version: 170000, superuser: true,
			role: model.Role{ID: pg("u"), Inherit: &no, MemberOf: []model.RoleID{pg("g1"), pg("g2"), pg("g3")}},
			want: `GRANT "g1" TO "u" WITH INHERIT FALSE GRANTED BY "postgres"` + "\n" + `GRANT "g3" TO "u" WITH INHERIT FALSE GRANTED BY "other"`,
		},
		{
			name: "inherit", version: 170000, superuser: true,
			role: model.Role{ID: pg("u"), Inherit: &yes},
			want: `GRANT "g2" TO "u" WITH INHERIT TRUE GRANTED BY "postgres"`,
		},
		{
			name: "grant by another role as non-superuser", version: 170000,
			role:     model.Role{ID: pg("u"), Inherit: &no, MemberOf: []model.RoleID{pg("g3")}},
			wantWarn: true,
		},
		{name: "unmanaged", version: 170000, superuser: true, role: model.Role{ID: pg("u")}},
		{name: "before 16", version: 150000, superuser: true, role: model.Role{ID: pg("u"), Inherit: &no}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			st := &state{user: "postgres", version: tt.version, superuser: tt.superuser, members: members}
			stmts, warns := st.inheritOptions(tt.role)
			if got := sqlOf(stmts); got != tt.want {
				t.Errorf("got\n%s\nwant\n%s", got, tt.want)
			}
			if (len(warns) > 0) != tt.wantWarn {
				t.Errorf("warnings = %v", warns)
			}
		})
	}
}

func TestDropSchema(t *testing.T) {
	t.Parallel()
	full := model.Schema{Database: "app", Name: "full"}
	tests := []struct {
		name   string
		st     *state
		schema model.Schema
		want   string
	}{
		{"not inspected", nil, full, `app: DROP SCHEMA "full"`},
		{"empty", &state{objects: map[model.Object]int{}}, model.Schema{Database: "app", Name: "empty"}, `app: DROP SCHEMA "empty"`},
		{
			"not empty",
			&state{objects: map[model.Object]int{{Type: model.ObjectSchema, Database: "app", Schema: "full"}: 2}},
			full,
			"app: -- CASCADE: the schema contains 2 objects, which are dropped too\nDROP SCHEMA \"full\" CASCADE",
		},
	}
	for _, tt := range tests {
		d := &Driver{st: tt.st}
		if got := sqlOf(d.DropSchema(tt.schema)); got != tt.want {
			t.Errorf("%s: got\n%s\nwant\n%s", tt.name, got, tt.want)
		}
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

func TestPublicRendering(t *testing.T) {
	t.Parallel()
	db := model.Object{Type: model.ObjectDatabase, Database: "app"}
	tests := []struct {
		name string
		want string
		got  []plan.Statement
	}{
		{name: "grant", got: Dialect{}.Grant(model.PublicRole, db, []string{"CONNECT"}, false), want: `GRANT CONNECT ON DATABASE "app" TO PUBLIC`},
		{name: "revoke", got: Dialect{}.Revoke(model.PublicRole, db, []string{"CONNECT"}), want: `REVOKE CONNECT ON DATABASE "app" FROM PUBLIC`},
		{name: "role named PUBLIC is quoted", got: Dialect{}.Grant(pg("PUBLIC"), db, []string{"CONNECT"}, false), want: `GRANT CONNECT ON DATABASE "app" TO "PUBLIC"`},
	}
	for _, tt := range tests {
		if got := sqlOf(tt.got); got != tt.want {
			t.Errorf("%s: got %s, want %s", tt.name, got, tt.want)
		}
	}
}

func TestDefaultPublicPrivileges(t *testing.T) {
	t.Parallel()
	db := model.Object{Type: model.ObjectDatabase, Database: "app"}
	public := model.Object{Type: model.ObjectSchema, Database: "app", Schema: "public"}
	api := model.Object{Type: model.ObjectSchema, Database: "app", Schema: "api"}
	tests := []struct {
		name    string
		want    string
		obj     model.Object
		version int
	}{
		{name: "database", obj: db, version: 170000, want: "CONNECT,TEMPORARY"},
		{name: "database before 15", obj: db, version: 140000, want: "CONNECT,TEMPORARY"},
		{name: "public schema", obj: public, version: 150000, want: "USAGE"},
		{name: "public schema before 15", obj: public, version: 140011, want: "CREATE,USAGE"},
		{name: "other schema", obj: api, version: 170000},
	}
	for _, tt := range tests {
		d := &Driver{st: &state{version: tt.version}}
		if got := strings.Join(d.DefaultPublicPrivileges(tt.obj), ","); got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, got, tt.want)
		}
	}
	if got := strings.Join(Dialect{}.DefaultPublicPrivileges(public), ","); got != "USAGE" {
		t.Errorf("Dialect: got %q, want USAGE", got)
	}
}

func TestUnreadableVerifiers(t *testing.T) {
	t.Parallel()
	pw := "pw"
	desired := &model.Desired{Roles: []model.Role{
		{ID: model.RoleID{Name: "b"}, Password: &pw},
		{ID: model.RoleID{Name: "a"}, Password: &pw},
		{ID: model.RoleID{Name: "nopw"}},
		{ID: model.RoleID{Name: "new"}, Password: &pw},
	}}
	tests := []struct {
		name  string
		want  string
		roles []model.RoleState
	}{
		{name: "none exist", roles: nil, want: ""},
		{name: "one", roles: []model.RoleState{{ID: model.RoleID{Name: "a"}}, {ID: model.RoleID{Name: "nopw"}}}, want: `cannot read the password verifiers of existing role "a" (superuser required)`},
		{name: "several sorted", roles: []model.RoleState{{ID: model.RoleID{Name: "b"}}, {ID: model.RoleID{Name: "a"}}}, want: `existing roles "a", "b" (superuser required)`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := unreadableVerifiersWarning(desired, &model.Current{Roles: tt.roles})
			if (tt.want == "") != (got == "") || !strings.Contains(got, tt.want) {
				t.Errorf("warning = %q, want substring %q", got, tt.want)
			}
		})
	}

	// The Driver leaves the per-role warning to the grouped one; the
	// stateless Dialect keeps it.
	r := model.Role{ID: model.RoleID{Name: "a"}, Password: &pw}
	cur := model.RoleState{ID: r.ID}
	if _, warns := (&Driver{st: &state{superuser: true}}).AlterRole(r, cur, false); len(warns) != 0 {
		t.Errorf("Driver warnings = %q, want none", warns)
	}
	if _, warns := (Dialect{}).AlterRole(r, cur, false); len(warns) != 1 {
		t.Errorf("Dialect warnings = %q, want one", warns)
	}
	if stmts, _ := (&Driver{st: &state{superuser: true}}).AlterRole(r, cur, true); len(stmts) != 1 {
		t.Errorf("forced password statements = %d, want 1", len(stmts))
	}
}

func TestDropRoleRegrants(t *testing.T) {
	t.Parallel()
	db := func(name string) model.Object { return model.Object{Type: model.ObjectDatabase, Database: name} }
	sch := model.Object{Type: model.ObjectSchema, Database: "app", Schema: "api"}
	desired := &model.Desired{
		Roles: []model.Role{
			{ID: model.RoleID{Name: "y"}},
			{ID: model.RoleID{Name: "q"}},
			{ID: model.RoleID{Name: "z"}, MemberOf: []model.RoleID{{Name: "g"}}},
			{ID: model.RoleID{Name: "w"}, MemberOf: []model.RoleID{{Name: "g"}}, MemberOptions: map[model.RoleID]model.MembershipOptions{{Name: "g"}: {Admin: new(true)}}},
		},
		Privileges: []model.Privilege{
			{Grantee: model.RoleID{Name: "y"}, Object: db("app"), Name: "CONNECT", GrantOption: true},
			{Grantee: model.RoleID{Name: "q"}, Object: db("app"), Name: "CONNECT"},
			{Grantee: model.RoleID{Name: "y"}, Object: sch, Name: "USAGE"},
			{Grantee: model.RoleID{Name: "y"}, Object: db("owned"), Name: "CONNECT"},
			{Grantee: model.RoleID{Name: "y"}, Object: db("gone"), Name: "CONNECT"},
		},
	}
	acl := []aclEntry{
		{obj: db("app"), grantee: "x", grantor: "postgres", priv: "CONNECT", grantable: true},
		{obj: db("app"), grantee: "y", grantor: "x", priv: "CONNECT", grantable: true},
		{obj: db("app"), grantee: "q", grantor: "y", priv: "CONNECT"},
		{obj: db("app"), grantee: "undeclared", grantor: "x", priv: "CONNECT"},
		{obj: sch, grantee: "y", grantor: "x", priv: "USAGE"},
		{obj: db("owned"), grantee: "y", grantor: "x", priv: "CONNECT"},
		{obj: db("gone"), grantee: "y", grantor: "x", priv: "CONNECT"},
	}
	members := []memberEntry{
		{role: "g", member: "x", grantor: "postgres", admin: true},
		{role: "g", member: "z", grantor: "x"},
		{role: "g", member: "w", grantor: "x", admin: true},
		{role: "g", member: "undeclared", grantor: "w"},
	}
	newState := func(version int) *state {
		return &state{
			desired: desired, acl: acl, members: members, version: version, user: "postgres", superuser: true,
			connectable: map[string]bool{"app": true, "owned": true, "postgres": true},
			owners:      map[model.Object]string{db("app"): "postgres", db("owned"): "x", sch: "postgres"},
		}
	}
	drop := `app: REASSIGN OWNED BY "x" TO CURRENT_USER
app: DROP OWNED BY "x"
owned: REASSIGN OWNED BY "x" TO CURRENT_USER
owned: DROP OWNED BY "x"
DROP ROLE "x"`
	tests := []struct {
		name      string
		want      string
		databases []string
		version   int
	}{
		{
			name:      "PostgreSQL 17",
			version:   170000,
			databases: []string{"app", "owned"},
			want: drop + `
GRANT CONNECT ON DATABASE "app" TO "q"
GRANT CONNECT ON DATABASE "app" TO "y" WITH GRANT OPTION
app: GRANT USAGE ON SCHEMA "api" TO "y"
GRANT "g" TO "w" WITH ADMIN OPTION
GRANT "g" TO "z"`,
		},
		{
			name:      "memberships survive before PostgreSQL 16",
			version:   150000,
			databases: []string{"app", "owned"},
			want: drop + `
GRANT CONNECT ON DATABASE "app" TO "q"
GRANT CONNECT ON DATABASE "app" TO "y" WITH GRANT OPTION
app: GRANT USAGE ON SCHEMA "api" TO "y"`,
		},
		{
			name:      "no reachable database",
			version:   170000,
			databases: []string{"noconn"},
			want:      `DROP ROLE "x"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := &Driver{st: newState(tt.version)}
			if got := sqlOf(d.DropRole(model.RoleID{Name: "x"}, tt.databases)); got != tt.want {
				t.Errorf("got\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}
