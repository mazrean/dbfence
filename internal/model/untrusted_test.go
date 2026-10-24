package model_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mazrean/dbfence/internal/model"
)

func TestCheckName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		engine model.Engine
		in     string
		want   string
		kind   model.NameKind
	}{
		{name: "plain", engine: model.EnginePostgres, kind: model.NameRole, in: "app"},
		{name: "empty", engine: model.EngineMySQL, kind: model.NameRole, in: ""},
		{name: "quotes and semicolons are fine", engine: model.EnginePostgres, kind: model.NameRole, in: `a"; DROP ROLE x; --`},
		{name: "non-ASCII", engine: model.EnginePostgres, kind: model.NameDatabase, in: "データ"},
		{name: "NUL", engine: model.EnginePostgres, kind: model.NameRole, in: "a\x00", want: "control characters"},
		{name: "newline", engine: model.EngineMySQL, kind: model.NameHost, in: "h\n", want: "control characters"},
		{name: "escape", engine: model.EngineMySQL, kind: model.NameDatabase, in: "\x1b[31m", want: "control characters"},
		{name: "DEL", engine: model.EnginePostgres, kind: model.NameSchema, in: "s\x7f", want: "control characters"},
		{name: "C1 NEL", engine: model.EnginePostgres, kind: model.NameRole, in: "a\u0085", want: "control characters"},
		{name: "C1 CSI", engine: model.EnginePostgres, kind: model.NameRole, in: "a\u009b", want: "control characters"},
		{name: "first after C1", engine: model.EnginePostgres, kind: model.NameRole, in: "a "},
		{name: "invalid UTF-8", engine: model.EnginePostgres, kind: model.NameRole, in: "a\xff", want: "not valid UTF-8"},
		{name: "postgres at limit", engine: model.EnginePostgres, kind: model.NameRole, in: strings.Repeat("a", 63)},
		{name: "postgres over limit", engine: model.EnginePostgres, kind: model.NameRole, in: strings.Repeat("a", 64), want: "64 bytes long, more than the postgres limit of 63"},
		{name: "postgres counts bytes", engine: model.EnginePostgres, kind: model.NameDatabase, in: strings.Repeat("é", 32), want: "64 bytes"},
		{name: "mysql user at limit", engine: model.EngineMySQL, kind: model.NameRole, in: strings.Repeat("é", 32)},
		{name: "mysql user over limit", engine: model.EngineMySQL, kind: model.NameRole, in: strings.Repeat("a", 33), want: "33 characters long, more than the mysql limit of 32"},
		{name: "mysql database at limit", engine: model.EngineMySQL, kind: model.NameDatabase, in: strings.Repeat("a", 64)},
		{name: "mysql database over limit", engine: model.EngineMySQL, kind: model.NameDatabase, in: strings.Repeat("a", 65), want: "limit of 64"},
		{name: "mysql host at limit", engine: model.EngineMySQL, kind: model.NameHost, in: strings.Repeat("a", 255)},
		{name: "mysql host over limit", engine: model.EngineMySQL, kind: model.NameHost, in: strings.Repeat("a", 256), want: "limit of 255"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := model.CheckName(tt.engine, tt.kind, tt.in)
			if (got == "") != (tt.want == "") || !strings.Contains(got, tt.want) {
				t.Errorf("CheckName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDropUntrusted(t *testing.T) {
	t.Parallel()
	bad := model.RoleID{Name: "evil\n"}
	app := model.RoleID{Name: "app"}
	db := func(name string) model.Object { return model.Object{Type: model.ObjectDatabase, Database: name} }
	cur := &model.Current{
		CurrentUser: model.RoleID{Name: "admin"},
		Roles: []model.RoleState{
			{ID: model.RoleID{Name: "admin"}},
			{ID: app, MemberOf: []model.RoleID{bad, {Name: "g"}}, MemberOptions: map[model.RoleID]model.MembershipState{bad: {}, {Name: "g"}: {}},
				DefaultRoles: []model.RoleID{bad}},
			{ID: bad},
			{ID: model.RoleID{Name: strings.Repeat("x", 64)}},
			{ID: model.RoleID{Name: "g"}},
		},
		Databases: []model.Database{{Name: "app", Owner: "evil\n"}, {Name: "d\x1b"}},
		Schemas:   []model.Schema{{Database: "app", Name: "s\u0085"}, {Database: "app", Name: "public"}},
		OtherSchemas: []model.Schema{
			{Database: "d\x1b", Name: "x"},
			{Database: "other", Name: "y"},
		},
		Privileges: []model.Privilege{
			{Grantee: app, Object: db("app"), Name: "CONNECT"},
			{Grantee: bad, Object: db("app"), Name: "CONNECT"},
			{Grantee: app, Object: db("d\x1b"), Name: "CONNECT"},
			{Grantee: app, Object: db("gone\x00"), Name: "CONNECT"},
			{Grantee: app, Object: model.Object{Type: model.ObjectSchema, Database: "app", Schema: "s\u0085"}, Name: "USAGE"},
			{Grantee: model.PublicRole, Object: db("app"), Name: "TEMPORARY"},
		},
		InspectedDatabases: []string{"app", "d\x1b"},
		Warnings:           []string{"earlier"},
	}
	u, err := cur.DropUntrusted(model.EnginePostgres)
	if err != nil {
		t.Fatal(err)
	}
	want := &model.Current{
		CurrentUser: model.RoleID{Name: "admin"},
		Roles: []model.RoleState{
			{ID: model.RoleID{Name: "admin"}},
			{ID: app, MemberOf: []model.RoleID{{Name: "g"}}, MemberOptions: map[model.RoleID]model.MembershipState{{Name: "g"}: {}}, DefaultRoles: []model.RoleID{}},
			{ID: model.RoleID{Name: "g"}},
		},
		Databases:    []model.Database{{Name: "app", Owner: "evil\n"}},
		Schemas:      []model.Schema{{Database: "app", Name: "public"}},
		OtherSchemas: []model.Schema{{Database: "other", Name: "y"}},
		Privileges: []model.Privilege{
			{Grantee: app, Object: db("app"), Name: "CONNECT"},
			{Grantee: model.PublicRole, Object: db("app"), Name: "TEMPORARY"},
		},
		InspectedDatabases: []string{"app"},
		Entangled:          map[model.Object]string{db("app"): `it is owned by role "evil\n", which dbfence does not manage`},
	}
	warnings := cur.Warnings
	cur.Warnings = nil
	if diff := cmp.Diff(want, cur, cmp.Comparer(func(a, b []model.RoleID) bool { return len(a) == len(b) && (len(a) == 0 || cmp.Equal(a, b)) })); diff != "" {
		t.Errorf("Current (-want +got):\n%s", diff)
	}
	wantWarn := []string{
		"earlier",
		`role "evil\n": its name contains control characters, so dbfence does not manage it`,
		`role "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx": its name is 64 bytes long`,
		`database "d\x1b": its name contains control characters`,
		`database "gone\x00": its name contains control characters`,
		`schema "s\u0085" in database "app": its name contains control characters`,
	}
	if len(warnings) != len(wantWarn) {
		t.Fatalf("warnings = %q, want %d", warnings, len(wantWarn))
	}
	for i, w := range wantWarn {
		if !strings.HasPrefix(warnings[i], w) {
			t.Errorf("warning %d = %q, want prefix %q", i, warnings[i], w)
		}
		if strings.ContainsFunc(warnings[i], model.IsControl) {
			t.Errorf("warning %d contains a raw control character: %q", i, warnings[i])
		}
	}
	if !u.Roles[bad] || !u.Databases["d\x1b"] || !u.Schemas[[2]string{"app", "s\u0085"}] || u.Roles[app] {
		t.Errorf("Untrusted = %+v", u)
	}
}

func TestDropUntrustedMySQLAccount(t *testing.T) {
	t.Parallel()
	cur := &model.Current{
		CurrentUser: model.RoleID{Name: "root", Host: "%"},
		Roles:       []model.RoleState{{ID: model.RoleID{Name: "root", Host: "%"}}, {ID: model.RoleID{Name: "u", Host: "h\r"}}, {ID: model.RoleID{Name: "", Host: "localhost"}}},
		Privileges: []model.Privilege{
			{Grantee: model.RoleID{Name: "a", Host: "%"}, Object: model.Object{Type: model.ObjectDatabase, Database: "x_y", Pattern: "x\\_y" + strings.Repeat("z", 64)}, Name: "SELECT"},
		},
	}
	if _, err := cur.DropUntrusted(model.EngineMySQL); err != nil {
		t.Fatal(err)
	}
	if len(cur.Roles) != 2 || cur.Roles[1].ID.Host != "localhost" || len(cur.Privileges) != 0 {
		t.Errorf("Current = %+v", cur)
	}
	if len(cur.Warnings) != 2 || !strings.HasPrefix(cur.Warnings[0], `account "u"@"h\r": its host contains control characters`) {
		t.Errorf("warnings = %q", cur.Warnings)
	}
}

func TestDropUntrustedCurrentUser(t *testing.T) {
	t.Parallel()
	cur := &model.Current{CurrentUser: model.RoleID{Name: "me\x1b"}}
	if _, err := cur.DropUntrusted(model.EnginePostgres); !errors.Is(err, model.ErrUntrustedCurrentUser) {
		t.Errorf("err = %v", err)
	}
}

func TestDropUntrustedEntangled(t *testing.T) {
	t.Parallel()
	bad := "bad\x01"
	db := func(name string) model.Object { return model.Object{Type: model.ObjectDatabase, Database: name} }
	sch := func(d, name string) model.Object { return model.Object{Type: model.ObjectSchema, Database: d, Schema: name} }
	tests := []struct {
		want   map[model.Object]string
		name   string
		engine model.Engine
		cur    model.Current
	}{
		{
			name:   "trusted owners and grantees",
			engine: model.EnginePostgres,
			cur: model.Current{
				Databases:    []model.Database{{Name: "d", Owner: "o"}},
				Schemas:      []model.Schema{{Database: "d", Name: "s", Owner: "o"}},
				OtherSchemas: []model.Schema{{Database: "e", Name: "t", Owner: "o"}},
				Privileges:   []model.Privilege{{Grantee: model.RoleID{Name: "o"}, Object: db("d"), Name: "CONNECT"}},
			},
		},
		{
			name:   "database owned by an untrusted role",
			engine: model.EnginePostgres,
			cur:    model.Current{Databases: []model.Database{{Name: "d", Owner: bad}}},
			want:   map[model.Object]string{db("d"): `it is owned by role "bad\x01", which dbfence does not manage`},
		},
		{
			name:   "database containing a schema with an untrusted name",
			engine: model.EnginePostgres,
			cur:    model.Current{OtherSchemas: []model.Schema{{Database: "d", Name: "s\x01", Owner: "o"}}},
			want:   map[model.Object]string{db("d"): `it contains schema "s\x01", which dbfence does not manage`},
		},
		{
			name:   "schema owned by an untrusted role",
			engine: model.EnginePostgres,
			cur: model.Current{
				Schemas:      []model.Schema{{Database: "d", Name: "s", Owner: bad}},
				OtherSchemas: []model.Schema{{Database: "e", Name: "t", Owner: bad}},
			},
			want: map[model.Object]string{
				sch("d", "s"): `it is owned by role "bad\x01", which dbfence does not manage`,
				db("d"):       `its schema "s" is owned by role "bad\x01", which dbfence does not manage`,
				sch("e", "t"): `it is owned by role "bad\x01", which dbfence does not manage`,
				db("e"):       `its schema "t" is owned by role "bad\x01", which dbfence does not manage`,
			},
		},
		{
			name:   "privileges granted to an untrusted role",
			engine: model.EnginePostgres,
			cur: model.Current{Privileges: []model.Privilege{
				{Grantee: model.RoleID{Name: bad}, Object: db("d"), Name: "CONNECT"},
				{Grantee: model.RoleID{Name: bad}, Object: sch("e", "s"), Name: "USAGE"},
			}},
			want: map[model.Object]string{
				db("d"):       `it grants CONNECT to role "bad\x01", which dbfence does not manage`,
				sch("e", "s"): `it grants USAGE to role "bad\x01", which dbfence does not manage`,
				db("e"):       `its schema "s" grants USAGE to role "bad\x01", which dbfence does not manage`,
			},
		},
		{
			name:   "first reason is kept",
			engine: model.EnginePostgres,
			cur: model.Current{
				Databases:  []model.Database{{Name: "d", Owner: bad}},
				Privileges: []model.Privilege{{Grantee: model.RoleID{Name: bad}, Object: db("d"), Name: "CONNECT"}},
			},
			want: map[model.Object]string{db("d"): `it is owned by role "bad\x01", which dbfence does not manage`},
		},
		{
			name:   "untrusted databases and schemas are dropped, not entangled",
			engine: model.EnginePostgres,
			cur: model.Current{
				Databases:  []model.Database{{Name: "d\x01", Owner: bad}},
				Schemas:    []model.Schema{{Database: "d\x01", Name: "s", Owner: bad}},
				Privileges: []model.Privilege{{Grantee: model.RoleID{Name: bad}, Object: sch("e", "s\x01"), Name: "USAGE"}},
			},
		},
		{
			name:   "MySQL keeps the grants of a dropped database",
			engine: model.EngineMySQL,
			cur: model.Current{Privileges: []model.Privilege{
				{Grantee: model.RoleID{Name: bad, Host: "%"}, Object: db("d"), Name: "SELECT"},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cur := tt.cur
			if _, err := cur.DropUntrusted(tt.engine); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, cur.Entangled, cmp.Comparer(func(a, b map[model.Object]string) bool {
				return len(a) == len(b) && (len(a) == 0 || cmp.Equal(a, b))
			})); diff != "" {
				t.Errorf("Entangled (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDropUntrustedShortensLongNames(t *testing.T) {
	t.Parallel()
	cur := &model.Current{Databases: []model.Database{{Name: strings.Repeat("é", 1000)}}}
	if _, err := cur.DropUntrusted(model.EnginePostgres); err != nil {
		t.Fatal(err)
	}
	if len(cur.Warnings) != 1 || len(cur.Warnings[0]) > 400 || !strings.Contains(cur.Warnings[0], `é"...`) {
		t.Errorf("warnings = %q", cur.Warnings)
	}
}

// FuzzCompileIgnorePattern checks that a compiled ignore pattern only
// ever matches whole names.
func FuzzCompileIgnorePattern(f *testing.F) {
	for _, s := range [][2]string{
		{"tmp_.*", "tmp_1"}, {"a)|(b", "a"}, {"a|b", "ab"}, {`app\..*`, "app.x"},
		{"(?i)ADMIN", "admin"}, {"x*", "x\ny"}, {"(?m)^a$", "a\nb"}, {"", ""}, {`\z`, "z"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pattern, name string) {
		if len(pattern) > 256 {
			t.Skip()
		}
		re, err := model.CompileIgnorePattern(pattern)
		if err != nil {
			return
		}
		if loc := re.FindStringIndex(name); loc != nil && (loc[0] != 0 || loc[1] != len(name)) {
			t.Errorf("pattern %q matches %q at %v, not the whole name", pattern, name, loc)
		}
	})
}
