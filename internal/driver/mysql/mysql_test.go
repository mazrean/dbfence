package mysql

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
)

var (
	app    = model.RoleID{Name: "app", Host: "%"}
	reader = model.RoleID{Name: "reader", Host: "%"}
)

func dbObj(name string) model.Object { return model.Object{Type: model.ObjectDatabase, Database: name} }

// first drops the warnings returned with stmts.
func first(stmts []plan.Statement, _ []string) []plan.Statement { return stmts }

func sqls(stmts []plan.Statement) []string {
	var out []string
	for _, s := range stmts {
		out = append(out, s.Display(false))
	}
	return out
}

func planSQL(t *testing.T, desired *model.Desired, cur *model.Current, d Dialect) ([]string, []string) {
	t.Helper()
	p, err := diff.Compute(desired, cur, d, diff.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return sqls(p.Statements()), p.Warnings
}

func TestGrantTarget(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		obj  model.Object
		want string
		d    Dialect
	}{
		{name: "plain", obj: dbObj("app"), want: "GRANT SELECT ON `app`.* TO 'app'@'%'"},
		{name: "wildcards are escaped", obj: dbObj(`my_app%\x`), want: "GRANT SELECT ON `my\\_app\\%\\\\x`.* TO 'app'@'%'"},
		{name: "backtick", obj: dbObj("a`b_c"), want: "GRANT SELECT ON `a``b\\_c`.* TO 'app'@'%'"},
		{name: "partial revokes", d: Dialect{PartialRevokes: true}, obj: dbObj("my_app"), want: "GRANT SELECT ON `my_app`.* TO 'app'@'%'"},
		{name: "pattern verbatim", obj: model.Object{Type: model.ObjectDatabase, Database: "my_app", Pattern: "my_app"}, want: "GRANT SELECT ON `my_app`.* TO 'app'@'%'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sqls(tt.d.Grant(app, tt.obj, []string{"SELECT"}, false)); got[0] != tt.want {
				t.Errorf("Grant = %s, want %s", got[0], tt.want)
			}
			wantRevoke := strings.Replace(strings.Replace(tt.want, "GRANT", "REVOKE", 1), " TO ", " FROM ", 1)
			if got := sqls(first(tt.d.Revoke(app, tt.obj, []string{"SELECT"}))); got[0] != wantRevoke {
				t.Errorf("Revoke = %s, want %s", got[0], wantRevoke)
			}
		})
	}
}

func TestDBObject(t *testing.T) {
	t.Parallel()
	tests := []struct {
		raw  string
		want model.Object
		d    Dialect
	}{
		{raw: "app", want: dbObj("app")},
		{raw: `my\_app`, want: dbObj("my_app")},
		{raw: `a\%b\\c`, want: dbObj(`a%b\c`)},
		{raw: "my_app", want: model.Object{Type: model.ObjectDatabase, Database: "my_app", Pattern: "my_app"}},
		{raw: `my\_%`, want: model.Object{Type: model.ObjectDatabase, Database: "my_%", Pattern: `my\_%`}},
		{raw: "my_app", d: Dialect{PartialRevokes: true}, want: dbObj("my_app")},
		{raw: `my\_app`, d: Dialect{PartialRevokes: true}, want: dbObj(`my\_app`)},
	}
	for _, tt := range tests {
		if got := tt.d.dbObject(tt.raw); got != tt.want {
			t.Errorf("dbObject(%q, partial=%v) = %+v, want %+v", tt.raw, tt.d.PartialRevokes, got, tt.want)
		}
	}
}

func TestMatchPattern(t *testing.T) {
	t.Parallel()
	tests := []struct {
		pattern, name string
		want          bool
	}{
		{"my_app", "my_app", true},
		{"my_app", "myXapp", true},
		{"my_app", "myapp", false},
		{`my\_app`, "myXapp", false},
		{`my\_app`, "my_app", true},
		{`dbf\_%`, "dbf_it_app", true},
		{`dbf\_%`, "dbfXit", false},
		{"%", "", true},
		{"a%b", "ab", true},
		{"a%b", "axxb", true},
		{"a%b", "axxc", false},
		{"_", "é", true},
	}
	for _, tt := range tests {
		if got := matchPattern(tt.pattern, tt.name); got != tt.want {
			t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
		}
	}
}

func TestDBPrivilegesPatterns(t *testing.T) {
	t.Parallel()
	desired := &model.Desired{
		Engine:     model.EngineMySQL,
		Roles:      []model.Role{{ID: app}},
		Databases:  []model.Database{{Name: "my_app"}},
		Privileges: []model.Privilege{{Grantee: app, Object: dbObj("my_app"), Name: "SELECT"}},
	}
	tests := []struct {
		name      string
		rows      []dbGrant
		want      []string
		wantWarns []string
		d         Dialect
	}{
		{
			name: "stale escaped row under partial_revokes is replaced",
			d:    Dialect{PartialRevokes: true},
			rows: []dbGrant{{grantee: app, db: `my\_app`, privs: []string{"SELECT"}}},
			want: []string{"GRANT SELECT ON `my_app`.* TO 'app'@'%'", "REVOKE SELECT ON `my\\_app`.* FROM 'app'@'%'"},
		},
		{
			name: "literal row under partial_revokes is converged",
			d:    Dialect{PartialRevokes: true},
			rows: []dbGrant{{grantee: app, db: "my_app", privs: []string{"SELECT"}}},
		},
		{
			name: "escaped grant is converged",
			rows: []dbGrant{{grantee: app, db: `my\_app`, privs: []string{"SELECT"}}},
		},
		{
			name: "wildcard grant written by older versions is replaced",
			rows: []dbGrant{{grantee: app, db: "my_app", privs: []string{"SELECT"}}},
			want: []string{"GRANT SELECT ON `my\\_app`.* TO 'app'@'%'", "REVOKE SELECT ON `my_app`.* FROM 'app'@'%'"},
		},
		{
			name:      "other pattern covering a declared database is reported",
			rows:      []dbGrant{{grantee: app, db: `my\_%`, privs: []string{"DELETE"}}, {grantee: app, db: `my\_app`, privs: []string{"SELECT"}}},
			wantWarns: []string{`"app"@"%" holds privileges on the database pattern "my\\_%", which also matches declared database "my_app"`},
		},
		{
			name: "pattern of an undeclared role is ignored",
			rows: []dbGrant{{grantee: reader, db: `my\_%`, privs: []string{"DELETE"}}, {grantee: app, db: `my\_app`, privs: []string{"SELECT"}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			privs, warns := tt.d.dbPrivileges(tt.rows, desired)
			cur := &model.Current{
				CurrentUser: model.RoleID{Name: "root", Host: "%"},
				Roles:       []model.RoleState{{ID: app, Login: true}},
				Databases:   []model.Database{{Name: "my_app"}},
				Privileges:  privs,
				Warnings:    warns,
			}
			got, gotWarns := planSQL(t, desired, cur, tt.d)
			if d := cmp.Diff(tt.want, got); d != "" {
				t.Errorf("statements (-want +got):\n%s", d)
			}
			if len(gotWarns) != len(tt.wantWarns) {
				t.Fatalf("warnings = %q, want %q", gotWarns, tt.wantWarns)
			}
			for _, w := range tt.wantWarns {
				if !slices.ContainsFunc(gotWarns, func(g string) bool { return strings.Contains(g, w) }) {
					t.Errorf("missing warning %q in %q", w, gotWarns)
				}
			}
		})
	}
}

func TestDBPrivilegesGrantOption(t *testing.T) {
	t.Parallel()
	mixed := []model.Privilege{
		{Grantee: app, Object: dbObj("app"), Name: "SELECT", GrantOption: true},
		{Grantee: app, Object: dbObj("app"), Name: "INSERT"},
	}
	plain := []model.Privilege{
		{Grantee: app, Object: dbObj("app"), Name: "SELECT"},
		{Grantee: app, Object: dbObj("app"), Name: "INSERT"},
	}
	tests := []struct {
		name      string
		declared  []model.Privilege
		want      []string
		row       dbGrant
		wantWarns int
	}{
		{
			name:      "mixed declaration converges once the level has the option",
			declared:  mixed,
			row:       dbGrant{grantee: app, db: "app", privs: []string{"SELECT", "INSERT"}, grantOption: true},
			wantWarns: 1,
		},
		{
			name:      "mixed declaration grants the option once",
			declared:  mixed,
			row:       dbGrant{grantee: app, db: "app", privs: []string{"SELECT", "INSERT"}},
			want:      []string{"GRANT SELECT ON `app`.* TO 'app'@'%' WITH GRANT OPTION"},
			wantWarns: 1,
		},
		{
			name:     "undeclared option is revoked",
			declared: plain,
			row:      dbGrant{grantee: app, db: "app", privs: []string{"SELECT", "INSERT"}, grantOption: true},
			want:     []string{"REVOKE GRANT OPTION ON `app`.* FROM 'app'@'%'"},
		},
		{
			name: "option left after removing all privileges is revoked with them",
			row:  dbGrant{grantee: app, db: "app", privs: []string{"CREATE", "DROP"}, grantOption: true},
			want: []string{"REVOKE CREATE, DROP, GRANT OPTION ON `app`.* FROM 'app'@'%'"},
		},
		{
			name: "option without privileges is revoked",
			row:  dbGrant{grantee: app, db: "app", grantOption: true},
			want: []string{"REVOKE GRANT OPTION ON `app`.* FROM 'app'@'%'"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			desired := &model.Desired{
				Engine:     model.EngineMySQL,
				Roles:      []model.Role{{ID: app}},
				Databases:  []model.Database{{Name: "app"}},
				Privileges: tt.declared,
			}
			privs, warns := Dialect{}.dbPrivileges([]dbGrant{tt.row}, desired)
			cur := &model.Current{
				CurrentUser: model.RoleID{Name: "root", Host: "%"},
				Roles:       []model.RoleState{{ID: app, Login: true}},
				Databases:   []model.Database{{Name: "app"}},
				Privileges:  privs,
				Warnings:    warns,
			}
			got, gotWarns := planSQL(t, desired, cur, Dialect{})
			if d := cmp.Diff(tt.want, got); d != "" {
				t.Errorf("statements (-want +got):\n%s", d)
			}
			if len(gotWarns) != tt.wantWarns {
				t.Errorf("warnings = %q, want %d", gotWarns, tt.wantWarns)
			}
		})
	}
}
