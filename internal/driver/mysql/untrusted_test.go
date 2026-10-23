package mysql

import (
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/model"
)

// TestUntrustedNamesAreNotManaged checks that accounts and databases
// whose names Inspect leaves out are neither revoked, dropped nor named,
// and that the default roles naming one are left alone.
func TestUntrustedNamesAreNotManaged(t *testing.T) {
	t.Parallel()
	root := model.RoleID{Name: "root", Host: "%"}
	bad := model.RoleID{Name: "evil", Host: "h\n"}
	long := model.RoleID{Name: strings.Repeat("u", 33), Host: "%"}
	grp := model.RoleID{Name: "grp", Host: "%"}
	desired := &model.Desired{
		Engine:    model.EngineMySQL,
		Databases: []model.Database{{Name: "app"}},
		Roles: []model.Role{
			{ID: app, MemberOf: []model.RoleID{grp}},
			{ID: grp},
		},
		Privileges: []model.Privilege{{Grantee: app, Object: dbObj("app"), Name: "SELECT"}},
	}
	cur := &model.Current{
		CurrentUser: root,
		Roles: []model.RoleState{
			{ID: root, Login: true},
			{ID: app, MemberOf: []model.RoleID{grp, bad}, MemberOptions: map[model.RoleID]model.MembershipState{grp: {}, bad: {}}, DefaultRoles: []model.RoleID{grp, bad}},
			{ID: grp},
			{ID: bad},
			{ID: long},
		},
		Databases: []model.Database{{Name: "app"}, {Name: "x\x1b[2J"}},
		Privileges: []model.Privilege{
			{Grantee: app, Object: dbObj("app"), Name: "SELECT"},
			{Grantee: app, Object: dbObj("x\x1b[2J"), Name: "SELECT"},
			{Grantee: bad, Object: dbObj("app"), Name: "SELECT"},
			{Grantee: app, Object: model.Object{Type: model.ObjectDatabase, Database: "p", Pattern: "p" + strings.Repeat("%", 64)}, Name: "SELECT"},
		},
	}
	d := &Driver{}
	if err := d.dropUntrusted(cur, desired); err != nil {
		t.Fatal(err)
	}
	for _, opts := range []diff.Options{{}, {Prune: true}} {
		p, err := compute(t, desired, cur, d, opts)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range p.Statements() {
			if strings.Contains(s.SQL(), "evil") || strings.Contains(s.SQL(), "x\x1b") || strings.Contains(s.SQL(), "uuu") || strings.Contains(s.SQL(), "%%%") {
				t.Errorf("prune %v: plan names an unmanaged object: %s", opts.Prune, s.SQL())
			}
			if strings.Contains(s.SQL(), "DEFAULT ROLE") {
				t.Errorf("prune %v: default roles naming an unmanaged account are set: %s", opts.Prune, s.SQL())
			}
		}
		warnings := strings.Join(p.Warnings, "\n")
		for _, w := range []string{
			`account "evil"@"h\n": its host contains control characters, so dbfence does not manage it`,
			`account "uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu"@"%": its name is 33 characters long`,
			`database "x\x1b[2J": its name contains control characters`,
			`database "p%%%%`,
			`default roles of "app"@"%" include an account dbfence does not manage`,
		} {
			if !strings.Contains(warnings, w) {
				t.Errorf("prune %v: warnings do not contain %q:\n%s", opts.Prune, w, warnings)
			}
		}
	}
}

func TestSetDefaultRolesWithoutUntrusted(t *testing.T) {
	t.Parallel()
	grp := model.RoleID{Name: "grp", Host: "%"}
	d := &Driver{}
	if err := d.dropUntrusted(&model.Current{CurrentUser: app, Roles: []model.RoleState{{ID: app}}}, nil); err != nil {
		t.Fatal(err)
	}
	stmts := d.SetDefaultRoles(model.Role{ID: app, MemberOf: []model.RoleID{grp}}, model.RoleState{ID: app})
	if len(stmts) != 1 || stmts[0].SQL() != "SET DEFAULT ROLE 'grp'@'%' TO 'app'@'%'" {
		t.Errorf("SetDefaultRoles = %v", sqls(stmts))
	}
}

func TestDropUntrustedCurrentUser(t *testing.T) {
	t.Parallel()
	d := &Driver{}
	err := d.dropUntrusted(&model.Current{CurrentUser: model.RoleID{Name: "me", Host: "\x7f"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "connected user") {
		t.Errorf("err = %v", err)
	}
}
