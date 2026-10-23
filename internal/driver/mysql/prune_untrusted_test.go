package mysql

import (
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/model"
)

// TestPruneKeepsRolesOfUnmanagedAccounts checks that --prune keeps an
// account whose DROP USER would change an account or database dbfence
// does not manage, and says why.
func TestPruneKeepsRolesOfUnmanagedAccounts(t *testing.T) {
	t.Parallel()
	root := model.RoleID{Name: "root", Host: "%"}
	bad := model.RoleID{Name: "evil", Host: "h\n"}
	grp := model.RoleID{Name: "oldgrp", Host: "%"}
	tests := []struct {
		privileges []model.Privilege
		name       string
		grp, bad   model.RoleState
		dropped    bool
	}{
		{
			name: "default role of an unmanaged account",
			bad:  model.RoleState{DefaultRoles: []model.RoleID{grp}},
		},
		{
			name: "member of an unmanaged account",
			grp:  model.RoleState{MemberOf: []model.RoleID{bad}, MemberOptions: map[model.RoleID]model.MembershipState{bad: {}}},
		},
		{
			name: "unmanaged default role",
			grp:  model.RoleState{DefaultRoles: []model.RoleID{bad}},
		},
		{
			name:       "privilege on an unmanaged database",
			privileges: []model.Privilege{{Grantee: grp, Object: model.Object{Type: model.ObjectDatabase, Database: "db\x01"}, Name: "SELECT"}},
		},
		{
			name:       "privilege on an unmanaged pattern",
			privileges: []model.Privilege{{Grantee: grp, Object: model.Object{Type: model.ObjectDatabase, Pattern: "db\x01%"}, Name: "SELECT"}},
		},
		{
			name:       "nothing unmanaged",
			privileges: []model.Privilege{{Grantee: grp, Object: model.Object{Type: model.ObjectDatabase, Database: "app"}, Name: "SELECT"}},
			dropped:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.grp.ID, tt.bad.ID, tt.bad.Login = grp, bad, true
			desired := &model.Desired{Engine: model.EngineMySQL}
			cur := &model.Current{
				CurrentUser: root,
				Roles:       []model.RoleState{{ID: root, Login: true}, tt.grp, tt.bad},
				Privileges:  tt.privileges,
			}
			d := &Driver{}
			if err := d.dropUntrusted(cur, desired); err != nil {
				t.Fatal(err)
			}
			p, err := compute(t, desired, cur, d, diff.Options{Prune: true})
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Join(sqls(p.Statements()), "\n")
			if dropped := strings.Contains(got, "DROP USER 'oldgrp'@'%'"); dropped != tt.dropped {
				t.Errorf("DROP USER planned = %v, want %v:\n%s", dropped, tt.dropped, got)
			}
			const keep = "is granted to, has as a granted or default role, or holds privileges on an account or database that dbfence does not manage"
			if w := strings.Join(p.Warnings, "\n"); strings.Contains(w, keep) == tt.dropped {
				t.Errorf("warnings (want the keep reason: %v):\n%s", !tt.dropped, w)
			}
		})
	}
}

// TestPruneKeepsRoleOfUnmanagedAccount checks that --prune keeps a role
// granted to an account dbfence does not manage: MySQL's DROP ROLE would
// revoke it from that account (and its default roles).
func TestPruneKeepsRoleOfUnmanagedAccount(t *testing.T) {
	t.Parallel()
	root := model.RoleID{Name: "root", Host: "%"}
	bad := model.RoleID{Name: "evil", Host: "h\n"}
	grp := model.RoleID{Name: "oldgrp", Host: "%"}
	desired := &model.Desired{Engine: model.EngineMySQL}
	cur := &model.Current{
		CurrentUser: root,
		Roles: []model.RoleState{
			{ID: root, Login: true},
			{ID: grp},
			{ID: bad, Login: true, MemberOf: []model.RoleID{grp}, MemberOptions: map[model.RoleID]model.MembershipState{grp: {}}, DefaultRoles: []model.RoleID{grp}},
		},
	}
	d := &Driver{}
	if err := d.dropUntrusted(cur, desired); err != nil {
		t.Fatal(err)
	}
	p, err := compute(t, desired, cur, d, diff.Options{Prune: true})
	if err != nil {
		t.Fatal(err)
	}
	got := sqls(p.Statements())
	t.Logf("plan: %q\nwarnings:\n%s", got, strings.Join(p.Warnings, "\n"))
	if strings.Contains(strings.Join(got, "\n"), "DROP") {
		t.Errorf("prune drops %v, which is granted to (and a default role of) the unmanaged account %v", grp, bad)
	}
}
