package postgres

import (
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/policy"
)

// A role that granted the connected user, not a superuser, its CONNECT on
// the connected database, or (16+) a membership it relies on, is kept by
// --prune: DROP OWNED BY it would revoke those grants with CASCADE.
func TestPruneKeepsGrantorOfReliedGrants(t *testing.T) {
	t.Parallel()
	db := model.Object{Type: model.ObjectDatabase, Database: "postgres"}
	desired := &model.Desired{Engine: model.EnginePostgres,
		Databases: []model.Database{{Name: "postgres", Owner: "postgres"}}}
	connectCurrent := func(extra ...model.RoleState) *model.Current {
		return &model.Current{
			CurrentUser: pg("admin"), CurrentDatabase: "postgres",
			Roles: append([]model.RoleState{
				{ID: pg("admin"), Login: true, Inherit: true, CreateRole: true},
				{ID: pg("postgres"), Superuser: true, Login: true, Inherit: true},
			}, extra...),
			Databases: []model.Database{{Name: "postgres", Owner: "postgres"}},
		}
	}
	tests := []struct {
		cur       *model.Current
		st        *state
		name      string
		role      string
		superuser bool
		kept      bool
	}{
		{
			name: "grantor of the connected user's CONNECT", role: "d2", kept: true,
			cur: connectCurrent(model.RoleState{ID: pg("d2"), Inherit: true}),
			st: &state{
				roles: map[string]roleAccess{"d2": {admin: true, set: true, use: true}},
				acl: []aclEntry{
					{obj: db, grantee: "postgres", grantor: "postgres", priv: "CONNECT", grantable: true},
					{obj: db, grantee: "d2", grantor: "postgres", priv: "CONNECT", grantable: true},
					{obj: db, grantee: "admin", grantor: "d2", priv: "CONNECT"},
				},
			},
		},
		{
			name: "transitive grantor of the connected user's CONNECT", role: "d2", kept: true,
			cur: connectCurrent(model.RoleState{ID: pg("d2"), Inherit: true}, model.RoleState{ID: pg("mid"), Inherit: true}),
			st: &state{
				roles: map[string]roleAccess{"d2": {admin: true, set: true, use: true}, "mid": {admin: true, set: true, use: true}},
				acl: []aclEntry{
					{obj: db, grantee: "d2", grantor: "postgres", priv: "CONNECT", grantable: true},
					{obj: db, grantee: "mid", grantor: "d2", priv: "CONNECT", grantable: true},
					{obj: db, grantee: "admin", grantor: "mid", priv: "CONNECT"},
				},
			},
		},
		{
			name: "grantor of PUBLIC's CONNECT", role: "d2", kept: true,
			cur: connectCurrent(model.RoleState{ID: pg("d2"), Inherit: true}),
			st: &state{
				roles: map[string]roleAccess{"d2": {admin: true, set: true, use: true}},
				acl: []aclEntry{
					{obj: db, grantee: "d2", grantor: "postgres", priv: "CONNECT", grantable: true},
					{obj: db, grantee: "public", grantor: "d2", priv: "CONNECT"},
				},
			},
		},
		{
			name: "grantor of the connected user's CONNECT, superuser", role: "d2", superuser: true,
			cur: connectCurrent(model.RoleState{ID: pg("d2"), Inherit: true}),
			st: &state{
				roles: map[string]roleAccess{"d2": {admin: true, set: true, use: true}},
				acl: []aclEntry{
					{obj: db, grantee: "d2", grantor: "postgres", priv: "CONNECT", grantable: true},
					{obj: db, grantee: "admin", grantor: "d2", priv: "CONNECT"},
				},
			},
		},
		{
			name: "grantor of another role's CONNECT", role: "d2",
			cur: connectCurrent(model.RoleState{ID: pg("d2"), Inherit: true}, model.RoleState{ID: pg("other"), Inherit: true}),
			st: &state{
				roles: map[string]roleAccess{"d2": {admin: true, set: true, use: true}, "other": {admin: true, set: true, use: true}},
				acl: []aclEntry{
					{obj: db, grantee: "admin", grantor: "postgres", priv: "CONNECT"},
					{obj: db, grantee: "d2", grantor: "postgres", priv: "CONNECT", grantable: true},
					{obj: db, grantee: "other", grantor: "d2", priv: "CONNECT"},
				},
			},
		},
		{
			name: "grantor of the connected user's membership", role: "x", kept: true,
			cur: &model.Current{
				CurrentUser: pg("admin"), CurrentDatabase: "postgres",
				Roles: []model.RoleState{
					{ID: pg("admin"), Login: true, Inherit: true, CreateRole: true, MemberOf: []model.RoleID{pg("ops")},
						MemberOptions: map[model.RoleID]model.MembershipState{pg("ops"): {Admin: true, Inherit: true, Set: true}}},
					{ID: pg("x"), Inherit: true, MemberOf: []model.RoleID{pg("ops")},
						MemberOptions: map[model.RoleID]model.MembershipState{pg("ops"): {Admin: true, Inherit: true, Set: true}}},
					{ID: pg("ops"), Inherit: true},
					{ID: pg("postgres"), Superuser: true, Login: true, Inherit: true},
				},
				Databases: []model.Database{{Name: "postgres", Owner: "postgres"}},
			},
			st: &state{
				roles: map[string]roleAccess{"x": {admin: true, set: true, use: true}, "ops": {admin: true, use: true, set: true}},
				members: []memberEntry{
					{role: "ops", member: "x", grantor: "admin", admin: true, inherit: true, set: true},
					{role: "ops", member: "admin", grantor: "x", inherit: true, set: true},
					{role: "ops", member: "admin", grantor: "postgres", admin: true},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			st := tt.st
			st.desired, st.user, st.database, st.version, st.createRole = desired, "admin", "postgres", 170000, true
			st.superuser = tt.superuser
			st.connectable = map[string]bool{"postgres": true}
			st.owners = map[model.Object]string{db: "postgres"}
			if tt.superuser {
				tt.cur.Roles[0].Superuser = true
			}
			p, err := diff.Compute(desired, tt.cur, &Driver{st: st}, diff.Options{Prune: true})
			if err != nil {
				t.Fatal(err)
			}
			got := sqlOf(p.Statements())
			warns := strings.Join(p.Warnings, "\n")
			if v := policy.Verify(p, tt.cur, desired, policy.Options{System: Dialect{}, Prune: true}); len(v) > 0 {
				t.Errorf("Verify = %v\nplan:\n%s", v, got)
			}
			dropped := strings.Contains(got, `DROP OWNED BY "`+tt.role+`"`)
			if dropped == tt.kept {
				t.Errorf("dropped %q = %v, want %v\nplan:\n%s\nwarnings:\n%s", tt.role, dropped, !tt.kept, got, warns)
			}
			if tt.kept && !strings.Contains(warns, "granted, directly or through other roles, CONNECT") {
				t.Errorf("warnings do not say why %q is kept:\n%s", tt.role, warns)
			}
		})
	}
}
