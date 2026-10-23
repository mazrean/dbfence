package config

import (
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/mazrean/dbfence/internal/model"
)

func TestLoadMemberships(t *testing.T) {
	t.Parallel()
	runDiagCases(t, []diagCase{
		{
			name:  "self membership",
			src:   pgConn + "user \"u\" {\n  member_of = [user.u.id]\n}\n",
			want:  []string{"Membership cycle", `role "u" cannot be a member of itself`, "dbfence.hcl line 6"},
			count: 1,
		},
		{
			name:  "two-role cycle",
			src:   pgConn + "role \"a\" {\n  member_of = [role.b.id]\n}\nrole \"b\" {\n  member_of = [role.a.id]\n}\n",
			want:  []string{`role memberships form a cycle: "a" -> "b" -> "a"`, "dbfence.hcl line 9"},
			count: 1,
		},
		{
			name:  "three-role cycle on mysql",
			src:   myConn + "role \"a\" { member_of = [role.b.id] }\nrole \"b\" { member_of = [role.c.id] }\nrole \"c\" { member_of = [role.a.id] }\n",
			want:  []string{`"a@%" -> "b@%" -> "c@%" -> "a@%"`},
			count: 1,
		},
		{
			name:  "duplicate membership",
			src:   pgConn + "role \"a\" {}\nuser \"u\" {\n  member_of = [role.a.id, \"a\"]\n}\n",
			want:  []string{`member_of lists role "a" more than once`, "dbfence.hcl line 7"},
			count: 1,
		},
		{
			name:  "mysql host-less member_of misses the declared account",
			src:   myConn + "role \"ro\" { host = \"localhost\" }\nuser \"u\" {\n  member_of = [role.ro.name]\n}\n",
			want:  []string{`member_of entry "ro" resolves to "ro"@"%"`, `"ro"@"localhost" (role "ro")`, "role.<label>.id", "dbfence.hcl line 7"},
			count: 1,
		},
		{
			name:  "mysql grant role with another host",
			src:   myConn + "user \"u\" { host = \"localhost\" }\ndatabase \"d\" {}\ngrant {\n  role = user.u.name\n  database = database.d.name\n  privileges = [\"SELECT\"]\n}\n",
			want:  []string{`grant targets role "u"@"%"`, `"u"@"localhost" (user "u")`, "user.<label>.id"},
			count: 1,
		},
	})
}

func TestLoadMembershipsValid(t *testing.T) {
	t.Parallel()
	for _, src := range []string{
		// A diamond is not a cycle; undeclared parents stay allowed.
		pgConn + "role \"top\" {}\nrole \"l\" { member_of = [role.top.id] }\nrole \"r\" { member_of = [role.top.id] }\nuser \"u\" { member_of = [role.l.id, role.r.id, \"unmanaged\"] }\n",
		// An explicit host still targets an unmanaged account on purpose.
		myConn + "role \"ro\" { host = \"localhost\" }\nuser \"u\" { member_of = [role.ro.id, \"ro@%\", \"other\"] }\n",
	} {
		if _, err := load(t, src); err != nil {
			t.Errorf("Load() error = %v", err)
		}
	}
}

func TestLoadMembershipOptions(t *testing.T) {
	t.Parallel()
	yes, no := true, false
	tests := []struct {
		want    map[model.RoleID]model.MembershipOptions
		name    string
		src     string
		members []model.RoleID
	}{
		{
			name:    "string form manages no options",
			src:     pgConn + "role \"g\" {}\nuser \"u\" { member_of = [role.g.id] }\n",
			members: []model.RoleID{{Name: "g"}},
		},
		{
			name:    "object form on postgres",
			src:     pgConn + "role \"g\" {}\nrole \"h\" {}\nuser \"u\" {\n  member_of = [{ role = role.g.id, admin = true, inherit = false }, role.h.id, { role = \"x\", set = false }]\n}\n",
			members: []model.RoleID{{Name: "g"}, {Name: "h"}, {Name: "x"}},
			want: map[model.RoleID]model.MembershipOptions{
				{Name: "g"}: {Admin: &yes, Inherit: &no},
				{Name: "x"}: {Set: &no},
			},
		},
		{
			name:    "object without options is the string form",
			src:     pgConn + "role \"g\" {}\nuser \"u\" { member_of = [{ role = role.g.id, admin = null }] }\n",
			members: []model.RoleID{{Name: "g"}},
		},
		{
			name:    "admin on mysql",
			src:     myConn + "role \"g\" {}\nuser \"u\" { member_of = [{ role = role.g.id, admin = false }] }\n",
			members: []model.RoleID{{Name: "g", Host: "%"}},
			want:    map[model.RoleID]model.MembershipOptions{{Name: "g", Host: "%"}: {Admin: &no}},
		},
		{
			name: "empty list",
			src:  pgConn + "user \"u\" { member_of = [] }\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := load(t, tt.src)
			if err != nil {
				t.Fatal(err)
			}
			i := slices.IndexFunc(cfg.Desired.Roles, func(r model.Role) bool { return r.ID.Name == "u" })
			r := cfg.Desired.Roles[i]
			if d := cmp.Diff(tt.members, r.MemberOf, cmpopts.EquateEmpty()); d != "" {
				t.Errorf("MemberOf (-want +got):\n%s", d)
			}
			if d := cmp.Diff(tt.want, r.MemberOptions, cmpopts.EquateEmpty()); d != "" {
				t.Errorf("MemberOptions (-want +got):\n%s", d)
			}
		})
	}
}

func TestLoadMembershipOptionErrors(t *testing.T) {
	t.Parallel()
	runDiagCases(t, []diagCase{
		{
			name:  "inherit on mysql",
			src:   myConn + "role \"g\" {}\nuser \"u\" {\n  member_of = [{ role = role.g.id, inherit = false }]\n}\n",
			want:  []string{"Invalid member_of", `option inherit of role "g@%" is only supported for postgres`, "dbfence.hcl line 7"},
			count: 1,
		},
		{
			name:  "set on mysql",
			src:   myConn + "role \"g\" {}\nuser \"u\" { member_of = [{ role = role.g.id, set = true }] }\n",
			want:  []string{"option set of role", "only supported for postgres"},
			count: 1,
		},
		{
			name:  "unknown attribute",
			src:   pgConn + "role \"g\" {}\nuser \"u\" { member_of = [{ role = role.g.id, grant = true }] }\n",
			want:  []string{`unsupported attribute "grant"`, "role, admin, inherit, set"},
			count: 1,
		},
		{
			name:  "missing role",
			src:   pgConn + "user \"u\" { member_of = [{ admin = true }] }\n",
			want:  []string{"must set role to a role id"},
			count: 1,
		},
		{
			name:  "non-bool option",
			src:   pgConn + "user \"u\" { member_of = [{ role = \"g\", admin = \"maybe\" }] }\n",
			want:  []string{`member_of option admin of role "g" must be a bool`},
			count: 1,
		},
		{
			name:  "not a list",
			src:   pgConn + "user \"u\" { member_of = \"g\" }\n",
			want:  []string{"member_of must be a list"},
			count: 1,
		},
		{
			name:  "null entry",
			src:   pgConn + "user \"u\" { member_of = [null] }\n",
			want:  []string{"must not be null"},
			count: 1,
		},
		{
			name:  "duplicate across forms",
			src:   pgConn + "role \"g\" {}\nuser \"u\" { member_of = [role.g.id, { role = \"g\", admin = true }] }\n",
			want:  []string{`member_of lists role "g" more than once`},
			count: 1,
		},
		{
			name:  "self membership in object form",
			src:   pgConn + "user \"u\" { member_of = [{ role = user.u.id, admin = true }] }\n",
			want:  []string{`role "u" cannot be a member of itself`},
			count: 1,
		},
		{
			name:  "mysql empty host in object form",
			src:   myConn + "user \"u\" { member_of = [{ role = \"g@\" }] }\n",
			want:  []string{`member_of entry "g@" has an empty host`},
			count: 1,
		},
		{
			name:  "undefined reference",
			src:   pgConn + "user \"u\" { member_of = [{ role = role.nope.id }] }\n",
			want:  []string{"nope"},
			deny:  []string{"value must be known"},
			count: 1,
		},
	})
}
