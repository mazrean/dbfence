package config

import "testing"

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
