package config

import "testing"

func TestLoadMySQLHost(t *testing.T) {
	t.Parallel()
	cfg, err := load(t, myConn+`role "r" { host = "LocalHost" }
user "u" {
  name      = "casey"
  host      = "App.Example.COM"
  member_of = ["r@LOCALHOST"]
}
database "d" {}
grant {
  role       = "casey@APP.example.com"
  database   = database.d.name
  privileges = ["SELECT"]
}
`)
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Desired.Roles
	if r[0].ID.Host != "localhost" || r[1].ID.Host != "app.example.com" || r[1].MemberOf[0].Host != "localhost" {
		t.Errorf("hosts not lower-cased: %+v", r)
	}
	if g := cfg.Desired.Privileges[0].Grantee; g != r[1].ID {
		t.Errorf("grantee = %v, want %v", g, r[1].ID)
	}
}

func TestLoadMySQLEmptyHost(t *testing.T) {
	t.Parallel()
	runDiagCases(t, []diagCase{
		{
			name:  "empty host attribute",
			src:   myConn + "user \"u\" {\n  host = \"\"\n}\n",
			want:  []string{"Empty host", "dbfence.hcl line 7"},
			count: 1,
		},
		{
			name:  "empty host in member_of",
			src:   myConn + "role \"r\" {}\nuser \"u\" {\n  member_of = [\"r@\"]\n}\n",
			want:  []string{`member_of entry "r@" has an empty host`, "dbfence.hcl line 8"},
			count: 1,
		},
		{
			name:  "empty host in grant role",
			src:   myConn + "user \"u\" {}\ndatabase \"d\" {}\ngrant {\n  role = \"u@\"\n  database = database.d.name\n  privileges = [\"SELECT\"]\n}\n",
			want:  []string{`role "u@" has an empty host`, "dbfence.hcl line 9"},
			count: 1,
		},
	})
}

// TestLoadMySQLHostWithAt checks that a host containing "@" is rejected:
// ids are name@host split at the last "@", so .id would name another
// account.
func TestLoadMySQLHostWithAt(t *testing.T) {
	t.Parallel()
	runDiagCases(t, []diagCase{
		{
			name:  "role host in member_of",
			src:   myConn + "role \"ro\" {\n  host = \"a@b\"\n}\nuser \"u\" {\n  member_of = [role.ro.id]\n}\n",
			want:  []string{"Invalid host", `host must not contain "@"`, "dbfence.hcl line 7"},
			count: 1,
		},
		{
			name:  "user host in grant role",
			src:   myConn + "user \"u\" {\n  host = \"a@B\"\n}\ndatabase \"d\" {}\ngrant {\n  role       = user.u.id\n  database   = database.d.name\n  privileges = [\"SELECT\"]\n}\n",
			want:  []string{"Invalid host", `host must not contain "@"`, "dbfence.hcl line 7"},
			count: 1,
		},
		{
			name:  "host from a function",
			src:   myConn + "user \"u\" {\n  host = format(\"%s@%s\", \"a\", \"b\")\n}\n",
			want:  []string{"Invalid host", "dbfence.hcl line 7"},
			count: 1,
		},
	})
}
