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
			want:  []string{"Empty host", "dbfence.hcl line 6"},
			count: 1,
		},
		{
			name:  "empty host in member_of",
			src:   myConn + "role \"r\" {}\nuser \"u\" {\n  member_of = [\"r@\"]\n}\n",
			want:  []string{`member_of entry "r@" has an empty host`, "dbfence.hcl line 7"},
			count: 1,
		},
		{
			name:  "empty host in grant role",
			src:   myConn + "user \"u\" {}\ndatabase \"d\" {}\ngrant {\n  role = \"u@\"\n  database = database.d.name\n  privileges = [\"SELECT\"]\n}\n",
			want:  []string{`role "u@" has an empty host`, "dbfence.hcl line 8"},
			count: 1,
		},
	})
}
