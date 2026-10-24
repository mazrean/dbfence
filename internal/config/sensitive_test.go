package config

import (
	"strings"
	"testing"
)

// TestLoadSensitiveValues checks that values marked sensitive by the
// secret functions decode into every kind of attribute (gohcl cannot
// decode marked values), and that errors about them do not show them.
func TestLoadSensitiveValues(t *testing.T) {
	t.Parallel()
	cfg, err := load(t, `
connection {
  engine = "postgres"
  dsn    = "${secretenv("DSN")}?sslmode=disable"
}
role "owner" {
  name = lower(secretenv("PW"))
}
user "app" {
  password         = secretenv("PW")
  member_of        = [role.owner.name]
  connection_limit = length([secretenv("PW"), "x"])
}
database "app" {
  owner = role.owner.name
}
grant {
  role       = user.app.name
  database   = database.app.name
  privileges = [upper("connect"), secretenv("PRIV", "TEMPORARY")]
}
`)
	if err != nil {
		t.Fatal(err)
	}
	d := cfg.Desired
	if cfg.DSN != "postgres://localhost/postgres?sslmode=disable" || d.Roles[0].ID.Name != "secret" || *d.Roles[1].Password != "secret" ||
		*d.Roles[1].ConnectionLimit != 2 || d.Databases[0].Owner != "secret" || len(d.Privileges) != 2 {
		t.Errorf("decoded %+v / %+v", cfg.DSN, d)
	}

	_, err = load(t, pgConn+"user \"app\" {\n  connection_limit = tonumber(secretenv(\"PW\"))\n}\n")
	if err == nil || !strings.Contains(err.Error(), "the arguments include a secret value") || strings.Contains(err.Error(), "secret\"") {
		t.Errorf("err = %v, want the secret hidden", err)
	}
}

// TestLoadSensitiveReferences checks that block references keep the mark
// of a secret-derived name, host or database, so that errors about them
// do not show the secret ("secret" is the value of PW).
func TestLoadSensitiveReferences(t *testing.T) {
	t.Parallel()
	const hidden = "the arguments include a secret value"
	secretRole := "role \"r\" {\n  name = secretenv(\"PW\")\n}\n"
	runDiagCases(t, []diagCase{
		{
			name:  "direct",
			src:   pgConn + "user \"u\" {\n  connection_limit = tonumber(secretenv(\"PW\"))\n}\n",
			want:  []string{hidden},
			deny:  []string{`"secret`},
			count: 1,
		},
		{
			name:  "function on role name",
			src:   pgConn + secretRole + "user \"u\" {\n  connection_limit = tonumber(role.r.name)\n}\n",
			want:  []string{hidden},
			deny:  []string{`"secret`},
			count: 1,
		},
		{
			name:  "operator on role name",
			src:   pgConn + secretRole + "user \"u\" {\n  connection_limit = role.r.name + 1\n}\n",
			want:  []string{"Unsuitable value for left operand"},
			deny:  []string{`"secret`},
			count: 1,
		},
		{
			name:  "function on mysql id",
			src:   myConn + secretRole + "user \"u\" {\n  connection_limit = tonumber(role.r.id)\n}\n",
			want:  []string{hidden},
			deny:  []string{`"secret`},
			count: 1,
		},
		{
			name:  "function on mysql host",
			src:   myConn + "role \"r\" {\n  host = secretenv(\"PW\")\n}\nuser \"u\" {\n  connection_limit = tonumber(role.r.host)\n}\n",
			want:  []string{hidden},
			deny:  []string{`"secret`},
			count: 1,
		},
		{
			name:  "function on schema database",
			src:   pgConn + "database \"d\" {\n  name = secretenv(\"PW\")\n}\nschema \"s\" {\n  database = database.d.name\n}\nuser \"u\" {\n  connection_limit = tonumber(schema.s.database)\n}\n",
			want:  []string{hidden},
			deny:  []string{`"secret`},
			count: 1,
		},
	})
}

// TestLoadSensitiveDuplicateKey checks that the duplicate key error of a
// for expression shows the key only when it is not secret-derived.
func TestLoadSensitiveDuplicateKey(t *testing.T) {
	t.Parallel()
	runDiagCases(t, []diagCase{
		{
			name:  "plain key",
			src:   pgConn + "user \"u\" {\n  connection_limit = length({for x in [1, 2] : \"k\" => x})\n}\n",
			want:  []string{"Duplicate object key", `produced the key "k"`},
			count: 1,
		},
		{
			name:  "secret key",
			src:   pgConn + "user \"u\" {\n  connection_limit = length({for x in [1, 2] : secretenv(\"PW\") => x})\n}\n",
			want:  []string{"Duplicate object key", "produced the same key"},
			deny:  []string{"secret\""},
			count: 1,
		},
		{
			name:  "key from a secret element",
			src:   pgConn + "user \"u\" {\n  connection_limit = length({for k, v in {a = secretenv(\"PW\"), b = secretenv(\"PW\")} : v => k})\n}\n",
			want:  []string{"Duplicate object key", "produced the same key"},
			deny:  []string{"secret\""},
			count: 1,
		},
	})
}
