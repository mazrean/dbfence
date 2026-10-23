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
