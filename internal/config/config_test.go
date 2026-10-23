package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mazrean/dbfence/internal/funcs"
	"github.com/mazrean/dbfence/internal/model"
)

func load(t *testing.T, src string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dbfence.hcl")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"DSN": "postgres://localhost/postgres", "PW": "secret"}
	r := funcs.NewRegistry(t.Context(), funcs.WithEnv(func(k string) (string, bool) { v, ok := env[k]; return v, ok }))
	return Load(path, r.Functions())
}

func TestLoadPostgres(t *testing.T) {
	t.Parallel()
	cfg, err := load(t, `
connection {
  engine = "postgres"
  dsn    = env("DSN")
}
role "owner" {}
user "app" {
  password  = env("PW")
  member_of = [role.owner.name]
  createdb  = true
}
database "app" {
  owner = role.owner.name
}
schema "api" {
  database = database.app.name
  owner    = role.owner.name
}
grant {
  role       = user.app.name
  database   = schema.api.database
  schema     = schema.api.name
  privileges = ["usage", "ALL"]
}
grant {
  role       = user.app.name
  database   = database.app.name
  privileges = ["connect", "temp"]
  with_grant_option = true
}
ignore {
  roles   = ["datadog"]
  schemas = ["vendor", "app\\.audit"]
}
`)
	if err != nil {
		t.Fatal(err)
	}
	want := &model.Desired{
		Engine:    model.EnginePostgres,
		Databases: []model.Database{{Name: "app", Owner: "owner"}},
		Roles: []model.Role{
			{ID: model.RoleID{Name: "owner"}, Login: new(false)},
			{ID: model.RoleID{Name: "app"}, Login: new(true), Password: new("secret"), CreateDB: new(true), MemberOf: []model.RoleID{{Name: "owner"}}},
		},
		Schemas: []model.Schema{{Database: "app", Name: "api", Owner: "owner"}},
		Privileges: []model.Privilege{
			{Grantee: model.RoleID{Name: "app"}, Object: model.Object{Type: model.ObjectSchema, Database: "app", Schema: "api"}, Name: "CREATE"},
			{Grantee: model.RoleID{Name: "app"}, Object: model.Object{Type: model.ObjectSchema, Database: "app", Schema: "api"}, Name: "USAGE"},
			{Grantee: model.RoleID{Name: "app"}, Object: model.Object{Type: model.ObjectDatabase, Database: "app"}, Name: "CONNECT", GrantOption: true},
			{Grantee: model.RoleID{Name: "app"}, Object: model.Object{Type: model.ObjectDatabase, Database: "app"}, Name: "TEMPORARY", GrantOption: true},
		},
		Ignore: model.Ignore{Roles: []string{"datadog"}, Schemas: []string{"vendor", `app\.audit`}},
	}
	if cfg.DSN != "postgres://localhost/postgres" {
		t.Errorf("DSN = %q", cfg.DSN)
	}
	if diff := cmp.Diff(want, cfg.Desired); diff != "" {
		t.Errorf("Desired mismatch (-want +got):\n%s", diff)
	}
}

func TestLoadMySQL(t *testing.T) {
	t.Parallel()
	cfg, err := load(t, `
connection {
  engine = "mysql"
  dsn    = "root@tcp(localhost)/"
}
role "reader" {}
user "app_local" {
  name        = "app"
  host        = "localhost"
  auth_plugin = "caching_sha2_password"
  member_of   = [role.reader.id, "other@10.0.0.1"]
}
database "app" {
  charset = "utf8mb4"
}
grant {
  role       = user.app_local.id
  database   = database.app.name
  privileges = ["select", "insert"]
}
`)
	if err != nil {
		t.Fatal(err)
	}
	app := model.RoleID{Name: "app", Host: "localhost"}
	want := &model.Desired{
		Engine:    model.EngineMySQL,
		Databases: []model.Database{{Name: "app", Charset: "utf8mb4"}},
		Roles: []model.Role{
			{ID: model.RoleID{Name: "reader", Host: "%"}, Login: new(false)},
			{ID: app, Login: new(true), AuthPlugin: "caching_sha2_password", MemberOf: []model.RoleID{{Name: "other", Host: "10.0.0.1"}, {Name: "reader", Host: "%"}}},
		},
		Privileges: []model.Privilege{
			{Grantee: app, Object: model.Object{Type: model.ObjectDatabase, Database: "app"}, Name: "INSERT"},
			{Grantee: app, Object: model.Object{Type: model.ObjectDatabase, Database: "app"}, Name: "SELECT"},
		},
	}
	if diff := cmp.Diff(want, cfg.Desired); diff != "" {
		t.Errorf("Desired mismatch (-want +got):\n%s", diff)
	}
}

func TestLoadErrors(t *testing.T) {
	t.Parallel()
	const pg = "connection {\n engine = \"postgres\"\n dsn = \"x\"\n}\n"
	const my = "connection {\n engine = \"mysql\"\n dsn = \"x\"\n}\n"
	tests := []struct {
		name, src, want string
	}{
		{"missing connection", `role "a" {}`, "Missing connection block"},
		{"bad engine", "connection {\n engine = \"sqlite\"\n dsn = \"x\"\n}", "Unsupported engine"},
		{"duplicate connection", pg + pg, "Duplicate connection block"},
		{"unset env", "connection {\n engine = \"postgres\"\n dsn = env(\"NOPE\")\n}", `"NOPE" is not set`},
		{"env default", pg + `role "a" { password = env("NOPE", 1, 2) }`, "at most one default"},
		{"pg only attr on mysql", my + `role "a" { superuser = true }`, `"superuser" is only supported for postgres`},
		{"mysql only attr on pg", pg + `database "a" { charset = "utf8" }`, `"charset" is only supported for mysql`},
		{"host on pg", pg + `user "a" { host = "%" }`, `"host" is only supported for mysql`},
		{"schema on mysql", my + `database "d" {}` + "\n" + `schema "s" { database = "d" }`, "only supported for postgres"},
		{"duplicate label", pg + `role "a" {}` + "\n" + `user "a" {}`, "Duplicate label"},
		{"duplicate name", pg + `role "a" {}` + "\n" + `role "b" { name = "a" }`, "declared more than once"},
		{"unknown reference", pg + `database "d" { owner = role.nope.name }`, "Unsupported attribute"},
		{"undeclared schema db", pg + `schema "s" { database = "d" }`, "not declared"},
		{"grant undeclared role", pg + `database "d" {}` + "\n" + "grant {\nrole = \"x\"\ndatabase = \"d\"\nprivileges = [\"CONNECT\"]\n}", `role "x", which is not declared`},
		{"invalid privilege", pg + `role "r" {}` + "\n" + `database "d" {}` + "\n" + "grant {\nrole = \"r\"\ndatabase = \"d\"\nprivileges = [\"SELECT\"]\n}", `privilege "SELECT" is not valid`},
		{"empty privileges", pg + `role "r" {}` + "\n" + `database "d" {}` + "\n" + "grant {\nrole = \"r\"\ndatabase = \"d\"\nprivileges = []\n}", "privileges must not be empty"},
		{"duplicate privilege", pg + `role "r" {}` + "\n" + `database "d" {}` + "\n" + "grant {\nrole = \"r\"\ndatabase = \"d\"\nprivileges = [\"CONNECT\"]\n}" + "\n" + "grant {\nrole = \"r\"\ndatabase = \"d\"\nprivileges = [\"ALL\"]\n}", "already granted"},
		{"bad ignore regexp", pg + `ignore { roles = ["("] }`, "Invalid ignore pattern"},
		{"unknown block", pg + `table "t" {}`, "Unsupported block type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := load(t, tt.src)
			if err == nil {
				t.Fatalf("Load() succeeded, want error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Load() error = %v\nwant substring %q", err, tt.want)
			}
		})
	}
}

func TestLoadDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	files := map[string]string{
		"a.hcl": "connection {\n engine = \"postgres\"\n dsn = \"x\"\n}",
		"b.hcl": `role "r" {}`,
		"c.txt": `garbage`,
	}
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := Load(dir, funcs.NewRegistry(t.Context()).Functions())
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Desired.Roles) != 1 {
		t.Errorf("roles = %v, want 1", cfg.Desired.Roles)
	}
	if _, err := Load(t.TempDir(), nil); err == nil {
		t.Error("Load(empty dir) succeeded")
	}
}

func TestExpandPrivileges(t *testing.T) {
	t.Parallel()
	got, err := ExpandPrivileges(model.EngineMySQL, model.ObjectDatabase, []string{"all privileges"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(privileges[model.EngineMySQL][model.ObjectDatabase]) {
		t.Errorf("ALL expanded to %v", got)
	}
	got, err = ExpandPrivileges(model.EngineMySQL, model.ObjectDatabase, []string{"create   temporary tables", "Select"})
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff([]string{"CREATE TEMPORARY TABLES", "SELECT"}, got); diff != "" {
		t.Error(diff)
	}
}

func TestLoadDirectoryEntries(t *testing.T) {
	t.Parallel()
	conn := "connection {\n engine = \"postgres\"\n dsn = \"x\"\n}"
	tests := []struct {
		setup func(t *testing.T, dir string)
		name  string
		roles int
	}{
		{
			name:  "glob metacharacters in directory name",
			setup: func(t *testing.T, dir string) { write(t, filepath.Join(dir, "a.hcl"), conn+"\nrole \"r\" {}") },
			roles: 1,
		},
		{
			name: "subdirectory named *.hcl is skipped",
			setup: func(t *testing.T, dir string) {
				write(t, filepath.Join(dir, "a.hcl"), conn)
				if err := os.Mkdir(filepath.Join(dir, "old.hcl"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink to a file counts",
			setup: func(t *testing.T, dir string) {
				write(t, filepath.Join(dir, "a.hcl"), conn)
				target := filepath.Join(t.TempDir(), "roles.txt")
				write(t, target, `role "r" {}`)
				if err := os.Symlink(target, filepath.Join(dir, "b.hcl")); err != nil {
					t.Fatal(err)
				}
			},
			roles: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := filepath.Join(t.TempDir(), "g[1]*?")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			tt.setup(t, dir)
			cfg, err := Load(dir, funcs.NewRegistry(t.Context()).Functions())
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.Desired.Roles) != tt.roles {
				t.Errorf("roles = %v, want %d", cfg.Desired.Roles, tt.roles)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	t.Parallel()
	_, err := Load(filepath.Join(t.TempDir(), "dbfence.hcl"), nil)
	if err == nil || !strings.Contains(err.Error(), "not found (use -f/--file or DBFENCE_FILE)") {
		t.Errorf("Load(missing) error = %v", err)
	}
}

// TestLoadDiagnosticOutput checks the rendered error: no "Error:" header on
// the first diagnostic (the CLI adds it) and no cascaded diagnostics.
func TestLoadDiagnosticOutput(t *testing.T) {
	t.Parallel()
	const pg = "connection {\n engine = \"postgres\"\n dsn = \"x\"\n}\n"
	tests := []struct {
		name, src, prefix string
		count             int
	}{
		{"unset env", "connection {\n engine = \"postgres\"\n dsn = env(\"NOPE\")\n}", "Invalid function argument", 1},
		{"unknown reference", pg + `database "d" { owner = role.nope.name }`, "Unsupported attribute", 1},
		{
			"two unknown references",
			pg + "role \"r\" {}\ngrant {\n role = role.nope.id\n database = databse.app.name\n privileges = [\"CONNECT\"]\n}",
			"Unsupported attribute", 2,
		},
		{"password env", pg + `user "u" { password = env("NOPE") }`, "Invalid function argument", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := load(t, tt.src)
			if err == nil {
				t.Fatal("Load() succeeded")
			}
			msg := err.Error()
			if !strings.HasPrefix(msg, tt.prefix) {
				t.Errorf("error does not start with %q:\n%s", tt.prefix, msg)
			}
			if got := 1 + strings.Count(msg, "Error: "); got != tt.count {
				t.Errorf("%d diagnostics, want %d:\n%s", got, tt.count, msg)
			}
			if strings.Contains(msg, "value must be known") {
				t.Errorf("cascaded diagnostic in:\n%s", msg)
			}
		})
	}
}

func write(t *testing.T, path, src string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadResolvesTFStateRelativeToConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	state := `{"version": 4, "serial": 1, "lineage": "x", "outputs": {"db_host": {"value": "db.internal", "type": "string"}}, "resources": []}`
	cfgSrc := `connection {
  engine = "postgres"
  dsn    = "postgres://u@${tfstate("terraform.tfstate", "output.db_host")}/x"
}
`
	if err := os.WriteFile(filepath.Join(dir, "terraform.tfstate"), []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dbfence.hcl"), []byte(cfgSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		path string
	}{
		{"file", filepath.Join(dir, "dbfence.hcl")},
		{"directory", dir},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := Load(tt.path, funcs.NewRegistry(t.Context()).Functions())
			if err != nil {
				t.Fatal(err)
			}
			if want := "postgres://u@db.internal/x"; cfg.DSN != want {
				t.Errorf("DSN = %q, want %q", cfg.DSN, want)
			}
		})
	}
}
