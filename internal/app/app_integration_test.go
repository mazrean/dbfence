package app_test

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/mazrean/dbfence/internal/app"
	"github.com/mazrean/dbfence/internal/funcs"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

// Integration tests start disposable MySQL and PostgreSQL servers with
// dockertest. They are skipped with -short, and when Docker is
// unavailable outside CI.

type harness struct {
	t      *testing.T
	engine model.Engine
	dsn    string
	db     *sql.DB
	dir    string
}

type container struct {
	dsn        func(hostPort string) string
	repository string
	tag        string
	port       string
	sqlDriver  string
	env        []string
}

var (
	postgresContainer = container{
		repository: "postgres", tag: "17",
		env:       []string{"POSTGRES_PASSWORD=postgres"},
		port:      "5432/tcp",
		sqlDriver: "pgx",
		dsn: func(hp string) string {
			return "postgres://postgres:postgres@" + hp + "/postgres?sslmode=disable"
		},
	}
	mysqlContainer = container{
		repository: "mysql", tag: "8.4",
		env:       []string{"MYSQL_ROOT_PASSWORD=root"},
		port:      "3306/tcp",
		sqlDriver: "mysql",
		dsn: func(hp string) string {
			return "root:root@tcp(" + hp + ")/"
		},
	}
)

func newHarness(t *testing.T, engine model.Engine, c container) *harness {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test")
	}
	pool, err := dockertest.NewPool("")
	if err == nil {
		err = pool.Client.Ping()
	}
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("docker is required in CI: %v", err)
		}
		t.Skipf("docker is unavailable: %v", err)
	}
	pool.MaxWait = 3 * time.Minute
	res, err := pool.RunWithOptions(&dockertest.RunOptions{Repository: c.repository, Tag: c.tag, Env: c.env},
		func(hc *docker.HostConfig) {
			hc.AutoRemove = true
			hc.RestartPolicy = docker.RestartPolicy{Name: "no"}
		})
	if err != nil {
		t.Fatalf("start %s:%s: %v", c.repository, c.tag, err)
	}
	t.Cleanup(func() { _ = pool.Purge(res) })
	_ = res.Expire(600)

	dsn := c.dsn(res.GetHostPort(c.port))
	db, err := sql.Open(c.sqlDriver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := pool.Retry(func() error { return db.PingContext(t.Context()) }); err != nil {
		t.Fatalf("%s did not become ready: %v", c.repository, err)
	}
	return &harness{t: t, engine: engine, dsn: dsn, db: db, dir: t.TempDir()}
}

func (h *harness) query(q string, args ...any) []string {
	h.t.Helper()
	rows, err := h.db.QueryContext(h.t.Context(), q, args...)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			h.t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func (h *harness) exec(q string) {
	h.t.Helper()
	if _, err := h.db.ExecContext(h.t.Context(), q); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
}

func (h *harness) write(body string) {
	h.t.Helper()
	src := fmt.Sprintf("connection {\n  engine = %q\n  dsn = env(\"DBFENCE_IT_DSN\")\n}\n%s", h.engine, body)
	if err := os.WriteFile(filepath.Join(h.dir, "dbfence.hcl"), []byte(src), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) app() (*app.App, *bytes.Buffer) {
	out := &bytes.Buffer{}
	env := func(k string) (string, bool) {
		if k == "DBFENCE_IT_DSN" {
			return h.dsn, true
		}
		return os.LookupEnv(k)
	}
	return app.New(funcs.NewRegistry(h.t.Context(), funcs.WithEnv(env)), app.NewOpener(),
		&app.IO{In: strings.NewReader(""), Out: out, Err: out}), out
}

func (h *harness) plan(o app.Options) (int, string) {
	h.t.Helper()
	a, out := h.app()
	o.Path = filepath.Join(h.dir, "dbfence.hcl")
	p, err := a.Plan(context.WithoutCancel(h.t.Context()), o)
	if err != nil {
		h.t.Fatalf("plan: %v\n%s", err, out)
	}
	return len(p.Statements()), out.String()
}

func (h *harness) apply(o app.Options) string {
	h.t.Helper()
	a, out := h.app()
	o.Path = filepath.Join(h.dir, "dbfence.hcl")
	o.AutoApprove = true
	if err := a.Apply(h.t.Context(), o); err != nil {
		h.t.Fatalf("apply: %v\n%s", err, out)
	}
	return out.String()
}

func (h *harness) assertConverged(o app.Options) {
	h.t.Helper()
	if n, out := h.plan(o); n != 0 {
		h.t.Fatalf("expected no changes after apply, got %d statements:\n%s", n, out)
	}
}

func TestPostgresIntegration(t *testing.T) {
	t.Parallel()
	h := newHarness(t, model.EnginePostgres, postgresContainer)
	config := func(pw string) string {
		return fmt.Sprintf(`
role "owner" { name = "dbf_it_owner" }
role "ro"    { name = "dbf_it_ro" }
user "app" {
  name      = "dbf_it_app"
  password  = %q
  member_of = [role.ro.name]
  connection_limit = 5
}
database "app" {
  name     = "dbf_it_app"
  owner    = role.owner.name
  encoding = "UTF8"
}
schema "api" {
  database = database.app.name
  owner    = role.owner.name
}
grant {
  role       = user.app.name
  database   = database.app.name
  privileges = ["CONNECT", "TEMPORARY"]
}
grant {
  role       = role.ro.name
  database   = schema.api.database
  schema     = schema.api.name
  privileges = ["USAGE"]
}
`, pw)
	}

	h.write(config("first'pw"))
	if n, out := h.plan(app.Options{}); n != 8 || !strings.Contains(out, "PASSWORD '<redacted>'") || strings.Contains(out, "first'pw") {
		t.Fatalf("initial plan: %d statements\n%s", n, out)
	}
	h.apply(app.Options{})
	h.assertConverged(app.Options{})

	// Password change is detected through the SCRAM verifier.
	h.write(config("second"))
	if n, out := h.plan(app.Options{}); n != 1 || !strings.Contains(out, `ALTER ROLE "dbf_it_app" WITH PASSWORD`) {
		t.Fatalf("password plan: %d\n%s", n, out)
	}
	h.apply(app.Options{})
	h.assertConverged(app.Options{})

	// Drift is reverted; unmanaged objects are reported, then pruned.
	h.exec("GRANT CREATE ON DATABASE dbf_it_app TO dbf_it_app")
	h.exec("ALTER ROLE dbf_it_app NOLOGIN CONNECTION LIMIT 1")
	h.exec("CREATE ROLE dbf_it_stray")
	h.exec("CREATE DATABASE dbf_it_legacy OWNER dbf_it_stray")
	n, out := h.plan(app.Options{})
	if n != 2 || !strings.Contains(out, `unmanaged role "dbf_it_stray"`) || !strings.Contains(out, `unmanaged database "dbf_it_legacy"`) {
		t.Fatalf("drift plan: %d\n%s", n, out)
	}
	h.apply(app.Options{Prune: true})
	h.assertConverged(app.Options{Prune: true})
	if got := h.query("SELECT rolname FROM pg_roles WHERE rolname = 'dbf_it_stray'"); len(got) != 0 {
		t.Errorf("stray role survived prune")
	}
}

func TestMySQLIntegration(t *testing.T) {
	t.Parallel()
	h := newHarness(t, model.EngineMySQL, mysqlContainer)

	h.write(mysqlConfig(`first'pw\`))
	h.apply(app.Options{})
	// Converging proves caching_sha2_password verification against a real server.
	h.assertConverged(app.Options{})
	// _ is escaped, so the grant does not cover look-alike databases.
	if got := h.query("SELECT DISTINCT Db FROM mysql.db WHERE User LIKE 'dbf\\_it\\_%'"); len(got) != 1 || got[0] != `dbf\_it\_app` {
		t.Errorf("granted database patterns = %q", got)
	}

	h.write(mysqlConfig("second"))
	if n, out := h.plan(app.Options{}); n != 1 || !strings.Contains(out, "ALTER USER 'dbf_it_app'@'%' IDENTIFIED WITH caching_sha2_password BY '<redacted>'") {
		t.Fatalf("password plan: %d\n%s", n, out)
	}
	h.apply(app.Options{})
	h.assertConverged(app.Options{})

	h.exec("GRANT DELETE ON dbf_it_app.* TO 'dbf_it_app'@'%'")
	h.exec("GRANT SELECT ON `dbf\\_it\\_app`.* TO 'dbf_it_ro'@'%' WITH GRANT OPTION")
	h.exec("SET DEFAULT ROLE NONE TO 'dbf_it_app'@'%'")
	h.exec("ALTER USER 'dbf_it_app'@'%' ACCOUNT LOCK")
	h.exec("CREATE USER 'dbf_it_stray'@'%'")
	h.exec("CREATE DATABASE dbf_it_legacy")
	n, out := h.plan(app.Options{})
	if n != 4 || !strings.Contains(out, "REVOKE GRANT OPTION ON `dbf\\_it\\_app`.*") ||
		!strings.Contains(out, "SET DEFAULT ROLE 'dbf_it_ro'@'%' TO 'dbf_it_app'@'%'") || !strings.Contains(out, `unmanaged role "dbf_it_stray"@"%"`) || !strings.Contains(out, `unmanaged database "dbf_it_legacy"`) {
		t.Fatalf("drift plan: %d\n%s", n, out)
	}
	h.apply(app.Options{Prune: true})
	h.assertConverged(app.Options{Prune: true})
}

func mysqlConfig(pw string) string {
	return fmt.Sprintf(`
role "ro" { name = "dbf_it_ro" }
user "app" {
  name        = "dbf_it_app"
  password    = %q
  auth_plugin = "caching_sha2_password"
  member_of   = [role.ro.id]
}
database "app" {
  name    = "dbf_it_app"
  charset = "utf8mb4"
}
grant {
  role       = user.app.id
  database   = database.app.name
  privileges = ["SELECT", "INSERT"]
}
grant {
  role       = role.ro.id
  database   = database.app.name
  privileges = ["SELECT"]
}
`, pw)
}

// TestMySQLWithoutSystemTableAccess runs dbfence as an account that may
// not read mysql.user, mysql.db or mysql.role_edges.
func TestMySQLWithoutSystemTableAccess(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// wantCreate is the statement creating the app account on the first plan.
		wantCreate string
		wantWarn   string
		// grants are extra grants for the dbfence account.
		grants []string
	}{
		{
			name:       "accounts listed via USER_ATTRIBUTES",
			grants:     []string{"GRANT SYSTEM_USER ON *.* TO 'dbf_limited'@'%'"},
			wantCreate: "CREATE USER 'dbf_it_app'@'%' IDENTIFIED WITH caching_sha2_password BY '<redacted>'",
			wantWarn:   "cannot read login state",
		},
		{
			name:       "accounts cannot be listed",
			wantCreate: "CREATE USER IF NOT EXISTS 'dbf_it_app'@'%' IDENTIFIED WITH caching_sha2_password BY '<redacted>'",
			wantWarn:   "cannot list roles",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, model.EngineMySQL, mysqlContainer)
			for _, q := range append([]string{
				"CREATE USER 'dbf_limited'@'%' IDENTIFIED BY 'limited'",
				"GRANT CREATE USER, ROLE_ADMIN ON *.* TO 'dbf_limited'@'%'",
				"GRANT ALL PRIVILEGES ON `dbf\\_it\\_%`.* TO 'dbf_limited'@'%' WITH GRANT OPTION",
			}, tt.grants...) {
				h.exec(q)
			}
			h.dsn = strings.Replace(h.dsn, "root:root@", "dbf_limited:limited@", 1)
			h.write(mysqlConfig("pw1"))

			_, out := h.plan(app.Options{})
			if !strings.Contains(out, tt.wantCreate) || !strings.Contains(out, tt.wantWarn) {
				t.Fatalf("first plan:\n%s", out)
			}
			h.apply(app.Options{})
			// Unknown state is re-asserted idempotently, so applying again must succeed.
			h.apply(app.Options{})
			// Created accounts do not make a partial account list look complete.
			if _, out := h.plan(app.Options{}); !strings.Contains(out, tt.wantWarn) {
				t.Errorf("plan after apply lacks %q:\n%s", tt.wantWarn, out)
			}

			if got := h.query("SELECT CONCAT(FROM_USER, '>', TO_USER) FROM mysql.role_edges WHERE TO_USER = 'dbf_it_app'"); len(got) != 1 || got[0] != "dbf_it_ro>dbf_it_app" {
				t.Errorf("role edges = %v", got)
			}
			if got := h.query("SELECT Db FROM mysql.db WHERE User = 'dbf_it_app' AND Select_priv = 'Y' AND Insert_priv = 'Y'"); len(got) != 1 {
				t.Errorf("privileges of dbf_it_app = %v", got)
			}
			appDB, err := sql.Open("mysql", strings.Replace(h.dsn, "dbf_limited:limited@", "dbf_it_app:pw1@", 1))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = appDB.Close() }()
			if err := appDB.PingContext(t.Context()); err != nil {
				t.Errorf("dbf_it_app cannot log in with the declared password: %v", err)
			}
		})
	}
}
