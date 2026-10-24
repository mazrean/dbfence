package app_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	gomysql "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/mazrean/dbfence/internal/app"
	"github.com/mazrean/dbfence/internal/apply"
	"github.com/mazrean/dbfence/internal/driver/mysql"
	"github.com/mazrean/dbfence/internal/funcs"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
	"github.com/ory/dockertest/v4"
)

// Integration tests start disposable MySQL and PostgreSQL servers with
// dockertest. They are skipped with -short, and when Docker is
// unavailable outside CI.

// TestMain removes the containers even when a test hangs or the run is
// interrupted, and labels them so that a later run removes what a killed
// run left behind.
func TestMain(m *testing.M) {
	dockertest.TestMain(context.Background(), m)
}

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
	pool, err := dockertest.NewPool(t.Context(), "", dockertest.WithMaxWait(3*time.Minute))
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("docker is required in CI: %v", err)
		}
		t.Skipf("docker is unavailable: %v", err)
	}
	t.Cleanup(func() { _ = pool.Close(context.WithoutCancel(t.Context())) })
	// Tests change server-wide state, so each one gets its own server
	// instead of one reused per image.
	res, err := pool.Run(t.Context(), c.repository,
		dockertest.WithTag(c.tag), dockertest.WithEnv(c.env), dockertest.WithoutReuse())
	if err != nil {
		t.Fatalf("start %s:%s: %v", c.repository, c.tag, err)
	}

	dsn := c.dsn(res.GetHostPort(c.port))
	db, err := sql.Open(c.sqlDriver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := pool.Retry(t.Context(), 0, func() error { return db.PingContext(t.Context()) }); err != nil {
		stdout, stderr, _ := res.Logs(context.WithoutCancel(t.Context()))
		t.Fatalf("%s did not become ready: %v\nstdout:\n%s\nstderr:\n%s", c.repository, err, stdout, stderr)
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

	// Revoking a privilege PUBLIC still holds is warned about.
	h.write(strings.Replace(config("second"), `privileges = ["CONNECT", "TEMPORARY"]`, `privileges = ["TEMPORARY"]`, 1))
	if n, out := h.plan(app.Options{}); n != 1 || !strings.Contains(out, `"dbf_it_app" keeps CONNECT on database "dbf_it_app" through PUBLIC`) {
		t.Fatalf("revoke plan: %d\n%s", n, out)
	}

	// PUBLIC is managed where a grant block names it.
	h.write(config("second") + `
grant {
  role       = "PUBLIC"
  database   = database.app.name
  privileges = []
}
`)
	if n, out := h.plan(app.Options{}); n != 1 || !strings.Contains(out, `REVOKE CONNECT, TEMPORARY ON DATABASE "dbf_it_app" FROM PUBLIC`) {
		t.Fatalf("PUBLIC plan: %d\n%s", n, out)
	}
	h.apply(app.Options{})
	h.assertConverged(app.Options{})
	if got := h.query("SELECT has_database_privilege('dbf_it_ro', 'dbf_it_app', 'CONNECT')::text || has_database_privilege('dbf_it_app', 'dbf_it_app', 'CONNECT')::text"); len(got) != 1 || got[0] != "falsetrue" {
		t.Errorf("CONNECT of dbf_it_ro, dbf_it_app = %v, want falsetrue", got)
	}

	// Membership options in the object form of member_of.
	h.write(strings.Replace(config("second"), `member_of = [role.ro.name]`,
		"inherit = false\n  member_of = [{ role = role.ro.name, admin = true, inherit = true, set = false }]", 1))
	if n, out := h.plan(app.Options{}); n != 3 || !strings.Contains(out, `GRANT "dbf_it_ro" TO "dbf_it_app" WITH ADMIN TRUE, INHERIT TRUE, SET FALSE`) ||
		!strings.Contains(out, `declares inherit = true, but the role has inherit = false`) {
		t.Fatalf("membership options plan: %d\n%s", n, out)
	}
	h.apply(app.Options{})
	h.assertConverged(app.Options{})
	if got := h.query(`SELECT bool_or(admin_option)::text || bool_or(inherit_option)::text || bool_or(set_option)::text FROM pg_auth_members
		WHERE roleid = 'dbf_it_ro'::regrole AND member = 'dbf_it_app'::regrole`); len(got) != 1 || got[0] != "truetruefalse" {
		t.Errorf("membership options = %v, want truetruefalse", got)
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
		!strings.Contains(out, "SET DEFAULT ROLE 'dbf_it_ro'@'%' TO 'dbf_it_app'@'%'") || !strings.Contains(out, `unmanaged user "dbf_it_stray"@"%"`) || !strings.Contains(out, `unmanaged database "dbf_it_legacy"`) {
		t.Fatalf("drift plan: %d\n%s", n, out)
	}
	h.apply(app.Options{Prune: true})
	h.assertConverged(app.Options{Prune: true})

	// ADMIN OPTION in the object form of member_of. Dropping it revokes
	// and grants the role again, which keeps it a default role.
	withAdmin := func(v bool) string {
		return strings.Replace(mysqlConfig("second"), "member_of   = [role.ro.id]", fmt.Sprintf("member_of   = [{ role = role.ro.id, admin = %v }]", v), 1)
	}
	state := func() string {
		got := h.query("SELECT CONCAT(e.WITH_ADMIN_OPTION, COUNT(d.USER)) FROM mysql.role_edges e LEFT JOIN mysql.default_roles d ON d.USER = e.TO_USER AND d.DEFAULT_ROLE_USER = e.FROM_USER WHERE e.TO_USER = 'dbf_it_app' GROUP BY e.WITH_ADMIN_OPTION")
		return strings.Join(got, ",")
	}
	h.write(withAdmin(true))
	if n, out := h.plan(app.Options{}); n != 1 || !strings.Contains(out, "GRANT 'dbf_it_ro'@'%' TO 'dbf_it_app'@'%' WITH ADMIN OPTION") {
		t.Fatalf("admin plan: %d\n%s", n, out)
	}
	h.apply(app.Options{})
	h.assertConverged(app.Options{})
	if got := state(); got != "Y1" {
		t.Errorf("admin option, default roles = %s, want Y1", got)
	}
	h.write(withAdmin(false))
	if n, out := h.plan(app.Options{}); n != 3 || !strings.Contains(out, "SET DEFAULT ROLE 'dbf_it_ro'@'%' TO 'dbf_it_app'@'%'") {
		t.Fatalf("drop admin plan: %d\n%s", n, out)
	}
	h.apply(app.Options{})
	h.assertConverged(app.Options{})
	if got := state(); got != "N1" {
		t.Errorf("admin option, default roles = %s, want N1", got)
	}
}

// TestMySQLRetainedPassword checks that a secondary password kept by
// RETAIN CURRENT PASSWORD is discarded when the primary already matches.
func TestMySQLRetainedPassword(t *testing.T) {
	t.Parallel()
	h := newHarness(t, model.EngineMySQL, mysqlContainer)
	h.write(mysqlConfig("first"))
	h.apply(app.Options{})
	h.exec("ALTER USER 'dbf_it_app'@'%' IDENTIFIED BY 'second' RETAIN CURRENT PASSWORD")
	h.write(mysqlConfig("second"))
	if n, out := h.plan(app.Options{}); n != 1 || !strings.Contains(out, "ALTER USER 'dbf_it_app'@'%' DISCARD OLD PASSWORD") {
		t.Fatalf("retained password plan: %d\n%s", n, out)
	}
	h.apply(app.Options{})
	h.assertConverged(app.Options{})
	if got := h.query("SELECT User FROM mysql.user WHERE JSON_CONTAINS_PATH(User_attributes, 'one', '$.additional_password')"); len(got) != 0 {
		t.Errorf("accounts with a secondary password = %q", got)
	}
}

// TestMySQLOneStatementPerExec checks that Driver.Exec sends exactly one
// statement even when the DSN asks for multiStatements.
func TestMySQLOneStatementPerExec(t *testing.T) {
	t.Parallel()
	h := newHarness(t, model.EngineMySQL, mysqlContainer)
	d, err := mysql.Open(t.Context(), h.dsn+"?multiStatements=true&allowAllFiles=true")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	for _, q := range []plan.Keyword{
		"SELECT 1; SELECT 2",
		"CREATE USER 'dbf_ms1'@'%'; CREATE USER 'dbf_ms2'@'%'",
		"DO 1;DO 2",
	} {
		err := d.Exec(t.Context(), plan.SQL("", q))
		if myErr, ok := errors.AsType[*gomysql.MySQLError](err); !ok || myErr.Number != 1064 {
			t.Errorf("Exec(%q) = %v, want error 1064", q, err)
		}
	}
	if got := h.query("SELECT User FROM mysql.user WHERE User LIKE 'dbf\\_ms%'"); len(got) != 0 {
		t.Errorf("users created by rejected statements: %q", got)
	}
	if err := d.Exec(t.Context(), plan.SQL("", plan.Keyword("DO 1"))); err != nil {
		t.Errorf("single statement: %v", err)
	}
	// MySQL statements never run as another role.
	if err := d.Exec(t.Context(), plan.SQL("", plan.Keyword("DO 1")).WithRole("r")); err == nil || !strings.Contains(err.Error(), "not supported on MySQL") {
		t.Errorf("Exec as role = %v", err)
	}
}

// TestMySQLPruneKeepsTableRoutineAndProxyPrivileges checks that --prune
// keeps accounts whose DROP USER would delete table, column, routine or
// PROXY privileges naming a database or account dbfence does not manage,
// and still drops an account without them.
func TestMySQLPruneKeepsTableRoutineAndProxyPrivileges(t *testing.T) {
	t.Parallel()
	h := newHarness(t, model.EngineMySQL, mysqlContainer)
	for _, q := range []string{
		"CREATE DATABASE `ev\x01db`",
		"CREATE TABLE `ev\x01db`.t (c INT)",
		"CREATE PROCEDURE `ev\x01db`.p() BEGIN END",
		"CREATE USER 'dbf_tbl'@'%', 'dbf_col'@'%', 'dbf_proc'@'%', 'dbf_proxy'@'%', 'dbf_plain'@'%', 'ev\x01u'@'%'",
		"GRANT SELECT ON `ev\x01db`.t TO 'dbf_tbl'@'%'",
		"GRANT SELECT (c) ON `ev\x01db`.t TO 'dbf_col'@'%'",
		"GRANT EXECUTE ON PROCEDURE `ev\x01db`.p TO 'dbf_proc'@'%'",
		// root@'%' may not grant PROXY; GRANT PROXY writes this row.
		"INSERT INTO mysql.proxies_priv (Host, User, Proxied_host, Proxied_user, With_grant) VALUES ('%', 'dbf_proxy', '%', 'ev\x01u', 0)",
		"FLUSH PRIVILEGES",
	} {
		h.exec(q)
	}
	h.write(mysqlConfig("pw"))
	_, out := h.plan(app.Options{Prune: true})
	for _, u := range []string{"dbf_tbl", "dbf_col", "dbf_proc", "dbf_proxy"} {
		if strings.Contains(out, "DROP USER '"+u+"'") {
			t.Errorf("prune drops %s:\n%s", u, out)
		}
		if !strings.Contains(out, `user "`+u+`"@"%" is granted to, has as a granted or default role, or holds privileges`) {
			t.Errorf("plan does not say why %s is kept:\n%s", u, out)
		}
	}
	if !strings.Contains(out, "DROP USER 'dbf_plain'@'%'") {
		t.Errorf("prune does not drop dbf_plain:\n%s", out)
	}
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

// TestMySQLConnectedAccount runs dbfence as an account that gets its
// privileges from a default role, connected to a database named in the
// DSN: --prune keeps both, and SET DEFAULT ROLE keeps the role active.
func TestMySQLConnectedAccount(t *testing.T) {
	t.Parallel()
	h := newHarness(t, model.EngineMySQL, mysqlContainer)
	for _, q := range []string{
		"CREATE ROLE 'dbf_dbarole'@'%'",
		"GRANT ALL PRIVILEGES ON *.* TO 'dbf_dbarole'@'%' WITH GRANT OPTION",
		"CREATE USER 'dbf_dba'@'%' IDENTIFIED BY 'dbapw'",
		"GRANT 'dbf_dbarole'@'%' TO 'dbf_dba'@'%'",
		"SET DEFAULT ROLE ALL TO 'dbf_dba'@'%'",
		"CREATE DATABASE dbf_conn",
	} {
		h.exec(q)
	}
	h.dsn = strings.Replace(h.dsn, "root:root@", "dbf_dba:dbapw@", 1) + "dbf_conn"
	h.write(`
user "dba" {
  name      = "dbf_dba"
  password  = "dbapw"
  member_of = []
}
`)
	_, out := h.plan(app.Options{Prune: true})
	for _, w := range []string{
		`not revoking membership of the connected user "dbf_dba"@"%" in "dbf_dbarole"@"%"`,
		`database "dbf_conn" is the database dbfence is connected to; not pruned`,
	} {
		if !strings.Contains(out, w) {
			t.Errorf("plan lacks %q:\n%s", w, out)
		}
	}
	if strings.Contains(out, "SET DEFAULT ROLE") || strings.Contains(out, "DROP DATABASE `dbf_conn`") {
		t.Fatalf("plan changes the connected account or database:\n%s", out)
	}
	h.apply(app.Options{Prune: true})
	h.assertConverged(app.Options{Prune: true})

	dba, err := sql.Open("mysql", h.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dba.Close() }()
	var role string
	if err := dba.QueryRowContext(t.Context(), "SELECT CURRENT_ROLE()").Scan(&role); err != nil || role != "`dbf_dbarole`@`%`" {
		t.Errorf("CURRENT_ROLE() of a new session = %q, %v; want the role kept active", role, err)
	}

	h.write("")
	if _, out := h.plan(app.Options{Prune: true}); !strings.Contains(out, `user "dbf_dba"@"%" is the connected user; not pruned`) {
		t.Errorf("plan lacks the connected user warning:\n%s", out)
	}
}

// TestPostgresServerSideHashing checks that passwords are hashed by the
// server with its own settings, and that md5 verifiers converge under
// password_encryption = md5 and are upgraded once it is scram-sha-256.
func TestPostgresServerSideHashing(t *testing.T) {
	t.Parallel()
	h := newHarness(t, model.EnginePostgres, postgresContainer)
	verifier := func() string {
		t.Helper()
		got := h.query("SELECT rolpassword FROM pg_authid WHERE rolname = 'dbf_it_hash'")
		if len(got) != 1 {
			t.Fatalf("rolpassword rows = %q", got)
		}
		return got[0]
	}
	login := func() {
		t.Helper()
		u, err := sql.Open("pgx", strings.Replace(h.dsn, "postgres:postgres@", "dbf_it_hash:hashpw@", 1))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = u.Close() }()
		if err = u.PingContext(t.Context()); err != nil {
			t.Errorf("log in with the declared password: %v", err)
		}
	}
	h.write(`
user "app" {
  name     = "dbf_it_hash"
  password = "hashpw"
}
`)

	h.exec("ALTER ROLE postgres SET scram_iterations = 8192")
	h.exec("ALTER ROLE postgres SET password_encryption = 'md5'")
	h.apply(app.Options{})
	h.assertConverged(app.Options{})
	if v := verifier(); !strings.HasPrefix(v, "md5") {
		t.Fatalf("verifier = %q, want md5 under password_encryption = md5", v)
	}
	// No login check here: the image's pg_hba.conf requires scram-sha-256.

	h.exec("ALTER ROLE postgres RESET password_encryption")
	if n, out := h.plan(app.Options{}); n != 1 {
		t.Fatalf("plan after switching to scram-sha-256: %d statements, want the password upgrade:\n%s", n, out)
	}
	h.apply(app.Options{})
	h.assertConverged(app.Options{})
	if v := verifier(); !strings.HasPrefix(v, "SCRAM-SHA-256$8192:") {
		t.Fatalf("verifier = %q, want SCRAM with the server's scram_iterations", v)
	}
	login()
}

// TestMySQLDatabasePattern manages a wildcard grant declared with
// database_pattern.
func TestMySQLDatabasePattern(t *testing.T) {
	t.Parallel()
	h := newHarness(t, model.EngineMySQL, mysqlContainer)
	for _, q := range []string{
		"CREATE DATABASE dbf_tenant_a", "CREATE TABLE dbf_tenant_a.t (i INT)",
		"CREATE DATABASE dbf_tenantXb", "CREATE TABLE dbf_tenantXb.t (i INT)",
	} {
		h.exec(q)
	}
	cfg := func(privs string) string {
		return `
user "app" {
  name     = "dbf_pat"
  password = "patpw"
}
grant {
  role             = user.app.id
  database_pattern = "dbf\\_tenant\\_%"
  privileges       = [` + privs + `]
}
ignore {
  databases = ["dbf_tenant.*"]
}
`
	}
	h.write(cfg(`"SELECT", "INSERT"`))
	h.apply(app.Options{})
	h.assertConverged(app.Options{})
	if got := h.query("SELECT Db FROM mysql.db WHERE User = 'dbf_pat'"); !slices.Equal(got, []string{`dbf\_tenant\_%`}) {
		t.Fatalf("mysql.db rows = %q, want the pattern verbatim", got)
	}

	u, err := sql.Open("mysql", strings.Replace(h.dsn, "root:root@", "dbf_pat:patpw@", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = u.Close() }()
	if _, err = u.ExecContext(t.Context(), "INSERT INTO dbf_tenant_a.t VALUES (1)"); err != nil {
		t.Errorf("insert into a database matching the pattern: %v", err)
	}
	if _, err = u.ExecContext(t.Context(), "SELECT * FROM dbf_tenantXb.t"); err == nil {
		t.Error("select from dbf_tenantXb succeeded; the escaped _ must not match X")
	}

	h.write(cfg(`"SELECT"`))
	if n, out := h.plan(app.Options{}); n != 1 || !strings.Contains(out, "REVOKE INSERT ON `dbf\\_tenant\\_%`.*") {
		t.Fatalf("plan after dropping INSERT = %d statements:\n%s", n, out)
	}
	h.apply(app.Options{})
	h.assertConverged(app.Options{})

	h.exec("SET GLOBAL partial_revokes = ON")
	a, out := h.app()
	_, err = a.Plan(context.WithoutCancel(t.Context()), app.Options{Path: filepath.Join(h.dir, "dbfence.hcl")})
	if err == nil || !strings.Contains(err.Error(), "needs partial_revokes = OFF") {
		t.Errorf("plan with partial_revokes ON: err = %v\n%s", err, out)
	}
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

// TestMySQLErrorsDoNotLeakSecrets checks that server errors quoting a
// failed statement, including the truncated "near '...'" fragment of
// syntax errors, never print the password.
func TestMySQLErrorsDoNotLeakSecrets(t *testing.T) {
	t.Parallel()
	h := newHarness(t, model.EngineMySQL, mysqlContainer)
	drv, err := mysql.Open(t.Context(), h.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = drv.Close() }()
	long := strings.Repeat("SECRET0123456789", 6)
	tests := []struct {
		name, password, wantMsg string
		prefix                  plan.Keyword
		leak                    []string
	}{
		{
			name: "truncated near fragment", prefix: "CREATE USER 'dbf_leak'@'%' IDENTIFIED WITH auth-pam BY ",
			password: long, leak: []string{long[:4]}, wantMsg: "near <withheld>",
		},
		{
			name: "short password", prefix: "CREATE USER 'dbf_leak'@'x.example.com' IDENTIFIED WITH auth-pam BY ",
			password: "x'y", leak: []string{"x'y", "x''y", "-pam"}, wantMsg: "near <withheld>",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &plan.Plan{Changes: []plan.Change{{Action: plan.ActionCreate, Resource: `role "dbf_leak"`, Statements: []plan.Statement{
				plan.SQL("", tt.prefix, plan.NewSecret(drv.Literal(tt.password))),
			}}}}
			err := apply.Run(t.Context(), drv, p, io.Discard, false)
			if err == nil {
				t.Fatal("apply succeeded")
			}
			if !strings.Contains(err.Error(), "1064") || !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error = %v, want substring %q", err, tt.wantMsg)
			}
			for _, l := range tt.leak {
				if strings.Contains(err.Error(), l) {
					t.Errorf("error leaked %q: %v", l, err)
				}
			}
		})
	}
}
