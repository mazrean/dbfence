package postgres

import (
	"database/sql"
	"io"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mazrean/dbfence/internal/apply"
	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

// The integration tests run against a disposable postgres:17 server. They
// are skipped with -short, and when Docker is unavailable outside CI.

type server struct {
	t     *testing.T
	admin *sql.DB
	// dsn returns a DSN for user (password "pw") on database "postgres".
	dsn func(user string) string
}

func startServer(t *testing.T) *server {
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
	res, err := pool.RunWithOptions(&dockertest.RunOptions{Repository: "postgres", Tag: "17", Env: []string{"POSTGRES_PASSWORD=pw"}},
		func(hc *docker.HostConfig) {
			hc.AutoRemove = true
			hc.RestartPolicy = docker.RestartPolicy{Name: "no"}
		})
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() { _ = pool.Purge(res) })
	_ = res.Expire(600)
	hp := res.GetHostPort("5432/tcp")
	s := &server{t: t, dsn: func(user string) string {
		return "postgres://" + user + ":pw@" + hp + "/postgres?sslmode=disable"
	}}
	s.admin, err = sql.Open("pgx", s.dsn("postgres"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.admin.Close() })
	if err := pool.Retry(func() error { return s.admin.PingContext(t.Context()) }); err != nil {
		t.Fatalf("postgres did not become ready: %v", err)
	}
	return s
}

// exec runs statements as the bootstrap superuser, on database "postgres"
// unless the first one is "\c <db>".
func (s *server) exec(t *testing.T, stmts ...string) {
	t.Helper()
	db := s.admin
	if len(stmts) > 0 && strings.HasPrefix(stmts[0], `\c `) {
		var err error
		db, err = sql.Open("pgx", strings.Replace(s.dsn("postgres"), "/postgres?", "/"+strings.TrimPrefix(stmts[0], `\c `)+"?", 1))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()
		stmts = stmts[1:]
	}
	for _, q := range stmts {
		if _, err := db.ExecContext(t.Context(), q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func (s *server) queryStrings(t *testing.T, q string) []string {
	t.Helper()
	rows, err := s.admin.QueryContext(t.Context(), q)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}

func (s *server) open(t *testing.T, user string) *Driver {
	t.Helper()
	d, err := Open(t.Context(), s.dsn(user))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// planFor inspects and diffs desired, returning the rendered plan.
func planFor(t *testing.T, d *Driver, desired *model.Desired, opts diff.Options) (*planResult, error) {
	t.Helper()
	cur, err := d.Inspect(t.Context(), desired)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	p, err := diff.Compute(desired, cur, d, opts)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	var sb strings.Builder
	if err := p.Render(&sb, false); err != nil {
		t.Fatal(err)
	}
	return &planResult{text: sb.String(), n: len(p.Statements())}, apply.Run(t.Context(), d, p, io.Discard, false)
}

type planResult struct {
	text string
	n    int
}

// converge applies desired and asserts that the next plan is empty.
func converge(t *testing.T, d *Driver, desired *model.Desired, opts diff.Options) string {
	t.Helper()
	first, err := planFor(t, d, desired, opts)
	if err != nil {
		t.Fatalf("apply: %v\nplan:\n%s", err, first.text)
	}
	cur, err := d.Inspect(t.Context(), desired)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	p, err := diff.Compute(desired, cur, d, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Empty() {
		var sb strings.Builder
		_ = p.Render(&sb, false)
		t.Fatalf("not converged after apply of\n%s\nsecond plan:\n%s", first.text, sb.String())
	}
	return first.text
}

func pg(name string) model.RoleID { return model.RoleID{Name: name} }

func TestIntegration(t *testing.T) {
	t.Parallel()
	s := startServer(t)

	t.Run("standard_conforming_strings is forced on", func(t *testing.T) {
		s.exec(t, "CREATE ROLE scs LOGIN SUPERUSER PASSWORD 'pw'", "ALTER ROLE scs SET standard_conforming_strings = off")
		d := s.open(t, "scs")
		var v string
		if err := d.db.QueryRowContext(t.Context(), "SELECT current_setting('standard_conforming_strings')").Scan(&v); err != nil {
			t.Fatal(err)
		}
		if v != "on" {
			t.Errorf("standard_conforming_strings = %q", v)
		}
		if err := d.Exec(t.Context(), "", "COMMENT ON ROLE scs IS "+Literal(`a\'b`)); err != nil {
			t.Fatal(err)
		}
		if got := s.queryStrings(t, "SELECT shobj_description(oid, 'pg_authid') FROM pg_roles WHERE rolname = 'scs'"); len(got) != 1 || got[0] != `a\'b` {
			t.Errorf("literal round trip = %q", got)
		}
	})

	t.Run("passwords are sent as SCRAM verifiers", func(t *testing.T) {
		pw := func(s string) *string { return &s }
		login := true
		d := s.open(t, "postgres")
		for _, p := range []string{`it's\'; SELECT 1; --`, "md5aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ""} {
			desired := &model.Desired{Engine: model.EnginePostgres, Roles: []model.Role{{ID: pg("pwuser"), Login: &login, Password: pw(p)}}}
			converge(t, d, desired, diff.Options{})
			if p == "" {
				if got := s.queryStrings(t, "SELECT coalesce(rolpassword, 'NULL') FROM pg_authid WHERE rolname = 'pwuser'"); got[0] != "NULL" {
					t.Errorf("empty password stored as %q", got)
				}
				continue
			}
			u, err := url.Parse(s.dsn("pwuser"))
			if err != nil {
				t.Fatal(err)
			}
			u.User = url.UserPassword("pwuser", p)
			c, err := sql.Open("pgx", u.String())
			if err != nil {
				t.Fatal(err)
			}
			if err := c.PingContext(t.Context()); err != nil {
				t.Errorf("cannot log in with %q: %v", p, err)
			}
			_ = c.Close()
		}
		// An md5 verifier of the declared password is upgraded.
		s.exec(t, "BEGIN; SET LOCAL password_encryption = 'md5'; ALTER ROLE pwuser PASSWORD 'old'; COMMIT")
		desired := &model.Desired{Engine: model.EnginePostgres, Roles: []model.Role{{ID: pg("pwuser"), Login: &login, Password: pw("old")}}}
		converge(t, d, desired, diff.Options{})
		if got := s.queryStrings(t, "SELECT left(rolpassword, 14) FROM pg_authid WHERE rolname = 'pwuser'"); got[0] != "SCRAM-SHA-256$" {
			t.Errorf("verifier not upgraded: %q", got)
		}
	})

	t.Run("databases that refuse connections", func(t *testing.T) {
		s.exec(t,
			"CREATE DATABASE noconn", "ALTER DATABASE noconn ALLOW_CONNECTIONS false",
			"CREATE DATABASE tmpl", "ALTER DATABASE tmpl IS_TEMPLATE true",
			"CREATE DATABASE private", "REVOKE CONNECT ON DATABASE private FROM PUBLIC",
			"CREATE ROLE limited LOGIN CREATEROLE PASSWORD 'pw'",
			"CREATE ROLE stray_noconn",
		)
		desired := &model.Desired{Engine: model.EnginePostgres, Databases: []model.Database{{Name: "noconn"}, {Name: "tmpl"}, {Name: "private"}}}
		for _, user := range []string{"postgres", "limited"} {
			d := s.open(t, user)
			cur, err := d.Inspect(t.Context(), desired)
			if err != nil {
				t.Fatalf("%s: %v", user, err)
			}
			if cur.CurrentDatabase != "postgres" {
				t.Errorf("CurrentDatabase = %q", cur.CurrentDatabase)
			}
			p, err := diff.Compute(desired, cur, d, diff.Options{})
			if err != nil {
				t.Fatal(err)
			}
			var sb strings.Builder
			_ = p.Render(&sb, false)
			out := sb.String()
			if strings.Contains(out, "CREATE DATABASE") || !strings.Contains(out, `cannot connect to database "noconn"`) {
				t.Errorf("%s plan:\n%s", user, out)
			}
			if user == "limited" && (!strings.Contains(out, `cannot connect to database "private"`) || cur.Roles[0].PasswordReadable) {
				t.Errorf("limited plan:\n%s", out)
			}
			// Pruning a role does not run statements on databases that
			// cannot be connected to.
			if user == "postgres" {
				p, err := diff.Compute(desired, cur, d, diff.Options{Prune: true})
				if err != nil {
					t.Fatal(err)
				}
				for _, st := range p.Statements() {
					if st.Database == "noconn" {
						t.Errorf("statement on unreachable database: %s", st.SQL())
					}
				}
			}
		}
	})

	t.Run("privileges from other grantors converge", func(t *testing.T) {
		s.exec(t, "CREATE ROLE g_owner", "CREATE ROLE g_ro", "CREATE ROLE g_app", "CREATE ROLE g_x", "CREATE DATABASE g_db OWNER g_owner")
		s.exec(t, `\c g_db`, "CREATE SCHEMA api AUTHORIZATION g_owner")
		d := s.open(t, "postgres")
		schema := model.Object{Type: model.ObjectSchema, Database: "g_db", Schema: "api"}
		db := model.Object{Type: model.ObjectDatabase, Database: "g_db"}
		base := func(privs ...model.Privilege) *model.Desired {
			return &model.Desired{
				Engine:     model.EnginePostgres,
				Roles:      []model.Role{{ID: pg("g_owner")}, {ID: pg("g_ro")}, {ID: pg("g_app")}, {ID: pg("g_x")}},
				Databases:  []model.Database{{Name: "g_db", Owner: "g_owner"}},
				Schemas:    []model.Schema{{Database: "g_db", Name: "api", Owner: "g_owner"}},
				Privileges: privs,
				Ignore:     model.Ignore{Roles: []string{".*"}},
			}
		}
		roUsage := model.Privilege{Grantee: pg("g_ro"), Object: schema, Name: "USAGE", GrantOption: true}
		converge(t, d, base(roUsage), diff.Options{})

		// L19: a grant made by g_ro is revoked as g_ro.
		s.exec(t, `\c g_db`, "SET ROLE g_ro; GRANT USAGE ON SCHEMA api TO g_app; RESET ROLE")
		converge(t, d, base(roUsage), diff.Options{})

		// L20: dropping the grant option of g_ro cascades to g_app and
		// g_x; the declared grant of g_app is granted again.
		appUsage := model.Privilege{Grantee: pg("g_app"), Object: schema, Name: "USAGE"}
		s.exec(t, `\c g_db`, "SET ROLE g_ro; GRANT USAGE ON SCHEMA api TO g_app WITH GRANT OPTION; RESET ROLE",
			"SET ROLE g_app; GRANT USAGE ON SCHEMA api TO g_x; RESET ROLE")
		noOption := roUsage
		noOption.GrantOption = false
		out := converge(t, d, base(noOption, appUsage), diff.Options{})
		if !strings.Contains(out, "CASCADE") {
			t.Errorf("plan does not say CASCADE:\n%s", out)
		}
		// Removing the grant entirely with dependents also converges.
		s.exec(t, `\c g_db`, "GRANT USAGE ON SCHEMA api TO g_ro WITH GRANT OPTION",
			"SET ROLE g_ro; GRANT USAGE ON SCHEMA api TO g_x; RESET ROLE")
		converge(t, d, base(appUsage), diff.Options{})

		// C64: database privileges, and the grant option held through a
		// second grantor.
		s.exec(t, "GRANT CONNECT ON DATABASE g_db TO g_ro WITH GRANT OPTION",
			"SET ROLE g_ro; GRANT CONNECT ON DATABASE g_db TO g_app WITH GRANT OPTION; RESET ROLE",
			"GRANT CONNECT ON DATABASE g_db TO g_app")
		connect := model.Privilege{Grantee: pg("g_ro"), Object: db, Name: "CONNECT"}
		appConnect := model.Privilege{Grantee: pg("g_app"), Object: db, Name: "CONNECT"}
		converge(t, d, base(appUsage, connect, appConnect), diff.Options{})
		converge(t, d, base(appUsage), diff.Options{})
		if got := s.queryStrings(t, "SELECT coalesce(datacl::text, '') FROM pg_database WHERE datname = 'g_db'"); strings.Contains(got[0], "g_app") || strings.Contains(got[0], "g_ro") {
			t.Errorf("datacl = %v", got)
		}
	})

	t.Run("memberships from other grantors converge", func(t *testing.T) {
		s.exec(t, "CREATE ROLE m_mgr CREATEROLE", "CREATE ROLE m_grp", "CREATE ROLE m_u1", "CREATE ROLE m_u2",
			"GRANT m_grp TO m_mgr WITH ADMIN OPTION",
			"SET ROLE m_mgr; GRANT m_grp TO m_u1; RESET ROLE",
			"GRANT m_grp TO m_u1 WITH ADMIN OPTION",
			"SET ROLE m_u1; GRANT m_grp TO m_u2; RESET ROLE")
		d := s.open(t, "postgres")
		desired := &model.Desired{
			Engine: model.EnginePostgres,
			Roles: []model.Role{
				{ID: pg("m_grp")},
				{ID: pg("m_u1"), MemberOf: []model.RoleID{}},
				{ID: pg("m_u2"), MemberOf: []model.RoleID{pg("m_grp")}},
			},
			Ignore: model.Ignore{Roles: []string{".*"}},
		}
		out := converge(t, d, desired, diff.Options{})
		if !strings.Contains(out, `GRANTED BY "m_mgr"`) || !strings.Contains(out, "CASCADE") {
			t.Errorf("plan:\n%s", out)
		}
		if got := s.queryStrings(t, "SELECT m.rolname FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member WHERE am.roleid = 'm_grp'::regrole ORDER BY 1"); strings.Join(got, ",") != "m_mgr,m_u2" {
			t.Errorf("members of m_grp = %v", got)
		}
	})

	t.Run("inherit applies to existing memberships", func(t *testing.T) {
		d := s.open(t, "postgres")
		for _, inherit := range []bool{true, false, true} {
			desired := &model.Desired{
				Engine: model.EnginePostgres,
				Roles:  []model.Role{{ID: pg("i_grp")}, {ID: pg("i_u"), Inherit: &inherit, MemberOf: []model.RoleID{pg("i_grp")}}},
				Ignore: model.Ignore{Roles: []string{".*"}},
			}
			converge(t, d, desired, diff.Options{})
			got := s.queryStrings(t, "SELECT pg_has_role('i_u', 'i_grp', 'USAGE')::text")
			if got[0] != strconv.FormatBool(inherit) {
				t.Errorf("inherit = %v: i_u has the privileges of i_grp = %s", inherit, got[0])
			}
		}
	})

	t.Run("membership options converge", func(t *testing.T) {
		s.exec(t, "CREATE ROLE o_mgr", "CREATE ROLE o_grp", "CREATE ROLE o_u", "CREATE ROLE o_dep",
			"GRANT o_grp TO o_mgr WITH ADMIN OPTION")
		d := s.open(t, "postgres")
		yes, no := true, false
		desired := func(opts model.MembershipOptions) *model.Desired {
			return &model.Desired{
				Engine: model.EnginePostgres,
				Roles: []model.Role{
					{ID: pg("o_grp")},
					{ID: pg("o_u"), Inherit: &yes, MemberOf: []model.RoleID{pg("o_grp")}, MemberOptions: map[model.RoleID]model.MembershipOptions{pg("o_grp"): opts}},
					{ID: pg("o_dep"), MemberOf: []model.RoleID{pg("o_grp")}, MemberOptions: map[model.RoleID]model.MembershipOptions{pg("o_grp"): {Set: &no}}},
				},
				Ignore: model.Ignore{Roles: []string{".*"}},
			}
		}
		options := func() string {
			return strings.Join(s.queryStrings(t, `SELECT m.rolname || ':' || g.rolname || ':' || am.admin_option || am.inherit_option || am.set_option
				FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member JOIN pg_roles g ON g.oid = am.grantor
				WHERE am.roleid = 'o_grp'::regrole AND m.rolname <> 'o_mgr' ORDER BY 1`), ",")
		}

		converge(t, d, desired(model.MembershipOptions{Admin: &yes, Inherit: &no, Set: &no}), diff.Options{})
		if got, want := options(), "o_dep:postgres:falsetruefalse,o_u:postgres:truefalsefalse"; got != want {
			t.Errorf("after create: %s, want %s", got, want)
		}

		// Drift: o_u passes o_grp on with its ADMIN OPTION, and a second
		// grantor's grant inherits.
		s.exec(t, "REVOKE o_grp FROM o_dep", "SET ROLE o_u; GRANT o_grp TO o_dep WITH SET FALSE; RESET ROLE",
			"SET ROLE o_mgr; GRANT o_grp TO o_u WITH ADMIN TRUE, INHERIT TRUE, SET TRUE; RESET ROLE")
		out := converge(t, d, desired(model.MembershipOptions{Admin: &no, Inherit: &yes, Set: &yes}), diff.Options{})
		for _, want := range []string{
			`REVOKE ADMIN OPTION FOR "o_grp" FROM "o_u" GRANTED BY "postgres" CASCADE`,
			`REVOKE ADMIN OPTION FOR "o_grp" FROM "o_u" GRANTED BY "o_mgr" CASCADE`,
			`GRANT "o_grp" TO "o_u" WITH INHERIT TRUE, SET TRUE GRANTED BY "postgres"`,
			`GRANT "o_grp" TO "o_dep" WITH SET FALSE`,
		} {
			if !strings.Contains(out, want) {
				t.Errorf("plan lacks %s:\n%s", want, out)
			}
		}
		if got, want := options(), "o_dep:postgres:falsetruefalse,o_u:o_mgr:falsetruetrue,o_u:postgres:falsetruetrue"; got != want {
			t.Errorf("after drift: %s, want %s", got, want)
		}

		// The string form manages no options (and without the role's
		// inherit attribute, nothing manages INHERIT).
		s.exec(t, "GRANT o_grp TO o_u WITH INHERIT FALSE GRANTED BY o_mgr")
		plain := desired(model.MembershipOptions{})
		plain.Roles[1].Inherit = nil
		if r, err := planFor(t, d, plain, diff.Options{}); err != nil || r.n != 0 {
			t.Errorf("string form plan (%v):\n%s", err, r.text)
		}
	})

	t.Run("membership inherit that disagrees with the role warns", func(t *testing.T) {
		d := s.open(t, "postgres")
		no, yes := false, true
		desired := &model.Desired{
			Engine: model.EnginePostgres,
			Roles: []model.Role{
				{ID: pg("mi_grp")}, {ID: pg("mi_other")},
				{ID: pg("mi_u"), Inherit: &no, MemberOf: []model.RoleID{pg("mi_grp"), pg("mi_other")}, MemberOptions: map[model.RoleID]model.MembershipOptions{pg("mi_grp"): {Inherit: &yes}}},
			},
			Ignore: model.Ignore{Roles: []string{".*"}},
		}
		converge(t, d, desired, diff.Options{})
		cur, err := d.Inspect(t.Context(), desired)
		if err != nil {
			t.Fatal(err)
		}
		if w := strings.Join(cur.Warnings, "\n"); !strings.Contains(w, `membership of "mi_u" in "mi_grp" declares inherit = true, but the role has inherit = false`) {
			t.Errorf("warnings: %s", w)
		}
		if got := s.queryStrings(t, "SELECT pg_has_role('mi_u', 'mi_grp', 'USAGE')::text || pg_has_role('mi_u', 'mi_other', 'USAGE')::text"); got[0] != "truefalse" {
			t.Errorf("mi_u inherits mi_grp, mi_other = %s, want truefalse", got[0])
		}
	})

	t.Run("non-superuser admin limits are reported in plan", func(t *testing.T) {
		s.exec(t, "CREATE ROLE n_admin LOGIN CREATEROLE CREATEDB PASSWORD 'pw'", "CREATE ROLE n_alice LOGIN", "CREATE ROLE n_ghost")
		d := s.open(t, "n_admin")
		pw := "new"
		desired := &model.Desired{
			Engine:    model.EnginePostgres,
			Roles:     []model.Role{{ID: pg("n_alice"), Password: &pw}, {ID: pg("n_rw")}},
			Databases: []model.Database{{Name: "n_db", Owner: "n_rw"}},
			Ignore:    model.Ignore{Roles: []string{"[^n].*|n_admin"}},
		}
		res, err := planFor(t, d, desired, diff.Options{ForcePassword: true})
		for _, want := range []string{
			`database "n_db": "n_admin" cannot SET ROLE "n_rw"`,
			`role "n_alice" differs from the configuration, but "n_admin" may not alter it`,
			`role "n_ghost": "n_admin" does not have its privileges`,
		} {
			if !strings.Contains(res.text, want) {
				t.Errorf("plan lacks %q:\n%s", want, res.text)
			}
		}
		if strings.Contains(res.text, "ALTER ROLE") {
			t.Errorf("plan alters a role it may not:\n%s", res.text)
		}
		// The warned owner change is what fails.
		if err == nil || !strings.Contains(err.Error(), `must be able to SET ROLE "n_rw"`) {
			t.Errorf("apply error = %v", err)
		}
	})

	t.Run("unreadable verifiers are reported in one warning", func(t *testing.T) {
		s.exec(t, "CREATE ROLE uv_admin LOGIN CREATEROLE PASSWORD 'pw'", "CREATE ROLE uv_a LOGIN", "CREATE ROLE uv_b LOGIN")
		d := s.open(t, "uv_admin")
		pw := "secret"
		desired := &model.Desired{
			Engine: model.EnginePostgres,
			Roles:  []model.Role{{ID: pg("uv_b"), Password: &pw}, {ID: pg("uv_a"), Password: &pw}, {ID: pg("uv_new"), Password: &pw}},
			Ignore: model.Ignore{Roles: []string{".*"}, Databases: []string{".*"}},
		}
		res, err := planFor(t, d, desired, diff.Options{})
		if err != nil {
			t.Fatalf("apply: %v\n%s", err, res.text)
		}
		want := `cannot read the password verifiers of existing roles "uv_a", "uv_b" (superuser required)`
		if !strings.Contains(res.text, want) || strings.Count(res.text, "password verifier") != 1 {
			t.Errorf("plan lacks one grouped warning %q:\n%s", want, res.text)
		}
	})

	t.Run("dependencies in unreachable databases are reported", func(t *testing.T) {
		s.exec(t, "CREATE ROLE sd_owner", "CREATE ROLE sd_grantee", "CREATE DATABASE sd_noconn", "CREATE DATABASE sd_ign")
		s.exec(t, `\c sd_noconn`, "CREATE TABLE t (id int)", "ALTER TABLE t OWNER TO sd_owner", "GRANT SELECT ON t TO sd_grantee")
		s.exec(t, `\c sd_ign`, "CREATE TABLE t (id int)", "ALTER TABLE t OWNER TO sd_owner")
		s.exec(t, "ALTER DATABASE sd_noconn ALLOW_CONNECTIONS false")
		d := s.open(t, "postgres")
		cur, err := d.Inspect(t.Context(), &model.Desired{Engine: model.EnginePostgres, Ignore: model.Ignore{Databases: []string{"sd_ign"}}})
		if err != nil {
			t.Fatal(err)
		}
		w := strings.Join(cur.Warnings, "\n")
		for _, want := range []string{
			`role "sd_owner" owns objects or holds privileges in database "sd_ign" (ignored), database "sd_noconn" (cannot connect), where dbfence does not run REASSIGN OWNED`,
			`role "sd_grantee" owns objects or holds privileges in database "sd_noconn" (cannot connect)`,
		} {
			if !strings.Contains(w, want) {
				t.Errorf("warnings lack %q:\n%s", want, w)
			}
		}
		// Later subtests prune with these roles in sight.
		s.exec(t, "ALTER DATABASE sd_noconn ALLOW_CONNECTIONS true", "DROP DATABASE sd_noconn", "DROP DATABASE sd_ign", "DROP ROLE sd_owner", "DROP ROLE sd_grantee")
	})

	t.Run("pruning a grantor grants its declared grants again", func(t *testing.T) {
		s.exec(t, "CREATE ROLE q_x", "CREATE ROLE q_y", "CREATE ROLE q_z", "CREATE ROLE q_g", "CREATE DATABASE q_db",
			"GRANT CONNECT ON DATABASE q_db TO q_x WITH GRANT OPTION", "GRANT q_g TO q_x WITH ADMIN OPTION",
			"GRANT q_g TO q_z GRANTED BY q_x",
			"SET ROLE q_x; GRANT CONNECT ON DATABASE q_db TO q_y; RESET ROLE")
		s.exec(t, `\c q_db`, "CREATE SCHEMA api", "GRANT USAGE ON SCHEMA api TO q_x WITH GRANT OPTION",
			"SET ROLE q_x; GRANT USAGE ON SCHEMA api TO q_y; RESET ROLE")
		d := s.open(t, "postgres")
		g := pg("q_g")
		desired := &model.Desired{
			Engine:    model.EnginePostgres,
			Roles:     []model.Role{{ID: pg("q_y")}, {ID: pg("q_z"), MemberOf: []model.RoleID{g}}, {ID: g, MemberOf: []model.RoleID{}}},
			Databases: []model.Database{{Name: "q_db"}},
			Schemas:   []model.Schema{{Database: "q_db", Name: "api"}},
			Privileges: []model.Privilege{
				{Grantee: pg("q_y"), Object: model.Object{Type: model.ObjectDatabase, Database: "q_db"}, Name: "CONNECT"},
				{Grantee: pg("q_y"), Object: model.Object{Type: model.ObjectSchema, Database: "q_db", Schema: "api"}, Name: "USAGE"},
			},
			Ignore: model.Ignore{Roles: []string{"[^q].*"}, Databases: []string{"[^q].*"}, Schemas: []string{"public"}},
		}
		out := converge(t, d, desired, diff.Options{Prune: true})
		if !strings.Contains(out, `DROP ROLE "q_x"`) {
			t.Errorf("plan does not drop q_x:\n%s", out)
		}
		if got := s.queryStrings(t, "SELECT has_database_privilege('q_y', 'q_db', 'CONNECT')::text || pg_has_role('q_z', 'q_g', 'MEMBER')::text"); got[0] != "truetrue" {
			t.Errorf("q_y CONNECT, q_z in q_g = %s, want truetrue", got[0])
		}
	})

	t.Run("prune drops non-empty schemas", func(t *testing.T) {
		s.exec(t, "CREATE DATABASE p_db")
		s.exec(t, `\c p_db`, "CREATE SCHEMA junk", "CREATE SCHEMA junkfull", "CREATE TABLE junkfull.t (id int)")
		d := s.open(t, "postgres")
		desired := &model.Desired{
			Engine:    model.EnginePostgres,
			Databases: []model.Database{{Name: "p_db"}},
			Ignore:    model.Ignore{Roles: []string{".*"}, Databases: []string{".*"}},
		}
		out := converge(t, d, desired, diff.Options{Prune: true})
		if !strings.Contains(out, `DROP SCHEMA "junkfull" CASCADE`) || strings.Contains(out, `DROP SCHEMA "junk" CASCADE`) {
			t.Errorf("plan:\n%s", out)
		}
	})

	t.Run("ignore schemas by qualified name", func(t *testing.T) {
		s.exec(t, "CREATE DATABASE is_app", "CREATE DATABASE is_analytics")
		s.exec(t, `\c is_app`, "CREATE SCHEMA staging")
		s.exec(t, `\c is_analytics`, "CREATE SCHEMA staging")
		d := s.open(t, "postgres")
		desired := &model.Desired{
			Engine:    model.EnginePostgres,
			Databases: []model.Database{{Name: "is_app"}, {Name: "is_analytics"}},
			Ignore:    model.Ignore{Roles: []string{".*"}, Databases: []string{".*"}, Schemas: []string{`is_analytics\.staging`}},
		}
		out := converge(t, d, desired, diff.Options{Prune: true})
		if !strings.Contains(out, `schema "staging" in database "is_app"`) || strings.Contains(out, `"is_analytics"`) {
			t.Errorf("plan:\n%s", out)
		}
		cur, err := d.Inspect(t.Context(), desired)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, sc := range cur.Schemas {
			if sc.Name == "staging" {
				got = append(got, sc.Database)
			}
		}
		if !slices.Equal(got, []string{"is_analytics"}) {
			t.Errorf("databases with schema staging = %v, want [is_analytics]", got)
		}
	})

	t.Run("statements without effect fail", func(t *testing.T) {
		s.exec(t, "CREATE ROLE w_grp", "CREATE ROLE w_u", "GRANT w_grp TO w_u")
		d := s.open(t, "postgres")
		// A repeated GRANT only raises a NOTICE.
		if err := d.Exec(t.Context(), "", `GRANT "w_grp" TO "w_u"`); err != nil {
			t.Errorf("repeated grant: %v", err)
		}
		err := d.Exec(t.Context(), "", `REVOKE "w_grp" FROM "w_u" GRANTED BY "w_grp"`)
		if err == nil || !strings.Contains(err.Error(), "has not been granted membership") {
			t.Errorf("no-op revoke: %v", err)
		}
	})

	t.Run("PUBLIC privileges", func(t *testing.T) {
		s.exec(t, "CREATE ROLE pub_owner", "CREATE ROLE pub_u LOGIN PASSWORD 'pw'", "CREATE DATABASE pub_db OWNER pub_owner")
		d := s.open(t, "postgres")
		db := model.Object{Type: model.ObjectDatabase, Database: "pub_db"}
		public := model.Object{Type: model.ObjectSchema, Database: "pub_db", Schema: "public"}
		pubPriv := func(obj model.Object, names ...string) []model.Privilege {
			var out []model.Privilege
			for _, n := range names {
				out = append(out, model.Privilege{Grantee: model.PublicRole, Object: obj, Name: n})
			}
			return out
		}
		desired := func(name string, privs []model.Privilege, objs ...model.Object) *model.Desired {
			return &model.Desired{
				Engine:        model.EnginePostgres,
				Roles:         []model.Role{{ID: pg("pub_owner")}, {ID: pg("pub_u")}},
				Databases:     []model.Database{{Name: name, Owner: "pub_owner"}},
				Schemas:       []model.Schema{{Database: name, Name: "public"}},
				Privileges:    privs,
				PublicObjects: objs,
			}
		}
		has := func(t *testing.T, q string) string {
			t.Helper()
			return strings.Join(s.queryStrings(t, q), ",")
		}

		// A NULL datacl means the defaults, which PUBLIC holds too.
		cur, err := d.Inspect(t.Context(), desired("pub_db", nil))
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, p := range cur.Privileges {
			if p.Grantee.IsPublic() && (p.Object == db || p.Object == public) {
				got = append(got, p.Object.String()+":"+p.Name)
			}
		}
		slices.Sort(got)
		if want := []string{"pub_db.public:USAGE", "pub_db:CONNECT", "pub_db:TEMPORARY"}; !slices.Equal(got, want) {
			t.Errorf("inspected PUBLIC privileges = %v, want %v", got, want)
		}

		// privileges = [] revokes every privilege of PUBLIC.
		text := converge(t, d, desired("pub_db", nil, db, public), diff.Options{})
		for _, w := range []string{`REVOKE CONNECT, TEMPORARY ON DATABASE "pub_db" FROM PUBLIC`, `REVOKE USAGE ON SCHEMA "public" FROM PUBLIC`} {
			if !strings.Contains(text, w) {
				t.Errorf("plan lacks %q:\n%s", w, text)
			}
		}
		if got := has(t, "SELECT has_database_privilege('pub_u', 'pub_db', 'CONNECT')::text || has_database_privilege('pub_u', 'pub_db', 'TEMP')::text"); got != "falsefalse" {
			t.Errorf("pub_u CONNECT, TEMP = %s, want falsefalse", got)
		}

		// Declared privileges are granted back.
		text = converge(t, d, desired("pub_db", pubPriv(db, "CONNECT"), db, public), diff.Options{})
		if !strings.Contains(text, `GRANT CONNECT ON DATABASE "pub_db" TO PUBLIC`) {
			t.Errorf("plan lacks the grant to PUBLIC:\n%s", text)
		}
		if got := has(t, "SELECT has_database_privilege('pub_u', 'pub_db', 'CONNECT')::text"); got != "true" {
			t.Errorf("pub_u CONNECT = %s, want true", got)
		}

		// A database created by the plan converges in one apply.
		privs := append(pubPriv(model.Object{Type: model.ObjectDatabase, Database: "pub_new"}, "CONNECT"),
			pubPriv(model.Object{Type: model.ObjectSchema, Database: "pub_new", Schema: "public"}, "USAGE")...)
		converge(t, d, desired("pub_new", privs, privs[0].Object, privs[1].Object), diff.Options{})
		if got := has(t, "SELECT has_database_privilege('pub_u', 'pub_new', 'CONNECT')::text || has_database_privilege('pub_u', 'pub_new', 'TEMP')::text"); got != "truefalse" {
			t.Errorf("pub_u CONNECT, TEMP on pub_new = %s, want truefalse", got)
		}
		converge(t, d, desired("pub_new2", nil, model.Object{Type: model.ObjectDatabase, Database: "pub_new2"},
			model.Object{Type: model.ObjectSchema, Database: "pub_new2", Schema: "public"}), diff.Options{})
		if got := has(t, "SELECT has_database_privilege('pub_u', 'pub_new2', 'CONNECT')::text"); got != "false" {
			t.Errorf("pub_u CONNECT on pub_new2 = %s, want false", got)
		}
	})

	t.Run("exec errors carry detail", func(t *testing.T) {
		s.exec(t, "CREATE ROLE detail_owner", "CREATE DATABASE detail_db OWNER detail_owner")
		d := s.open(t, "postgres")
		err := d.Exec(t.Context(), "", "DROP ROLE detail_owner")
		if err == nil || !strings.Contains(err.Error(), "DETAIL: owner of database detail_db") {
			t.Errorf("error = %v", err)
		}
	})
}
