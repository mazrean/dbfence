package postgres

import (
	"database/sql"
	"io"
	"net/url"
	"os"
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

	t.Run("exec errors carry detail", func(t *testing.T) {
		s.exec(t, "CREATE ROLE detail_owner", "CREATE DATABASE detail_db OWNER detail_owner")
		d := s.open(t, "postgres")
		err := d.Exec(t.Context(), "", "DROP ROLE detail_owner")
		if err == nil || !strings.Contains(err.Error(), "DETAIL: owner of database detail_db") {
			t.Errorf("error = %v", err)
		}
	})
}
