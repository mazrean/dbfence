package password_test

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/mazrean/dbfence/internal/password"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

// The oracle tests let real servers hash a corpus of passwords and check
// that the matchers accept exactly those passwords. Generating and
// matching verifiers share code (SASLprep, SHA256Crypt), so tests that
// compare dbfence with itself cannot find a wrong normalization or hash;
// only the servers can.

// corpusPieces are fragments that exercise SASLprep and the hashes:
// ASCII specials, compatibility characters, combining marks (also in runs
// longer than the 30 that the stream-safe format limits), Hangul jamo,
// characters mapped to nothing or to a space, bidi text, prohibited and
// unassigned code points.
var corpusPieces = []string{
	"a", "Z", "9", " ", "'", `\`, `"`, "%", "_", "$", "@", ":",
	"\u00E4", "a\u0308", "e\u0301\u0327", "\u212B", "\uFB01", "\u2168", "\uFF21", "\uFF76\uFF9E", "\u2460",
	"\u0301", "\u0316", strings.Repeat("\u0301", 40), strings.Repeat("\u0301\u0316", 20),
	"\u1100\u1161\u11A8", "\uAC01",
	"\u00AD", "\u200B", "\u034F", "\uFEFF", "\u00A0", "\u3000", "\u2003",
	"\u05D0", "\u05D01\u05D1", "\u0627\u0644",
	"\u0001", "\u007F", "\uE000", "\U0001F511", "\u0221",
	"\u1D2C", "\u03F9", "\u0340", "\u0341",
}

// corpus returns n deterministic passwords built from corpusPieces.
func corpus(n int) []string {
	out := make([]string, 0, n+len(corpusPieces))
	out = append(out, corpusPieces...)
	for i := range n {
		var sb strings.Builder
		for j := range 1 + i%5 {
			sb.WriteString(corpusPieces[(i*31+j*17+i/7)%len(corpusPieces)])
		}
		out = append(out, sb.String())
	}
	return out
}

func startServer(t *testing.T, opts *dockertest.RunOptions, port, sqlDriver string, dsn func(hostPort string) string) *sql.DB {
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
	res, err := pool.RunWithOptions(opts, func(hc *docker.HostConfig) {
		hc.AutoRemove = true
		hc.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		t.Fatalf("start %s:%s: %v", opts.Repository, opts.Tag, err)
	}
	t.Cleanup(func() { _ = pool.Purge(res) })
	_ = res.Expire(600)
	db, err := sql.Open(sqlDriver, dsn(res.GetHostPort(port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := pool.Retry(func() error { return db.PingContext(t.Context()) }); err != nil {
		t.Fatalf("%s did not become ready: %v", opts.Repository, err)
	}
	return db
}

func TestPostgresOracle(t *testing.T) {
	t.Parallel()
	db := startServer(t, &dockertest.RunOptions{Repository: "postgres", Tag: "17", Env: []string{"POSTGRES_PASSWORD=postgres"}},
		"5432/tcp", "pgx", func(hp string) string { return "postgres://postgres:postgres@" + hp + "/postgres?sslmode=disable" })
	db.SetMaxOpenConns(1) // keep SET password_encryption on one session
	for _, enc := range []string{"scram-sha-256", "md5"} {
		if _, err := db.ExecContext(t.Context(), "SET password_encryption = '"+enc+"'"); err != nil {
			t.Fatal(err)
		}
		for i, pw := range corpus(150) {
			if strings.ContainsRune(pw, 0) {
				continue
			}
			user := fmt.Sprintf("o_%s_%d", enc[:3], i)
			if _, err := db.ExecContext(t.Context(), fmt.Sprintf(`CREATE ROLE %s PASSWORD '%s'`, user, strings.ReplaceAll(pw, "'", "''"))); err != nil {
				t.Fatalf("create role for %+q: %v", pw, err)
			}
			var verifier string
			if err := db.QueryRowContext(t.Context(), "SELECT rolpassword FROM pg_authid WHERE rolname = $1", user).Scan(&verifier); err != nil {
				t.Fatal(err)
			}
			if got := password.PostgresVerifierKind(verifier); string(got) != enc {
				t.Fatalf("%s verifier kind = %q", enc, got)
			}
			if ok, err := password.MatchPostgres(verifier, user, pw); err != nil || !ok {
				t.Errorf("%s: MatchPostgres(%+q) = %v, %v; want true", enc, pw, ok, err)
			}
			if ok, _ := password.MatchPostgres(verifier, user, pw+"x"); ok {
				t.Errorf("%s: MatchPostgres(%+q) matches a different password", enc, pw)
			}
		}
	}
}

func TestMySQLOracle(t *testing.T) {
	t.Parallel()
	db := startServer(t, &dockertest.RunOptions{
		Repository: "mysql", Tag: "8.4", Env: []string{"MYSQL_ROOT_PASSWORD=root"},
		Cmd: []string{"--mysql-native-password=ON"},
	}, "3306/tcp", "mysql", func(hp string) string { return "root:root@tcp(" + hp + ")/?charset=utf8mb4&interpolateParams=true" })
	for _, plugin := range []string{password.PluginCachingSHA2, password.PluginSHA256, password.PluginNative} {
		for i, pw := range corpus(150) {
			if strings.ContainsRune(pw, 0) {
				continue
			}
			user := fmt.Sprintf("o_%s_%d", plugin[:3], i)
			if _, err := db.ExecContext(t.Context(), fmt.Sprintf("CREATE USER '%s'@'%%' IDENTIFIED WITH %s BY ?", user, plugin), pw); err != nil {
				t.Fatalf("create user for %+q: %v", pw, err)
			}
			var auth []byte
			if err := db.QueryRowContext(t.Context(), "SELECT authentication_string FROM mysql.user WHERE user = ? AND host = '%'", user).Scan(&auth); err != nil {
				t.Fatal(err)
			}
			if ok, err := password.MatchMySQL(plugin, auth, pw); err != nil || !ok {
				t.Errorf("%s: MatchMySQL(%+q) = %v, %v; want true", plugin, pw, ok, err)
			}
			if ok, _ := password.MatchMySQL(plugin, auth, pw+"x"); ok {
				t.Errorf("%s: MatchMySQL(%+q) matches a different password", plugin, pw)
			}
		}
	}
}
