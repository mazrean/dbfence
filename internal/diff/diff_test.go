package diff_test

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/driver/mysql"
	"github.com/mazrean/dbfence/internal/driver/postgres"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/password"
	"github.com/mazrean/dbfence/internal/plan"
)

func pgID(n string) model.RoleID { return model.RoleID{Name: n} }

func dbObj(db string) model.Object { return model.Object{Type: model.ObjectDatabase, Database: db} }

func statements(p *plan.Plan) []string {
	out := []string{}
	for _, s := range p.Statements() {
		prefix := ""
		if s.Database != "" {
			prefix = s.Database + ": "
		}
		out = append(out, prefix+s.Display(false))
	}
	return out
}

func scram(t *testing.T, pw string) []byte {
	t.Helper()
	salt := []byte("saltsaltsaltsalt")
	key, err := password.SCRAMStoredKey(pw, salt, 4096)
	if err != nil {
		t.Fatal(err)
	}
	return []byte("SCRAM-SHA-256$4096:" + base64.StdEncoding.EncodeToString(salt) + "$" + base64.StdEncoding.EncodeToString(key) + ":" + base64.StdEncoding.EncodeToString(make([]byte, 32)))
}

func pgDesired() *model.Desired {
	return &model.Desired{
		Engine: model.EnginePostgres,
		Roles: []model.Role{
			{ID: pgID("owner"), Login: new(false)},
			{ID: pgID("app"), Login: new(true), Password: new("pw"), MemberOf: []model.RoleID{pgID("owner")}},
		},
		Databases: []model.Database{{Name: "app", Owner: "owner"}},
		Schemas:   []model.Schema{{Database: "app", Name: "api", Owner: "owner"}},
		Privileges: []model.Privilege{
			{Grantee: pgID("app"), Object: dbObj("app"), Name: "CONNECT"},
			{Grantee: pgID("app"), Object: model.Object{Type: model.ObjectSchema, Database: "app", Schema: "api"}, Name: "USAGE"},
		},
	}
}

// pgMatching returns a current state that matches pgDesired.
func pgMatching(t *testing.T) *model.Current {
	t.Helper()
	return &model.Current{
		CurrentUser: pgID("admin"),
		Roles: []model.RoleState{
			{ID: pgID("admin"), Login: true, Superuser: true},
			{ID: pgID("postgres"), Login: true, Superuser: true},
			{ID: pgID("pg_read_all_data")},
			{ID: pgID("owner"), PasswordReadable: true},
			{ID: pgID("app"), Login: true, MemberOf: []model.RoleID{pgID("owner")}, PasswordHash: scram(t, "pw"), PasswordReadable: true},
		},
		Databases: []model.Database{{Name: "postgres", Owner: "postgres"}, {Name: "app", Owner: "owner"}},
		Schemas:   []model.Schema{{Database: "app", Name: "public", Owner: "pg_database_owner"}, {Database: "app", Name: "api", Owner: "owner"}},
		Privileges: []model.Privilege{
			{Grantee: pgID("owner"), Object: dbObj("app"), Name: "CONNECT", GrantOption: true},
			{Grantee: pgID("owner"), Object: dbObj("app"), Name: "CREATE", GrantOption: true},
			{Grantee: pgID("app"), Object: dbObj("app"), Name: "CONNECT"},
			{Grantee: pgID("app"), Object: model.Object{Type: model.ObjectSchema, Database: "app", Schema: "api"}, Name: "USAGE"},
			// Not managed: undeclared role and undeclared database.
			{Grantee: pgID("other"), Object: dbObj("app"), Name: "CONNECT"},
			{Grantee: pgID("app"), Object: dbObj("postgres"), Name: "CONNECT"},
		},
		InspectedDatabases: []string{"app"},
	}
}

func TestComputeCreateAll(t *testing.T) {
	t.Parallel()
	cur := &model.Current{CurrentUser: pgID("postgres"), Roles: []model.RoleState{{ID: pgID("postgres")}}, Databases: []model.Database{{Name: "postgres"}}}
	p, err := diff.Compute(pgDesired(), cur, postgres.Dialect{}, diff.Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`CREATE ROLE "owner" WITH NOLOGIN`,
		`CREATE ROLE "app" WITH LOGIN PASSWORD '<redacted>'`,
		`GRANT "owner" TO "app"`,
		`CREATE DATABASE "app" OWNER "owner"`,
		`app: CREATE SCHEMA "api" AUTHORIZATION "owner"`,
		`GRANT CONNECT ON DATABASE "app" TO "app"`,
		`app: GRANT USAGE ON SCHEMA "api" TO "app"`,
	}
	if d := cmp.Diff(want, statements(p)); d != "" {
		t.Errorf("statements (-want +got):\n%s", d)
	}
	if len(p.Warnings) != 0 {
		t.Errorf("warnings = %v", p.Warnings)
	}
}

func TestComputeNoChanges(t *testing.T) {
	t.Parallel()
	p, err := diff.Compute(pgDesired(), pgMatching(t), postgres.Dialect{}, diff.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Empty() {
		t.Errorf("expected no changes, got %v", statements(p))
	}
	if len(p.Warnings) != 0 {
		t.Errorf("warnings = %v", p.Warnings)
	}
}

func TestComputeDrift(t *testing.T) {
	t.Parallel()
	cur := pgMatching(t)
	cur.Roles[4].Login = false
	cur.Roles[4].ConnectionLimit = 3
	cur.Roles[4].MemberOf = []model.RoleID{pgID("owner"), pgID("postgres")}
	cur.Schemas[1].Owner = "app"
	cur.Databases[1].Owner = "app"
	cur.Privileges = append(cur.Privileges,
		model.Privilege{Grantee: pgID("app"), Object: dbObj("app"), Name: "TEMPORARY"},
	)
	cur.Privileges[2].GrantOption = true

	d := pgDesired()
	d.Roles[1].ConnectionLimit = new(-1)
	p, err := diff.Compute(d, cur, postgres.Dialect{}, diff.Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`ALTER ROLE "app" WITH LOGIN CONNECTION LIMIT -1`,
		`REVOKE "postgres" FROM "app"`,
		`ALTER DATABASE "app" OWNER TO "owner"`,
		`app: ALTER SCHEMA "api" OWNER TO "owner"`,
		// ALTER ... OWNER TO moves the ACL entries of the old owner "app"
		// to "owner", so the declared privileges are granted again.
		`GRANT CONNECT ON DATABASE "app" TO "app"`,
		`app: GRANT USAGE ON SCHEMA "api" TO "app"`,
	}
	if d := cmp.Diff(want, statements(p)); d != "" {
		t.Errorf("statements (-want +got):\n%s", d)
	}
}

func TestComputeUnmanaged(t *testing.T) {
	t.Parallel()
	cur := pgMatching(t)
	cur.Roles = append(cur.Roles, model.RoleState{ID: pgID("stray")}, model.RoleState{ID: pgID("datadog")}, model.RoleState{ID: pgID("rds_superuser")})
	cur.Databases = append(cur.Databases, model.Database{Name: "legacy"})
	cur.Schemas = append(cur.Schemas, model.Schema{Database: "app", Name: "junk"})
	d := pgDesired()
	d.Ignore.Roles = []string{"data.*"}

	p, err := diff.Compute(d, cur, postgres.Dialect{}, diff.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Empty() {
		t.Errorf("warn mode must not change anything, got %v", statements(p))
	}
	wantWarn := []string{
		`unmanaged database "legacy" (use --prune to drop it)`,
		`unmanaged schema "junk" in database "app" (use --prune to drop it)`,
		`unmanaged role "stray" (use --prune to drop it)`,
	}
	if diff := cmp.Diff(wantWarn, p.Warnings); diff != "" {
		t.Errorf("warnings (-want +got):\n%s", diff)
	}

	p, err = diff.Compute(d, cur, postgres.Dialect{}, diff.Options{Prune: true})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`app: DROP SCHEMA "junk"`,
		`DROP DATABASE "legacy"`,
		`app: REASSIGN OWNED BY "stray" TO CURRENT_USER`,
		`app: DROP OWNED BY "stray"`,
		`postgres: REASSIGN OWNED BY "stray" TO CURRENT_USER`,
		`postgres: DROP OWNED BY "stray"`,
		`DROP ROLE "stray"`,
	}
	if d := cmp.Diff(want, statements(p)); d != "" {
		t.Errorf("statements (-want +got):\n%s", d)
	}
}

func TestComputePassword(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		wantWarn  string
		hash      []byte
		wantStmts int
		readable  bool
		force     bool
	}{
		{name: "match", hash: nil, readable: true, force: false, wantStmts: 0, wantWarn: ""},
		{name: "mismatch", hash: []byte("md5" + strings.Repeat("0", 32)), readable: true, force: false, wantStmts: 1, wantWarn: ""},
		{name: "no verifier", hash: []byte(""), readable: true, force: false, wantStmts: 1, wantWarn: ""},
		{name: "unreadable", hash: nil, readable: false, force: false, wantStmts: 0, wantWarn: "cannot read the password verifier"},
		{name: "unreadable forced", hash: nil, readable: false, force: true, wantStmts: 1, wantWarn: ""},
		{name: "match forced", hash: nil, readable: true, force: true, wantStmts: 1, wantWarn: ""},
		{name: "unknown format", hash: []byte("plain"), readable: true, force: false, wantStmts: 0, wantWarn: "cannot compare the password"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cur := pgMatching(t)
			if tt.hash != nil {
				cur.Roles[4].PasswordHash = tt.hash
			}
			cur.Roles[4].PasswordReadable = tt.readable
			p, err := diff.Compute(pgDesired(), cur, postgres.Dialect{}, diff.Options{ForcePassword: tt.force})
			if err != nil {
				t.Fatal(err)
			}
			if got := len(p.Statements()); got != tt.wantStmts {
				t.Errorf("statements = %v, want %d", statements(p), tt.wantStmts)
			}
			if tt.wantStmts == 1 {
				if got, want := statements(p)[0], `ALTER ROLE "app" WITH PASSWORD '<redacted>'`; got != want {
					t.Errorf("statement = %s, want %s", got, want)
				}
			}
			gotWarn := strings.Join(p.Warnings, "\n")
			if (tt.wantWarn == "") != (gotWarn == "") || !strings.Contains(gotWarn, tt.wantWarn) {
				t.Errorf("warnings = %q, want %q", gotWarn, tt.wantWarn)
			}
		})
	}
}

func TestComputeMissingReference(t *testing.T) {
	t.Parallel()
	d := pgDesired()
	d.Roles[1].MemberOf = []model.RoleID{pgID("ghost")}
	_, err := diff.Compute(d, pgMatching(t), postgres.Dialect{}, diff.Options{})
	if err == nil || !strings.Contains(err.Error(), `role "ghost"`) {
		t.Errorf("err = %v", err)
	}
}

func TestComputeMySQL(t *testing.T) {
	t.Parallel()
	app := model.RoleID{Name: "app", Host: "%"}
	reader := model.RoleID{Name: "reader", Host: "%"}
	d := &model.Desired{
		Engine: model.EngineMySQL,
		Roles: []model.Role{
			{ID: reader, Login: new(false)},
			{ID: app, Login: new(true), Password: new(`p'w\`), AuthPlugin: password.PluginCachingSHA2, MemberOf: []model.RoleID{reader}},
		},
		Databases: []model.Database{{Name: "app", Charset: "utf8mb4"}},
		Privileges: []model.Privilege{
			{Grantee: app, Object: dbObj("app"), Name: "INSERT"},
			{Grantee: app, Object: dbObj("app"), Name: "SELECT"},
		},
	}
	root := model.RoleID{Name: "root", Host: "localhost"}
	cur := &model.Current{
		CurrentUser: root,
		Roles:       []model.RoleState{{ID: root, Login: true}, {ID: model.RoleID{Name: "mysql.sys", Host: "localhost"}}},
		Databases:   []model.Database{{Name: "mysql"}, {Name: "sys"}},
	}
	p, err := diff.Compute(d, cur, mysql.Dialect{}, diff.Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`CREATE USER 'reader'@'%' ACCOUNT LOCK`,
		`CREATE USER 'app'@'%' IDENTIFIED WITH caching_sha2_password BY '<redacted>'`,
		`GRANT 'reader'@'%' TO 'app'@'%'`,
		`SET DEFAULT ROLE 'reader'@'%' TO 'app'@'%'`,
		"CREATE DATABASE `app` CHARACTER SET utf8mb4",
		"GRANT INSERT, SELECT ON `app`.* TO 'app'@'%'",
	}
	if diff := cmp.Diff(want, statements(p)); diff != "" {
		t.Errorf("statements (-want +got):\n%s", diff)
	}
	if got, want := p.Statements()[1].SQL(), `CREATE USER 'app'@'%' IDENTIFIED WITH caching_sha2_password BY 'p''w\\'`; got != want {
		t.Errorf("SQL() = %s, want %s", got, want)
	}

	// Converged state: native password hash matches, privileges present.
	salt := "abcdefghij0123456789"
	cur.Roles = append(cur.Roles,
		model.RoleState{ID: reader},
		model.RoleState{ID: app, Login: true, AuthPlugin: password.PluginCachingSHA2, MemberOf: []model.RoleID{reader}, DefaultRoles: []model.RoleID{reader}, PasswordReadable: true,
			PasswordHash: []byte("$A$005$" + salt + string(password.SHA256Crypt([]byte(`p'w\`), []byte(salt), 5000)))},
	)
	cur.Databases = append(cur.Databases, model.Database{Name: "app", Charset: "utf8mb4", Collation: "utf8mb4_0900_ai_ci"})
	cur.Privileges = []model.Privilege{
		{Grantee: app, Object: dbObj("app"), Name: "INSERT"},
		{Grantee: app, Object: dbObj("app"), Name: "SELECT"},
		{Grantee: app, Object: dbObj("app"), Name: "DELETE", GrantOption: true},
	}
	p, err = diff.Compute(d, cur, mysql.Dialect{}, diff.Options{})
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"REVOKE DELETE ON `app`.* FROM 'app'@'%'"}
	if diff := cmp.Diff(want, statements(p)); diff != "" {
		t.Errorf("statements (-want +got):\n%s", diff)
	}
}

func TestComputeMySQLUnreadable(t *testing.T) {
	t.Parallel()
	app := model.RoleID{Name: "app", Host: "%"}
	reader := model.RoleID{Name: "reader", Host: "%"}
	desired := func() *model.Desired {
		return &model.Desired{
			Engine: model.EngineMySQL,
			Roles: []model.Role{
				{ID: reader, Login: new(false)},
				{ID: app, Login: new(true), Password: new("pw"), MemberOf: []model.RoleID{reader}},
			},
			Databases:  []model.Database{{Name: "app"}},
			Privileges: []model.Privilege{{Grantee: app, Object: dbObj("app"), Name: "SELECT"}},
		}
	}
	me := model.RoleID{Name: "dbfence", Host: "%"}
	tests := []struct {
		current   *model.Current
		name      string
		want      []string
		wantWarns []string
		opts      diff.Options
	}{
		{
			name: "accounts listed without credentials",
			current: &model.Current{
				CurrentUser: me,
				Roles: []model.RoleState{
					{ID: me, AttributesUnknown: true},
					{ID: model.RoleID{Name: "mysql.sys", Host: "localhost"}, AttributesUnknown: true},
					{ID: app, AttributesUnknown: true},
					{ID: model.RoleID{Name: "stray", Host: "%"}, AttributesUnknown: true},
				},
				Databases:  []model.Database{{Name: "app"}},
				Unreadable: model.Unreadable{RoleAttributes: true, Memberships: true, Privileges: true},
			},
			want: []string{
				`CREATE USER 'reader'@'%' ACCOUNT LOCK`,
				`GRANT 'reader'@'%' TO 'app'@'%'`,
				`SET DEFAULT ROLE 'reader'@'%' TO 'app'@'%'`,
				"GRANT SELECT ON `app`.* TO 'app'@'%'",
			},
			wantWarns: []string{"cannot read login state", "cannot read role memberships", "cannot read privileges", `unmanaged role "stray"@"%"`},
		},
		{
			name: "forced password with unknown credentials",
			current: &model.Current{
				CurrentUser: me,
				Roles:       []model.RoleState{{ID: me, AttributesUnknown: true}, {ID: reader, AttributesUnknown: true}, {ID: app, AttributesUnknown: true, MemberOf: []model.RoleID{reader}, DefaultRoles: []model.RoleID{reader}}},
				Databases:   []model.Database{{Name: "app"}},
				Privileges:  []model.Privilege{{Grantee: app, Object: dbObj("app"), Name: "SELECT"}},
				Unreadable:  model.Unreadable{RoleAttributes: true},
			},
			opts:      diff.Options{ForcePassword: true},
			want:      []string{`ALTER USER 'app'@'%' IDENTIFIED BY '<redacted>'`},
			wantWarns: []string{"cannot read login state"},
		},
		{
			name: "accounts cannot be listed",
			current: &model.Current{
				CurrentUser: me,
				Databases:   []model.Database{{Name: "app"}, {Name: "legacy"}},
				Privileges:  []model.Privilege{{Grantee: app, Object: dbObj("app"), Name: "DELETE"}},
				Unreadable:  model.Unreadable{Roles: true, RoleAttributes: true},
			},
			opts: diff.Options{Prune: true},
			want: []string{
				`CREATE USER IF NOT EXISTS 'reader'@'%' ACCOUNT LOCK`,
				`CREATE USER IF NOT EXISTS 'app'@'%' IDENTIFIED BY '<redacted>'`,
				`GRANT 'reader'@'%' TO 'app'@'%'`,
				`SET DEFAULT ROLE 'reader'@'%' TO 'app'@'%'`,
				"GRANT SELECT ON `app`.* TO 'app'@'%'",
				"REVOKE DELETE ON `app`.* FROM 'app'@'%'",
				"DROP DATABASE `legacy`",
			},
			wantWarns: []string{"cannot list roles", "cannot read login state", "cannot read role memberships"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := diff.Compute(desired(), tt.current, mysql.Dialect{}, tt.opts)
			if err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(tt.want, statements(p)); d != "" {
				t.Errorf("statements (-want +got):\n%s", d)
			}
			if len(p.Warnings) != len(tt.wantWarns) {
				t.Errorf("warnings = %q, want %d", p.Warnings, len(tt.wantWarns))
			}
			for _, w := range tt.wantWarns {
				if !slices.ContainsFunc(p.Warnings, func(got string) bool { return strings.Contains(got, w) }) {
					t.Errorf("missing warning %q in %q", w, p.Warnings)
				}
			}
		})
	}
}
