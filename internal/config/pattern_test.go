package config

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mazrean/dbfence/internal/model"
)

func TestLoadDatabasePattern(t *testing.T) {
	t.Parallel()
	app := model.RoleID{Name: "app", Host: "%"}
	tests := []struct {
		name string
		src  string
		want []model.Privilege
	}{
		{
			name: "escaped underscore and percent",
			src:  "grant {\n role = user.app.id\n database_pattern = \"tenant\\\\_%\"\n privileges = [\"select\"]\n}",
			want: []model.Privilege{{Grantee: app, Object: model.Object{Type: model.ObjectDatabase, Pattern: `tenant\_%`}, Name: "SELECT"}},
		},
		{
			name: "pattern with grant option next to a database grant",
			src: "database \"app\" {}\n" +
				"grant {\n role = user.app.id\n database = database.app.name\n privileges = [\"SELECT\"]\n}\n" +
				"grant {\n role = user.app.id\n database_pattern = \"app_%\"\n privileges = [\"INSERT\"]\n with_grant_option = true\n}",
			want: []model.Privilege{
				{Grantee: app, Object: model.Object{Type: model.ObjectDatabase, Database: "app"}, Name: "SELECT"},
				{Grantee: app, Object: model.Object{Type: model.ObjectDatabase, Pattern: "app_%"}, Name: "INSERT", GrantOption: true},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := load(t, myConn+"user \"app\" {\n password = \"pw\"\n}\n"+tt.src)
			if err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(tt.want, cfg.Desired.Privileges); d != "" {
				t.Errorf("Privileges (-want +got):\n%s", d)
			}
		})
	}
}

func TestLoadDatabasePatternErrors(t *testing.T) {
	t.Parallel()
	user := "user \"app\" {\n password = \"pw\"\n}\n"
	grant := func(target string) string {
		return user + "grant {\n role = user.app.id\n " + target + "\n privileges = [\"SELECT\"]\n}\n"
	}
	runDiagCases(t, []diagCase{
		{name: "postgres", src: pgConn + grant(`database_pattern = "app_%"`), want: []string{`"database_pattern" is only supported for mysql`}, count: 1},
		{name: "both database and pattern", src: myConn + "database \"app\" {}\n" + grant("database = \"app\"\n database_pattern = \"app_%\""), want: []string{`either "database" or "database_pattern"`}, count: 1},
		{name: "neither", src: myConn + grant(""), want: []string{`needs "database" or "database_pattern"`}, count: 1},
		{name: "no wildcard", src: myConn + grant(`database_pattern = "app\\_x"`), want: []string{`has no unescaped "%" or "_"`, "use database"}, count: 1},
		{name: "too long", src: myConn + grant(`database_pattern = "`+strings.Repeat("a", 64)+`%"`), want: []string{"longer than 64 characters"}, count: 1},
		{
			name: "mixed grant option on one pattern",
			src: myConn + user +
				"grant {\n role = user.app.id\n database_pattern = \"app_%\"\n privileges = [\"SELECT\"]\n}\n" +
				"grant {\n role = user.app.id\n database_pattern = \"app_%\"\n privileges = [\"INSERT\"]\n with_grant_option = true\n}\n",
			want:  []string{`on database pattern "app_%" must use the same with_grant_option`},
			count: 1,
		},
	})
}
