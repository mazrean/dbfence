package mysql

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mazrean/dbfence/internal/model"
)

func TestCreateDatabase(t *testing.T) {
	t.Parallel()
	tests := []struct {
		db   model.Database
		want string
	}{
		{db: model.Database{Name: "a"}, want: "CREATE DATABASE `a`"},
		{db: model.Database{Name: "a", Charset: "utf8mb4", Collation: "utf8mb4_bin"}, want: "CREATE DATABASE `a` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"},
		{db: model.Database{Name: "a", Charset: "utf8mb4; DROP DATABASE prod; --"}, want: "CREATE DATABASE `a` CHARACTER SET `utf8mb4; DROP DATABASE prod; --`"},
		{db: model.Database{Name: "a", Collation: "x` COLLATE y"}, want: "CREATE DATABASE `a` COLLATE `x`` COLLATE y`"},
	}
	for _, tt := range tests {
		if got := sqls(Dialect{}.CreateDatabase(tt.db)); got[0] != tt.want {
			t.Errorf("CreateDatabase(%+v) = %s, want %s", tt.db, got[0], tt.want)
		}
	}
}

func TestAlterDatabase(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		db   model.Database
		cur  model.Database
		want []string
	}{
		{
			name: "utf8 alias",
			db:   model.Database{Name: "a", Charset: "utf8", Collation: "utf8_general_ci"},
			cur:  model.Database{Name: "a", Charset: "utf8mb3", Collation: "utf8mb3_general_ci"},
		},
		{
			name: "case",
			db:   model.Database{Name: "a", Charset: "UTF8MB4", Collation: "UTF8MB4_BIN"},
			cur:  model.Database{Name: "a", Charset: "utf8mb4", Collation: "utf8mb4_bin"},
		},
		{
			name: "changed",
			db:   model.Database{Name: "a", Charset: "utf8"},
			cur:  model.Database{Name: "a", Charset: "utf8mb4"},
			want: []string{"ALTER DATABASE `a` CHARACTER SET utf8"},
		},
		{
			name: "utf8mb4 is not utf8",
			db:   model.Database{Name: "a", Collation: "utf8mb4_bin"},
			cur:  model.Database{Name: "a", Collation: "utf8mb3_bin"},
			want: []string{"ALTER DATABASE `a` COLLATE utf8mb4_bin"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stmts, _ := Dialect{}.AlterDatabase(tt.db, tt.cur)
			if d := cmp.Diff(tt.want, sqls(stmts)); d != "" {
				t.Errorf("statements (-want +got):\n%s", d)
			}
		})
	}
}
