package mysql

import (
	"testing"

	"github.com/mazrean/dbfence/internal/model"
)

func TestIsSystemRole(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		want bool
	}{
		{"root", true},
		{"mysql.sys", true},
		{"mysql.custom", true},
		{"mariadb.sys", true},
		{"debian-sys-maint", true},
		{"rdsadmin", true},
		{"rdsproxyadmin", true},
		{"rds_superuser_role", true},
		{"AWS_LOAD_S3_ACCESS", true},
		{"AWS_BEDROCK_ACCESS", true},
		{"cloudsqlsuperuser", true},
		{"azure_superuser", true},
		{"app", false},
		{"mysql", false},
		{"rooted", false},
		{"my_rds", false},
	}
	for _, tt := range tests {
		if got := (Dialect{}).IsSystemRole(model.RoleID{Name: tt.name, Host: "%"}); got != tt.want {
			t.Errorf("IsSystemRole(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}
