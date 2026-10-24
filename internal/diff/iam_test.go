package diff_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/driver/mysql"
	"github.com/mazrean/dbfence/internal/driver/postgres"
	"github.com/mazrean/dbfence/internal/model"
)

// TestComputeAWSIAM checks that an aws_iam role is a member of rds_iam on
// PostgreSQL, whether or not it manages member_of.
func TestComputeAWSIAM(t *testing.T) {
	t.Parallel()
	rdsIAM := pgID("rds_iam")
	login := true
	tests := []struct {
		name     string
		memberOf []model.RoleID
		have     []model.RoleID
		want     []string
		exists   bool
	}{
		{
			name: "new user",
			want: []string{`CREATE ROLE "app" WITH LOGIN`, `GRANT "rds_iam" TO "app"`},
		},
		{
			name: "existing user without member_of keeps its memberships", exists: true, have: []model.RoleID{pgID("g")},
			want: []string{`GRANT "rds_iam" TO "app"`},
		},
		{name: "converged without member_of", exists: true, have: []model.RoleID{pgID("g"), rdsIAM}},
		{
			name: "member_of does not revoke rds_iam", exists: true, memberOf: []model.RoleID{pgID("g")}, have: []model.RoleID{pgID("g"), rdsIAM},
		},
		{
			name: "member_of is still complete", exists: true, memberOf: []model.RoleID{}, have: []model.RoleID{pgID("g")},
			want: []string{`GRANT "rds_iam" TO "app"`, `REVOKE "g" FROM "app"`},
		},
		{name: "rds_iam listed in member_of too", exists: true, memberOf: []model.RoleID{rdsIAM}, have: []model.RoleID{rdsIAM}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cur := &model.Current{CurrentUser: pgID("admin"), Roles: []model.RoleState{
				{ID: pgID("admin"), Superuser: true, Login: true}, {ID: pgID("g")}, {ID: rdsIAM},
			}}
			if tt.exists {
				cur.Roles = append(cur.Roles, model.RoleState{ID: pgID("app"), Login: true, MemberOf: tt.have})
			}
			desired := &model.Desired{Engine: model.EnginePostgres, Ignore: model.Ignore{Roles: []string{"admin", "g"}}, Roles: []model.Role{
				{ID: pgID("app"), Login: &login, IAM: model.AuthAWSIAM, MemberOf: tt.memberOf},
			}}
			p, err := compute(t, desired, cur, postgres.Dialect{}, diff.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(tt.want, statements(p), cmpopts.EquateEmpty()); d != "" {
				t.Errorf("statements (-want +got):\n%s", d)
			}
			if len(p.Warnings) != 0 {
				t.Errorf("warnings = %q, want none", p.Warnings)
			}
			if desired.Roles[0].MemberOf != nil && len(desired.Roles[0].MemberOf) != len(tt.memberOf) {
				t.Errorf("Compute changed the desired member_of: %v", desired.Roles[0].MemberOf)
			}
		})
	}
}

func TestComputeAWSIAMWithoutRDSIAM(t *testing.T) {
	t.Parallel()
	login := true
	cur := &model.Current{CurrentUser: pgID("admin"), Roles: []model.RoleState{{ID: pgID("admin"), Superuser: true, Login: true}}}
	desired := &model.Desired{Engine: model.EnginePostgres, Roles: []model.Role{{ID: pgID("app"), Login: &login, IAM: model.AuthAWSIAM}}}
	_, err := compute(t, desired, cur, postgres.Dialect{}, diff.Options{})
	if err == nil || !strings.Contains(err.Error(), `user "app" aws_iam needs role "rds_iam", which does not exist`) {
		t.Errorf("err = %v, want the missing rds_iam", err)
	}
}

// TestComputeAWSIAMMySQL checks that MySQL needs no membership: the
// authentication plugin is enough.
func TestComputeAWSIAMMySQL(t *testing.T) {
	t.Parallel()
	login := true
	app := model.RoleID{Name: "app", Host: "%"}
	admin := model.RoleID{Name: "admin", Host: "%"}
	cur := &model.Current{CurrentUser: admin, Roles: []model.RoleState{{ID: admin, Login: true, PasswordReadable: true}}}
	desired := &model.Desired{Engine: model.EngineMySQL, Ignore: model.Ignore{Roles: []string{"admin"}}, Roles: []model.Role{{ID: app, Login: &login, IAM: model.AuthAWSIAM}}}
	p, err := compute(t, desired, cur, mysql.Dialect{}, diff.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if d := cmp.Diff([]string{"CREATE USER 'app'@'%' IDENTIFIED WITH AWSAuthenticationPlugin AS 'RDS'"}, statements(p)); d != "" {
		t.Errorf("statements (-want +got):\n%s", d)
	}
}
