package diff_test

import (
	"slices"
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

// TestComputeGCPIAM checks that a Cloud SQL IAM user is never created and
// keeps the memberships Cloud SQL granted it.
func TestComputeGCPIAM(t *testing.T) {
	t.Parallel()
	login := true
	sa := pgID("sa@p.iam")
	base := func() *model.Current {
		return &model.Current{CurrentUser: pgID("admin"), Roles: []model.RoleState{
			{ID: pgID("admin"), Superuser: true, Login: true}, {ID: pgID("g")}, {ID: pgID("cloudsqliamserviceaccount")}, {ID: pgID("cloudsqliamuser")},
		}}
	}
	desired := func(memberOf []model.RoleID) *model.Desired {
		return &model.Desired{Engine: model.EnginePostgres, Ignore: model.Ignore{Roles: []string{"admin", "g"}}, Roles: []model.Role{
			{ID: sa, Login: &login, IAM: model.AuthGCPIAM, MemberOf: memberOf},
		}}
	}

	t.Run("missing", func(t *testing.T) {
		t.Parallel()
		_, err := compute(t, desired(nil), base(), postgres.Dialect{}, diff.Options{})
		if err == nil || !strings.Contains(err.Error(), `user "sa@p.iam" gcp_iam: the Cloud SQL IAM user does not exist; create it with gcloud sql users create`) {
			t.Errorf("err = %v, want the missing IAM user", err)
		}
	})
	tests := []struct {
		name     string
		memberOf []model.RoleID
		have     []model.RoleID
		want     []string
	}{
		{name: "nothing granted without member_of", have: []model.RoleID{pgID("cloudsqliamserviceaccount")}},
		{
			name: "member_of keeps the Cloud SQL role", memberOf: []model.RoleID{pgID("g")}, have: []model.RoleID{pgID("cloudsqliamserviceaccount")},
			want: []string{`GRANT "g" TO "sa@p.iam"`},
		},
		{
			name: "member_of grants no Cloud SQL role", memberOf: []model.RoleID{}, have: []model.RoleID{pgID("g")},
			want: []string{`REVOKE "g" FROM "sa@p.iam"`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cur := base()
			cur.Roles = append(cur.Roles, model.RoleState{ID: sa, Login: true, MemberOf: tt.have})
			p, err := compute(t, desired(tt.memberOf), cur, postgres.Dialect{}, diff.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(tt.want, statements(p), cmpopts.EquateEmpty()); d != "" {
				t.Errorf("statements (-want +got):\n%s", d)
			}
			if len(p.Warnings) != 0 {
				t.Errorf("warnings = %q, want none", p.Warnings)
			}
		})
	}
}

// TestComputeGCPIAMUnlistedRoles checks that a Cloud SQL IAM user is not
// created when the roles cannot be listed (MySQL).
func TestComputeGCPIAMUnlistedRoles(t *testing.T) {
	t.Parallel()
	login := true
	app := model.RoleID{Name: "app", Host: "%"}
	cur := &model.Current{CurrentUser: model.RoleID{Name: "admin", Host: "%"}}
	cur.Unreadable.Roles = true
	desired := &model.Desired{Engine: model.EngineMySQL, Roles: []model.Role{{ID: app, Login: &login, IAM: model.AuthGCPIAM}}}
	p, err := compute(t, desired, cur, mysql.Dialect{}, diff.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := statements(p); len(got) != 0 {
		t.Errorf("statements = %q, want none", got)
	}
	if !slices.ContainsFunc(p.Warnings, func(w string) bool { return strings.Contains(w, `cannot check that the Cloud SQL IAM user "app"@"%" exists`) }) {
		t.Errorf("warnings = %q, want the unchecked IAM user", p.Warnings)
	}
}
