package app_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/app"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
)

const targetSrc = "user \"app\" {\n  name = \"App\"\n}\nrole \"ro\" {}\ndatabase \"main\" {\n  name = \"maindb\"\n}\nschema \"api\" {\n  database = database.main.name\n}\n"

func TestPlanTarget(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		wantErr string
		targets []string
		want    []string
		prune   bool
	}{
		{name: "role by user address", targets: []string{"role.app"}, want: []string{`CREATE ROLE "App" WITH LOGIN`}},
		{name: "role", targets: []string{"user.ro"}, want: []string{`CREATE ROLE "ro" WITH NOLOGIN`}},
		{name: "database", targets: []string{"database.main"}, want: []string{`CREATE DATABASE "maindb"`}},
		{name: "schema with its database", targets: []string{"schema.api"}, want: []string{`CREATE DATABASE "maindb"`, `CREATE SCHEMA "api"`}},
		{name: "several", targets: []string{"user.app", "role.ro"}, want: []string{`CREATE ROLE "ro" WITH NOLOGIN`, `CREATE ROLE "App" WITH LOGIN`}},
		{name: "name instead of label", targets: []string{"user.App"}, wantErr: `--target: "user.App" does not name a declared block`},
		{name: "grant", targets: []string{"grant"}, wantErr: `--target: "grant" does not name a declared block`},
		{name: "with prune", targets: []string{"user.app"}, prune: true, wantErr: "--prune cannot be combined with --target"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a, d, out, dir := newAppWith(t, "", targetSrc)
			p, err := a.Plan(t.Context(), app.Options{Dir: dir, Targets: tt.targets, Prune: tt.prune})
			if tt.wantErr != "" {
				if err == nil || !strings.HasPrefix(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, s := range p.Statements() {
				got = append(got, s.SQL())
			}
			if strings.Join(got, "\n") != strings.Join(tt.want, "\n") {
				t.Errorf("statements = %q, want %q", got, tt.want)
			}
			if !strings.Contains(out.String(), "-- warning: --target is in effect") || !strings.Contains(out.String(), "\nwarning: --target is in effect") {
				t.Errorf("no targeting warning on stdout and stderr:\n%s", out)
			}
			if len(d.executed) != 0 {
				t.Errorf("executed %v", d.executed)
			}
		})
	}
}

func TestApplyTarget(t *testing.T) {
	t.Parallel()
	a, d, _, dir := newAppWith(t, "", targetSrc)
	if err := a.Apply(t.Context(), app.Options{Dir: dir, Targets: []string{"role.ro"}, AutoApprove: true}); err != nil {
		t.Fatal(err)
	}
	if want := []string{`CREATE ROLE "ro" WITH NOLOGIN`}; strings.Join(d.executed, "\n") != strings.Join(want, "\n") {
		t.Errorf("executed %q, want %q", d.executed, want)
	}
}

// The full plan is safe, but the selection leaves out the membership that
// made a later revoke safe for the connected user.
func TestUnsafeTargetIsRefused(t *testing.T) {
	t.Parallel()
	pg, ops, dba := model.RoleID{Name: "postgres"}, model.RoleID{Name: "ops"}, model.RoleID{Name: "dba"}
	for _, cmd := range []string{"plan", "apply"} {
		a, d, out, dir := newAppWith(t, "yes\n", "role \"x\" {}\nrole \"y\" {}\n")
		d.memberOf = []model.RoleID{ops}
		d.extra = []model.RoleState{{ID: ops, MemberOf: []model.RoleID{dba}}, {ID: dba}}
		d.after = map[string][]plan.Statement{
			"x": {plan.New("", plan.KindGrantMembership, plan.MembershipTarget(pg, dba), plan.Keyword(`GRANT "dba" TO "postgres"`))},
			"y": {plan.New("", plan.KindRevokeMembership, plan.MembershipTarget(ops, dba), plan.Keyword(`REVOKE "dba" FROM "ops"`))},
		}
		if _, err := a.Plan(t.Context(), app.Options{Dir: dir}); err != nil {
			t.Fatalf("%s: full plan: %v", cmd, err)
		}
		var err error
		o := app.Options{Dir: dir, Targets: []string{"role.y"}}
		if cmd == "plan" {
			_, err = a.Plan(t.Context(), o)
		} else {
			err = a.Apply(t.Context(), o)
		}
		if !errors.Is(err, app.ErrUnsafeTarget) || !strings.HasSuffix(err.Error(), "; select more objects or run without --target") {
			t.Fatalf("%s: err = %v, want ErrUnsafeTarget", cmd, err)
		}
		if strings.Contains(out.String(), "Apply these changes?") || len(d.executed) != 0 {
			t.Errorf("%s: prompted or executed %v; output:\n%s", cmd, d.executed, out)
		}
	}
}
