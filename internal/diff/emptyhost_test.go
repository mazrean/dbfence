package diff_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/driver/mysql"
	"github.com/mazrean/dbfence/internal/model"
)

// TestComputeMySQLEmptyHost checks that an inspected MySQL account with an
// empty host is shown as "name"@"" and matched by "name@" ignore patterns.
func TestComputeMySQLEmptyHost(t *testing.T) {
	t.Parallel()
	root := model.RoleID{Name: "root", Host: "localhost"}
	anon := model.RoleID{Name: "anon", Host: ""}
	tests := []struct {
		name         string
		ignore       []string
		wantChanges  []string
		wantWarnings []string
		prune        bool
	}{
		{
			name:         "warned without prune",
			wantChanges:  []string{},
			wantWarnings: []string{`unmanaged role "anon"@"" (use --prune to drop it)`},
		},
		{
			name:         "dropped with prune",
			prune:        true,
			wantChanges:  []string{`[drop] user "anon"@""`},
			wantWarnings: nil,
		},
		{
			name:         "ignored by name@",
			ignore:       []string{"anon@"},
			prune:        true,
			wantChanges:  []string{},
			wantWarnings: nil,
		},
		{
			name:         "not ignored by name@%",
			ignore:       []string{"anon@%"},
			prune:        true,
			wantChanges:  []string{`[drop] user "anon"@""`},
			wantWarnings: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			desired := &model.Desired{Engine: model.EngineMySQL, Ignore: model.Ignore{Roles: tt.ignore}}
			current := &model.Current{
				CurrentUser: root,
				Roles:       []model.RoleState{{ID: root, Login: true}, {ID: anon, Login: true}},
			}
			p, err := diff.Compute(desired, current, mysql.Dialect{}, diff.Options{Prune: tt.prune})
			if err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(tt.wantChanges, resources(p)); d != "" {
				t.Errorf("changes (-want +got):\n%s", d)
			}
			if d := cmp.Diff(tt.wantWarnings, p.Warnings); d != "" {
				t.Errorf("warnings (-want +got):\n%s", d)
			}
			if tt.prune && len(p.Changes) > 0 {
				if got, want := p.Changes[0].Statements[0].SQL(), "DROP USER 'anon'@''"; got != want {
					t.Errorf("statement = %q, want %q", got, want)
				}
			}
		})
	}
}
