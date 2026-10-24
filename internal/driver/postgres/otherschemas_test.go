package postgres

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/mazrean/dbfence/internal/model"
)

// TestOtherSchemaDatabases checks which undeclared databases Inspect reads
// schema owners from: those where DropRole runs REASSIGN OWNED.
func TestOtherSchemaDatabases(t *testing.T) {
	t.Parallel()
	cur := &model.Current{Databases: []model.Database{
		{Name: "app"}, {Name: "legacy"}, {Name: "noconnect"}, {Name: "postgres"}, {Name: "scratch_1"},
	}}
	connectable := map[string]bool{"app": true, "legacy": true, "postgres": true, "scratch_1": true}
	tests := []struct {
		name     string
		ignoreDB []string
		want     []string
	}{
		{name: "undeclared connectable databases", want: []string{"legacy", "postgres", "scratch_1"}},
		{name: "ignored databases are skipped", ignoreDB: []string{"scratch_.*"}, want: []string{"legacy", "postgres"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			desired := &model.Desired{
				Engine:    model.EnginePostgres,
				Databases: []model.Database{{Name: "app"}},
				Ignore:    model.Ignore{Databases: tt.ignoreDB, Schemas: []string{"monitoring"}},
			}
			got := otherSchemaDatabases(desired, cur, connectable)
			if d := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); d != "" {
				t.Errorf("databases (-want +got):\n%s", d)
			}
		})
	}
}
