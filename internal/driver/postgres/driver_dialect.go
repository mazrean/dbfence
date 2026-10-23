package postgres

import (
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
)

// The Driver overrides some Dialect methods with variants that use the
// state captured by Inspect. Without a prior Inspect they behave like
// Dialect.

// DropRole implements diff.Dialect. Databases that cannot be connected to
// are skipped.
func (d *Driver) DropRole(id model.RoleID, databases []string) []plan.Statement {
	if d.st == nil {
		return d.Dialect.DropRole(id, databases)
	}
	var reachable []string
	for _, db := range databases {
		if d.st.connectable[db] {
			reachable = append(reachable, db)
		}
	}
	return d.Dialect.DropRole(id, reachable)
}
