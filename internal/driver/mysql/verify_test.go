package mysql

import (
	"testing"

	"github.com/mazrean/dbfence/internal/diff"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/plan"
	"github.com/mazrean/dbfence/internal/policy"
)

// compute is diff.Compute followed by the independent safety check: every
// plan the driver tests produce must pass it.
func compute(t *testing.T, desired *model.Desired, current *model.Current, d diff.Dialect, opts diff.Options) (*plan.Plan, error) {
	t.Helper()
	p, err := diff.Compute(desired, current, d, opts)
	if err != nil {
		return p, err
	}
	for _, v := range policy.Verify(p, current, desired, policy.Options{System: d, Prune: opts.Prune}) {
		t.Errorf("safety check: %s", v)
	}
	return p, nil
}
