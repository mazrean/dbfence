package sqlfragment_test

import (
	"testing"

	"github.com/mazrean/dbfence/tools/lint/sqlfragment"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestAnalyzer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		pkg  string
	}{
		{name: "rejects runtime strings as SQL text and constructors outside the drivers", pkg: "github.com/mazrean/dbfence/a"},
		{name: "allows constructors in a driver", pkg: "github.com/mazrean/dbfence/internal/driver/x"},
		{name: "rejects constructors in a package that only contains internal/driver in its path", pkg: "github.com/mazrean/dbfence/a/internal/driver/spoof"},
		{name: "allows constructors in the plan package", pkg: sqlfragment.PlanPath},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			analysistest.Run(t, analysistest.TestData(), sqlfragment.Analyzer, tt.pkg)
		})
	}
}
