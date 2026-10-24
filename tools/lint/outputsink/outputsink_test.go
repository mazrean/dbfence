package outputsink_test

import (
	"testing"

	"github.com/mazrean/dbfence/tools/lint/outputsink"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestAnalyzer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		pkg  string
	}{
		{name: "reports bypasses outside test files", pkg: "a"},
		{name: "allows the wiring file", pkg: "sink/internal/di"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			analysistest.Run(t, analysistest.TestData(), outputsink.Analyzer, tt.pkg)
		})
	}
}
