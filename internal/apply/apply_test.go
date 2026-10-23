package apply

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/plan"
)

type recorder struct {
	ran    []string
	failAt int
}

func (r *recorder) Exec(_ context.Context, database, query string) error {
	r.ran = append(r.ran, database+"|"+query)
	if len(r.ran) == r.failAt {
		return errors.New("syntax error near " + query)
	}
	return nil
}

func testPlan() *plan.Plan {
	return &plan.Plan{Changes: []plan.Change{
		{Action: plan.ActionCreate, Resource: `role "a"`, Statements: []plan.Statement{
			plan.SQL("", `CREATE ROLE "a" WITH PASSWORD `, plan.Secret("'hunter2'")),
		}},
		{Action: plan.ActionCreate, Resource: `schema "s"`, Statements: []plan.Statement{
			plan.SQL("app", `CREATE SCHEMA "s"`),
		}},
	}}
}

func TestRun(t *testing.T) {
	t.Parallel()
	r := &recorder{}
	var out strings.Builder
	if err := Run(t.Context(), r, testPlan(), &out, false); err != nil {
		t.Fatal(err)
	}
	want := []string{`|CREATE ROLE "a" WITH PASSWORD 'hunter2'`, `app|CREATE SCHEMA "s"`}
	if strings.Join(r.ran, "\n") != strings.Join(want, "\n") {
		t.Errorf("executed %q, want %q", r.ran, want)
	}
	if strings.Contains(out.String(), "hunter2") {
		t.Errorf("output leaked the secret: %s", out.String())
	}
}

func TestRunStopsAndRedactsErrors(t *testing.T) {
	t.Parallel()
	r := &recorder{failAt: 1}
	var out strings.Builder
	err := Run(t.Context(), r, testPlan(), &out, false)
	if err == nil {
		t.Fatal("Run() succeeded")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("error leaked the secret: %v", err)
	}
	if !strings.Contains(err.Error(), "0 of 2 statements applied") {
		t.Errorf("err = %v", err)
	}
	if len(r.ran) != 1 {
		t.Errorf("continued after failure: %q", r.ran)
	}
}
