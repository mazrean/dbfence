package funcs

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

type fakeGCP struct {
	names []string
}

func (f *fakeGCP) AccessSecretVersion(_ context.Context, name string) (string, error) {
	f.names = append(f.names, name)
	return "payload:" + name, nil
}

func eval(t *testing.T, r *Registry, expr string) (cty.Value, error) {
	t.Helper()
	e, diags := hclsyntax.ParseExpression([]byte(expr), "test.hcl", hcl.InitialPos)
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	v, diags := e.Value(&hcl.EvalContext{Functions: r.Functions()})
	if diags.HasErrors() {
		return cty.NilVal, diags
	}
	return v, nil
}

func newTestRegistry(t *testing.T) (*Registry, *fakeGCP) {
	t.Helper()
	gcp := &fakeGCP{}
	env := map[string]string{"SET": "value", "EMPTY": ""}
	r := NewRegistry(t.Context(),
		WithEnv(func(k string) (string, bool) { v, ok := env[k]; return v, ok }),
		WithGCP(gcp))
	return r, gcp
}

func TestFunctions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		expr    string
		want    cty.Value
		wantErr string
	}{
		{"env set", `env("SET")`, cty.StringVal("value"), ""},
		{"env empty is set", `env("EMPTY", "d")`, cty.StringVal(""), ""},
		{"env default", `env("UNSET", "d")`, cty.StringVal("d"), ""},
		{"env unset", `env("UNSET")`, cty.NilVal, `"UNSET" is not set`},
		{"gcp latest", `gcp_secretmanager("projects/p/secrets/s")`, cty.StringVal("payload:projects/p/secrets/s/versions/latest"), ""},
		{"gcp version", `gcp_secretmanager("projects/p/secrets/s", "3")`, cty.StringVal("payload:projects/p/secrets/s/versions/3"), ""},
		{"gcp full name", `gcp_secretmanager("projects/p/secrets/s/versions/2")`, cty.StringVal("payload:projects/p/secrets/s/versions/2"), ""},
		{"gcp twice", `gcp_secretmanager("projects/p/secrets/s/versions/2", "3")`, cty.NilVal, "version given twice"},
		{"gcp bad name", `gcp_secretmanager("s")`, cty.NilVal, "must look like"},
		{"tfstate attribute", `tfstate("testdata/terraform.tfstate", "aws_db_instance.main.address")`, cty.StringVal("main.rds.amazonaws.com"), ""},
		{"tfstate output", `tfstate("testdata/terraform.tfstate", "output.db_host")`, cty.StringVal("db.internal"), ""},
		{"tfstate number", `tfstate("testdata/terraform.tfstate", "aws_db_instance.main.port")`, cty.NumberIntVal(5432), ""},
		{"tfstate missing", `tfstate("testdata/terraform.tfstate", "aws_db_instance.nope.address")`, cty.NilVal, "not found"},
		{"stdlib format", `format("%s-%d", "a", 1)`, cty.StringVal("a-1"), ""},
		{"base64", `base64decode(base64encode("x"))`, cty.StringVal("x"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, _ := newTestRegistry(t)
			got, err := eval(t, r, tt.expr)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !got.RawEquals(tt.want) {
				t.Errorf("got %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestGCPSecretsAreCached(t *testing.T) {
	t.Parallel()
	r, gcp := newTestRegistry(t)
	for range 3 {
		if _, err := eval(t, r, `gcp_secretmanager("projects/p/secrets/s")`); err != nil {
			t.Fatal(err)
		}
	}
	if len(gcp.names) != 1 {
		t.Errorf("gcp calls = %v, want 1", gcp.names)
	}
}
