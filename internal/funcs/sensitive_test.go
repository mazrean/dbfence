package funcs

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

type fakeTFState struct{ json string }

func (f fakeTFState) Lookup(context.Context, string, string) ([]byte, error) {
	return []byte(f.json), nil
}

// TestSecretCollectionElementsStayHidden checks that elements of a secret
// collection keep Sensitive when for and splat expressions bind them, so
// neither function errors nor HCL's "with v as ..." line print them.
func TestSecretCollectionElementsStayHidden(t *testing.T) {
	t.Parallel()
	const secret = "s3cr3t-pw"
	tests := []struct {
		name string
		expr string
	}{
		{"for over jsondecode(secretenv)", `[for p in jsondecode(secretenv("LIST")) : tonumber(p)]`},
		{"for over object values", `[for k, p in jsondecode(secretenv("OBJ")) : tonumber(p)]`},
		{"for over nested list", `[for l in jsondecode(secretenv("NESTED")) : [for p in l : tonumber(p)]]`},
		{"splat over jsondecode(secretenv)", `[for p in jsondecode(secretenv("LIST"))[*] : tonumber(p)]`},
		{"for over tfstate", `[for p in tfstate("terraform.tfstate", "output.passwords") : tonumber(p)]`},
		{"for over tfstate into jsondecode", `[for p in tfstate("terraform.tfstate", "output.passwords") : jsondecode(p)]`},
	}
	env := map[string]string{
		"LIST":   `["` + secret + `"]`,
		"OBJ":    `{"a": "` + secret + `"}`,
		"NESTED": `[["` + secret + `"]]`,
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := NewRegistry(t.Context(),
				WithEnv(func(k string) (string, bool) { v, ok := env[k]; return v, ok }),
				WithTFState(fakeTFState{json: `["` + secret + `"]`}))
			e, diags := hclsyntax.ParseExpression([]byte(tt.expr), "test.hcl", hcl.InitialPos)
			if diags.HasErrors() {
				t.Fatal(diags)
			}
			_, diags = e.Value(&hcl.EvalContext{Functions: r.Functions()})
			if !diags.HasErrors() {
				t.Fatal("want an error")
			}
			var sb strings.Builder
			files := map[string]*hcl.File{"test.hcl": {Bytes: []byte(tt.expr)}}
			if err := hcl.NewDiagnosticTextWriter(&sb, files, 0, false).WriteDiagnostics(diags); err != nil {
				t.Fatal(err)
			}
			out := sb.String()
			if strings.Contains(out, secret) {
				t.Errorf("diagnostics leak the secret:\n%s", out)
			}
			if !strings.Contains(out, secretErrorMessage) {
				t.Errorf("diagnostics = %s, want %q", out, secretErrorMessage)
			}
		})
	}
}
