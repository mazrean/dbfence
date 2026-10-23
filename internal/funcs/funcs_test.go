package funcs

import (
	"context"
	"path/filepath"
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
	if strings.HasSuffix(name, "/binary/versions/latest") {
		return "\xff\xfe", nil
	}
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
		{"gcp version alias", `gcp_secretmanager("projects/p/secrets/s", "latest")`, cty.StringVal("payload:projects/p/secrets/s/versions/latest"), ""},
		{"gcp empty version", `gcp_secretmanager("projects/p/secrets/s", "")`, cty.NilVal, "version must be a non-empty"},
		{"gcp version with slash", `gcp_secretmanager("projects/p/secrets/s", "1/x")`, cty.NilVal, "version must be a non-empty"},
		{"gcp trailing slash", `gcp_secretmanager("projects/p/secrets/s/", "3")`, cty.NilVal, "must look like"},
		{"gcp empty secret", `gcp_secretmanager("projects/p/secrets/")`, cty.NilVal, "must look like"},
		{"gcp empty project", `gcp_secretmanager("projects//secrets/s")`, cty.NilVal, "must look like"},
		{"gcp empty version in name", `gcp_secretmanager("projects/p/secrets/s/versions/")`, cty.NilVal, "must look like"},
		{"gcp extra segment", `gcp_secretmanager("projects/p/secrets/s/versions/1/x")`, cty.NilVal, "must look like"},
		{"gcp regional", `gcp_secretmanager("projects/p/locations/l/secrets/s")`, cty.NilVal, "regional secrets"},
		{"gcp project named locations", `gcp_secretmanager("projects/locations/secrets/s")`, cty.StringVal("payload:projects/locations/secrets/s/versions/latest"), ""},
		{"gcp project named versions", `gcp_secretmanager("projects/versions/secrets/s", "2")`, cty.StringVal("payload:projects/versions/secrets/s/versions/2"), ""},
		{"tfstate attribute", `tfstate("testdata/terraform.tfstate", "aws_db_instance.main.address")`, cty.StringVal("main.rds.amazonaws.com"), ""},
		{"tfstate output", `tfstate("testdata/terraform.tfstate", "output.db_host")`, cty.StringVal("db.internal"), ""},
		{"tfstate number", `tfstate("testdata/terraform.tfstate", "aws_db_instance.main.port")`, cty.NumberIntVal(5432), ""},
		{"tfstate missing", `tfstate("testdata/terraform.tfstate", "aws_db_instance.nope.address")`, cty.NilVal, "not found"},
		{"stdlib format", `format("%s-%d", "a", 1)`, cty.StringVal("a-1"), ""},
		{"base64", `base64decode(base64encode("x"))`, cty.StringVal("x"), ""},
		{"base64 invalid utf-8", `base64decode("/w==")`, cty.NilVal, "not valid UTF-8"},
		{"gcp invalid utf-8", `gcp_secretmanager("projects/p/secrets/binary")`, cty.NilVal, `"projects/p/secrets/binary/versions/latest" is not valid UTF-8`},
		{"tonumber", `tonumber("12")`, cty.NumberIntVal(12), ""},
		{"tonumber invalid", `tonumber("x")`, cty.NilVal, "cannot convert value to number"},
		{"tonumber object", `tonumber({a = 1})`, cty.NilVal, "cannot convert object to number"},
		{"jsondecode", `jsondecode("{\"a\":1}").a`, cty.NumberIntVal(1), ""},
		{"jsondecode invalid", `jsondecode("{x")`, cty.NilVal, "not valid JSON"},
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

// Errors must never quote secret material passed to a function.
func TestFunctionErrorsDoNotLeakValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		expr string
	}{
		{"tonumber", `tonumber(env("SECRET"))`},
		{"jsondecode first char", `jsondecode(env("SECRET"))`},
		{"jsondecode inner", `jsondecode("{\"a\": ${env("SECRET")}}")`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := NewRegistry(t.Context(), WithEnv(func(string) (string, bool) { return "qs3cr3t", true }))
			_, err := eval(t, r, tt.expr)
			if err == nil {
				t.Fatal("want error")
			}
			if strings.Contains(err.Error(), "qs3cr3t") || strings.Contains(err.Error(), "'q'") || strings.Contains(err.Error(), `"q"`) {
				t.Errorf("error leaks the value: %v", err)
			}
		})
	}
}

func TestJSONKey(t *testing.T) {
	t.Parallel()
	doc := `{"s":"p@ss","big":12345678901234567890,"f":1e21,"neg":-0.5,"b":true,"n":null,"o":{"a":"<&>"},"a":[1]}`
	tests := []struct {
		name    string
		doc     string
		key     string
		want    string
		wantErr string
	}{
		{"string", doc, "s", "p@ss", ""},
		{"big integer keeps precision", doc, "big", "12345678901234567890", ""},
		{"exponent kept as written", doc, "f", "1e21", ""},
		{"negative float", doc, "neg", "-0.5", ""},
		{"bool", doc, "b", "true", ""},
		{"null", doc, "n", "", `key "n" in secret "id" is null`},
		{"object", doc, "o", "", "use jsondecode"},
		{"array", doc, "a", "", "use jsondecode"},
		{"missing", doc, "x", "", `key "x" not found in secret "id"`},
		{"not json", "xSECRET", "k", "", `secret "id" is not a JSON object`},
		{"json array", `["xSECRET"]`, "k", "", `secret "id" is not a JSON object`},
		{"json string", `"xSECRET"`, "k", "", `secret "id" is not a JSON object`},
		{"json null", `null`, "k", "", `secret "id" is not a JSON object`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := jsonKey("id", tt.doc, tt.key)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "'x'") {
					t.Errorf("error leaks the secret: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.AsString() != tt.want {
				t.Errorf("got %q, want %q", got.AsString(), tt.want)
			}
		})
	}
}

func TestResolvePathsFrom(t *testing.T) {
	t.Parallel()
	abs, err := filepath.Abs("testdata/terraform.tfstate")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		dir     string
		expr    string
		want    cty.Value
		wantErr string
	}{
		{"relative to dir", "testdata", `tfstate("terraform.tfstate", "output.db_host")`, cty.StringVal("db.internal"), ""},
		{"dot dir", ".", `tfstate("testdata/terraform.tfstate", "output.db_host")`, cty.StringVal("db.internal"), ""},
		{"absolute path kept", "elsewhere", `tfstate("` + abs + `", "output.db_host")`, cty.StringVal("db.internal"), ""},
		{"error shows resolved path", "testdata", `tfstate("none.tfstate", "output.db_host")`, cty.NilVal, filepath.Join(filepath.Dir(abs), "none.tfstate")},
		{"url not rewritten", "testdata", `tfstate("file:///nonexistent/terraform.tfstate", "output.db_host")`, cty.NilVal, "/nonexistent/terraform.tfstate"},
		{"other functions kept", "testdata", `upper("a")`, cty.StringVal("A"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, _ := newTestRegistry(t)
			e, diags := hclsyntax.ParseExpression([]byte(tt.expr), "test.hcl", hcl.InitialPos)
			if diags.HasErrors() {
				t.Fatal(diags)
			}
			got, diags := e.Value(&hcl.EvalContext{Functions: ResolvePathsFrom(r.Functions(), tt.dir)})
			if tt.wantErr != "" {
				if !diags.HasErrors() || !strings.Contains(diags.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", diags, tt.wantErr)
				}
				return
			}
			if diags.HasErrors() {
				t.Fatal(diags)
			}
			if !got.RawEquals(tt.want) {
				t.Errorf("got %#v, want %#v", got, tt.want)
			}
		})
	}
}
