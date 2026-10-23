package funcs

import (
	"context"
	"testing"

	"github.com/mazrean/dbfence/internal/secret"
)

type fakeAWS struct{ value string }

func (f fakeAWS) GetSecretString(context.Context, string) (string, error) { return f.value, nil }

// TestSecretSourcesRegisterResults checks that every string a secret
// source returns, nested ones included, is registered for redaction,
// while env results are not.
func TestSecretSourcesRegisterResults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		expr       string
		registered []string
		plain      []string
	}{
		{name: "secretenv", expr: `secretenv("PW")`, registered: []string{"reg-secretenv-value"}},
		{name: "env is not a secret source", expr: `env("PLAIN")`, plain: []string{"reg-env-unlisted"}},
		{name: "aws_secretsmanager json_key", expr: `aws_secretsmanager("id", "password")`, registered: []string{"reg-aws-password"}},
		{name: "aws_secretsmanager whole document", expr: `aws_secretsmanager("id2")`, registered: []string{`{"password": "reg-aws-doc"}`}},
		{name: "gcp_secretmanager", expr: `gcp_secretmanager("projects/p/secrets/reg-gcp")`, registered: []string{"payload:projects/p/secrets/reg-gcp/versions/latest"}},
		{name: "tfstate nested strings", expr: `tfstate("terraform.tfstate", "output.x")`, registered: []string{"reg-tf-inner", "reg-tf-list"}, plain: []string{"12345"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := map[string]string{"PW": "reg-secretenv-value", "PLAIN": "reg-env-unlisted"}
			aws := `{"password": "reg-aws-password"}`
			if tt.name == "aws_secretsmanager whole document" {
				aws = `{"password": "reg-aws-doc"}`
			}
			r := NewRegistry(t.Context(),
				WithEnv(func(k string) (string, bool) { v, ok := env[k]; return v, ok }),
				WithAWS(fakeAWS{value: aws}),
				WithGCP(&fakeGCP{}),
				WithTFState(fakeTFState{json: `{"a": {"b": "reg-tf-inner"}, "l": ["reg-tf-list"], "n": 12345}`}))
			if _, err := eval(t, r, tt.expr); err != nil {
				t.Fatal(err)
			}
			for _, s := range tt.registered {
				if got := secret.Default().Redact(s); got != secret.Placeholder {
					t.Errorf("Redact(%q) = %q, want it registered", s, got)
				}
			}
			for _, s := range tt.plain {
				if got := secret.Default().Redact(s); got != s {
					t.Errorf("Redact(%q) = %q, want it not registered", s, got)
				}
			}
		})
	}
}
