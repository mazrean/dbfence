package funcs

import (
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zclconf/go-cty/cty"
)

// envRegistry returns a Registry whose env() reads only from vars, so test
// inputs reach HCL without any string-literal escaping.
func envRegistry(t *testing.T, vars map[string]string) *Registry {
	t.Helper()
	return NewRegistry(t.Context(), WithEnv(func(k string) (string, bool) {
		v, ok := vars[k]
		return v, ok
	}))
}

func TestURLEncode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"unreserved", "abcXYZ019-._~", "abcXYZ019-._~"},
		{"space", "a b", "a%20b"},
		{"plus", "a+b", "a%2Bb"},
		{"userinfo delimiters", "@:/?#", "%40%3A%2F%3F%23"},
		{"percent", "100%", "100%25"},
		{"brackets and query delimiters", "[]&=;", "%5B%5D%26%3D%3B"},
		{"template sequences", "${x}%{y}", "%24%7Bx%7D%25%7By%7D"},
		{"unicode", "パス", "%E3%83%91%E3%82%B9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := eval(t, envRegistry(t, map[string]string{"IN": tt.in}), `urlencode(env("IN"))`)
			if err != nil {
				t.Fatal(err)
			}
			if !got.RawEquals(cty.StringVal(tt.want)) {
				t.Errorf("urlencode(%q) = %#v, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestURLEncodePostgresDSNRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		user     string
		password string
	}{
		{"all delimiters", "admin", "p@ss:w/o?r#d%+ x"},
		{"leading and trailing space", "admin", " pw "},
		{"percent escape lookalike", "admin", "%41%2B"},
		{"plus only", "admin", "+++"},
		{"user with delimiters", "ad@m:in", "pw"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := envRegistry(t, map[string]string{"USER": tt.user, "PW": tt.password})
			dsn, err := eval(t, r, `format("postgres://%s:%s@db.internal:5432/app?sslmode=disable", urlencode(env("USER")), urlencode(env("PW")))`)
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := pgconn.ParseConfig(dsn.AsString())
			if err != nil {
				t.Fatalf("ParseConfig: %v", err)
			}
			if cfg.User != tt.user {
				t.Errorf("user = %q, want %q", cfg.User, tt.user)
			}
			if cfg.Password != tt.password {
				t.Errorf("password did not round-trip (got %d bytes, want %d)", len(cfg.Password), len(tt.password))
			}
			if cfg.Host != "db.internal" || cfg.Port != 5432 || cfg.Database != "app" {
				t.Errorf("host/port/database = %q/%d/%q", cfg.Host, cfg.Port, cfg.Database)
			}
		})
	}
}
