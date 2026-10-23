// Package funcs provides the HCL functions available in dbfence
// configuration files.
package funcs

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

// AWSSecretsManager fetches a secret string by id.
type AWSSecretsManager interface {
	GetSecretString(ctx context.Context, secretID string) (string, error)
}

// GCPSecretManager fetches a secret payload by version resource name.
type GCPSecretManager interface {
	AccessSecretVersion(ctx context.Context, name string) (string, error)
}

// TFState looks up an address in a tfstate located at url and returns
// its value as JSON.
type TFState interface {
	Lookup(ctx context.Context, url, address string) ([]byte, error)
}

// Registry builds the function table. Backends are created lazily so
// that configurations that do not use them need no credentials.
type Registry struct {
	ctx     context.Context
	tfstate TFState
	lookup  func(string) (string, bool)
	aws     func(context.Context) (AWSSecretsManager, error)
	gcp     func(context.Context) (GCPSecretManager, error)
	cache   map[string]cty.Value
	mu      sync.Mutex
}

// Option configures a Registry.
type Option func(*Registry)

// WithEnv replaces the environment lookup.
func WithEnv(lookup func(string) (string, bool)) Option {
	return func(r *Registry) { r.lookup = lookup }
}

// WithAWS replaces the AWS Secrets Manager client.
func WithAWS(c AWSSecretsManager) Option {
	return func(r *Registry) {
		r.aws = func(context.Context) (AWSSecretsManager, error) { return c, nil }
	}
}

// WithGCP replaces the GCP Secret Manager client.
func WithGCP(c GCPSecretManager) Option {
	return func(r *Registry) {
		r.gcp = func(context.Context) (GCPSecretManager, error) { return c, nil }
	}
}

// WithTFState replaces the tfstate reader.
func WithTFState(t TFState) Option {
	return func(r *Registry) { r.tfstate = t }
}

// NewRegistry returns a Registry backed by the real cloud SDKs unless
// overridden by options.
func NewRegistry(ctx context.Context, opts ...Option) *Registry {
	r := &Registry{
		ctx:     ctx,
		lookup:  os.LookupEnv,
		aws:     onceClient(newAWSSecretsManager),
		gcp:     onceClient(newGCPSecretManager),
		tfstate: newTFStateReader(),
		cache:   map[string]cty.Value{},
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

func onceClient[T any](f func(context.Context) (T, error)) func(context.Context) (T, error) {
	var (
		once sync.Once
		c    T
		err  error
	)
	return func(ctx context.Context) (T, error) {
		once.Do(func() { c, err = f(ctx) })
		return c, err
	}
}

// Functions returns the function table including the cty stdlib.
func (r *Registry) Functions() map[string]function.Function {
	fns := map[string]function.Function{
		"env":                r.envFunc(),
		"aws_secretsmanager": r.awsFunc(),
		"gcp_secretmanager":  r.gcpFunc(),
		"tfstate":            r.tfstateFunc(),
	}
	maps.Copy(fns, stdlibFunctions())
	return fns
}

// ResolvePathsFrom returns fns with tfstate resolving a relative local
// path against dir (the configuration directory) instead of the working
// directory. URLs and absolute paths are left alone.
func ResolvePathsFrom(fns map[string]function.Function, dir string) map[string]function.Function {
	fn, ok := fns["tfstate"]
	if !ok {
		return fns
	}
	out := maps.Clone(fns)
	out["tfstate"] = function.New(&function.Spec{
		Description: fn.Description(),
		Params:      fn.Params(),
		VarParam:    fn.VarParam(),
		Type:        fn.ReturnTypeForValues,
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			args = slices.Clone(args)
			loc := args[0].AsString()
			if u, err := url.Parse(loc); err == nil && u.Scheme == "" && !filepath.IsAbs(loc) {
				abs, err := filepath.Abs(filepath.Join(dir, loc))
				if err != nil {
					return cty.NilVal, function.NewArgError(0, fmt.Errorf("resolve %q: %w", loc, err))
				}
				args[0] = cty.StringVal(abs)
			}
			return fn.Call(args)
		},
	})
	return out
}

func stdlibFunctions() map[string]function.Function {
	return map[string]function.Function{
		"abs":          stdlib.AbsoluteFunc,
		"base64decode": base64DecodeFunc,
		"base64encode": base64EncodeFunc,
		"chomp":        stdlib.ChompFunc,
		"coalesce":     stdlib.CoalesceFunc,
		"concat":       stdlib.ConcatFunc,
		"contains":     stdlib.ContainsFunc,
		"csvdecode":    stdlib.CSVDecodeFunc,
		"distinct":     stdlib.DistinctFunc,
		"flatten":      stdlib.FlattenFunc,
		"format":       stdlib.FormatFunc,
		"formatlist":   stdlib.FormatListFunc,
		"join":         stdlib.JoinFunc,
		"jsondecode":   withFixedError(stdlib.JSONDecodeFunc, "the given string is not valid JSON", true),
		"jsonencode":   stdlib.JSONEncodeFunc,
		"keys":         stdlib.KeysFunc,
		"length":       stdlib.LengthFunc,
		"lookup":       stdlib.LookupFunc,
		"lower":        stdlib.LowerFunc,
		"merge":        stdlib.MergeFunc,
		"regex":        stdlib.RegexFunc,
		"replace":      stdlib.ReplaceFunc,
		"split":        stdlib.SplitFunc,
		"substr":       stdlib.SubstrFunc,
		"tolist":       stdlib.MakeToFunc(cty.List(cty.DynamicPseudoType)),
		"tomap":        stdlib.MakeToFunc(cty.Map(cty.DynamicPseudoType)),
		"tonumber":     withFixedError(stdlib.MakeToFunc(cty.Number), "cannot convert value to number; given string must be a decimal representation of a number", false),
		"toset":        stdlib.MakeToFunc(cty.Set(cty.DynamicPseudoType)),
		"tostring":     stdlib.MakeToFunc(cty.String),
		"trimspace":    stdlib.TrimSpaceFunc,
		"upper":        stdlib.UpperFunc,
		"urlencode":    urlencodeFunc,
		"values":       stdlib.ValuesFunc,
	}
}

// cached memoizes fetches by key for the lifetime of the Registry.
func (r *Registry) cached(key string, fetch func() (cty.Value, error)) (cty.Value, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := r.cache[key]; ok {
		return v, nil
	}
	v, err := fetch()
	if err != nil {
		return cty.NilVal, err
	}
	r.cache[key] = v
	return v, nil
}

// maxArgs is the arity of functions taking one required and one optional argument.
const maxArgs = 2

func optionalString(args []cty.Value) (string, bool) {
	if len(args) == 0 || args[0].IsNull() {
		return "", false
	}
	return args[0].AsString(), true
}

func (r *Registry) envFunc() function.Function {
	return function.New(&function.Spec{
		Description: "Returns the value of an environment variable, or the default when unset.",
		Params:      []function.Parameter{{Name: "name", Type: cty.String}},
		VarParam:    &function.Parameter{Name: "default", Type: cty.String, AllowNull: true},
		Type:        function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			if len(args) > maxArgs {
				return cty.NilVal, function.NewArgErrorf(maxArgs, "env accepts at most one default")
			}
			name := args[0].AsString()
			if v, ok := r.lookup(name); ok {
				return cty.StringVal(v), nil
			}
			if def, ok := optionalString(args[1:]); ok {
				return cty.StringVal(def), nil
			}
			return cty.NilVal, function.NewArgErrorf(0, "environment variable %q is not set", name)
		},
	})
}

func (r *Registry) awsFunc() function.Function {
	return function.New(&function.Spec{
		Description: "Returns a secret from AWS Secrets Manager. With json_key, extracts that key from a JSON secret.",
		Params:      []function.Parameter{{Name: "secret_id", Type: cty.String}},
		VarParam:    &function.Parameter{Name: "json_key", Type: cty.String},
		Type:        function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			if len(args) > maxArgs {
				return cty.NilVal, function.NewArgErrorf(maxArgs, "aws_secretsmanager accepts at most one json_key")
			}
			id := args[0].AsString()
			v, err := r.cached("aws\x00"+id, func() (cty.Value, error) {
				c, err := r.aws(r.ctx)
				if err != nil {
					return cty.NilVal, fmt.Errorf("aws secrets manager client: %w", err)
				}
				s, err := c.GetSecretString(r.ctx, id)
				if err != nil {
					return cty.NilVal, fmt.Errorf("get secret %q: %w", id, err)
				}
				if !utf8.ValidString(s) {
					return cty.NilVal, fmt.Errorf("secret %q is not valid UTF-8", id)
				}
				return cty.StringVal(s), nil
			})
			if err != nil {
				return cty.NilVal, err
			}
			if key, ok := optionalString(args[1:]); ok {
				return jsonKey(id, v.AsString(), key)
			}
			return v, nil
		},
	})
}

// jsonKey extracts key from the JSON object doc. Strings are returned
// as is; numbers and booleans as their exact JSON text. Errors never
// quote doc, which holds secret material.
func jsonKey(id, doc, key string) (cty.Value, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(doc), &m); err != nil || m == nil {
		return cty.NilVal, fmt.Errorf("secret %q is not a JSON object", id)
	}
	raw, ok := m[key]
	if !ok {
		return cty.NilVal, fmt.Errorf("key %q not found in secret %q", key, id)
	}
	text := strings.TrimSpace(string(raw))
	switch {
	case text == "null":
		return cty.NilVal, fmt.Errorf("key %q in secret %q is null", key, id)
	case strings.HasPrefix(text, `"`):
		var v string
		if err := json.Unmarshal(raw, &v); err != nil {
			return cty.NilVal, fmt.Errorf("key %q in secret %q is not a valid JSON string", key, id)
		}
		return cty.StringVal(v), nil
	case strings.HasPrefix(text, "{"), strings.HasPrefix(text, "["):
		return cty.NilVal, fmt.Errorf("key %q in secret %q is an object or array, not a string; use jsondecode(aws_secretsmanager(%q)) instead", key, id, id)
	default: // number, true or false: keep the exact text, e.g. no float rounding.
		return cty.StringVal(text), nil
	}
}

func (r *Registry) gcpFunc() function.Function {
	return function.New(&function.Spec{
		Description: "Returns a secret payload from GCP Secret Manager. name is projects/<p>/secrets/<s>[/versions/<v>].",
		Params:      []function.Parameter{{Name: "name", Type: cty.String}},
		VarParam:    &function.Parameter{Name: "version", Type: cty.String},
		Type:        function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			if len(args) > maxArgs {
				return cty.NilVal, function.NewArgErrorf(maxArgs, "gcp_secretmanager accepts at most one version")
			}
			name, err := gcpVersionName(args[0].AsString(), args[1:])
			if err != nil {
				return cty.NilVal, err
			}
			return r.cached("gcp\x00"+name, func() (cty.Value, error) {
				c, err := r.gcp(r.ctx)
				if err != nil {
					return cty.NilVal, fmt.Errorf("gcp secret manager client: %w", err)
				}
				s, err := c.AccessSecretVersion(r.ctx, name)
				if err != nil {
					return cty.NilVal, fmt.Errorf("access secret %q: %w", name, err)
				}
				if !utf8.ValidString(s) {
					return cty.NilVal, fmt.Errorf("secret %q is not valid UTF-8", name)
				}
				return cty.StringVal(s), nil
			})
		},
	})
}

var (
	gcpSecretName  = regexp.MustCompile(`^projects/[^/]+/secrets/[^/]+(/versions/[^/]+)?$`)
	gcpVersionPart = regexp.MustCompile(`^[^/]+$`)
)

// gcpVersionName returns the version resource name, or a function.ArgError
// pointing at the offending argument.
func gcpVersionName(name string, rest []cty.Value) (string, error) {
	// Classify by segment: the project ID itself may be "locations" or
	// "versions".
	if seg := strings.Split(name, "/"); len(seg) > 2 && seg[0] == "projects" && seg[2] == "locations" {
		return "", function.NewArgErrorf(0, "regional secrets (projects/<project>/locations/<location>/...) are not supported, got %q", name)
	}
	m := gcpSecretName.FindStringSubmatch(name)
	if m == nil {
		return "", function.NewArgErrorf(0, "name must look like projects/<project>/secrets/<secret>[/versions/<version>], got %q", name)
	}
	version, hasVersion := optionalString(rest)
	if m[1] != "" {
		if hasVersion {
			return "", function.NewArgErrorf(0, "version given twice in %q", name)
		}
		return name, nil
	}
	if !hasVersion {
		return name + "/versions/latest", nil
	}
	if !gcpVersionPart.MatchString(version) {
		return "", function.NewArgErrorf(1, "version must be a non-empty version number or alias without \"/\", got %q", version)
	}
	return name + "/versions/" + version, nil
}

func (r *Registry) tfstateFunc() function.Function {
	return function.New(&function.Spec{
		Description: "Looks up a resource attribute or output in a Terraform state (s3://, gs://, file path, ...).",
		Params: []function.Parameter{
			{Name: "url", Type: cty.String},
			{Name: "address", Type: cty.String},
		},
		Type: function.StaticReturnType(cty.DynamicPseudoType),
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			url, addr := args[0].AsString(), args[1].AsString()
			return r.cached("tfstate\x00"+url+"\x00"+addr, func() (cty.Value, error) {
				b, err := r.tfstate.Lookup(r.ctx, url, addr)
				if err != nil {
					return cty.NilVal, err
				}
				ty, err := ctyjson.ImpliedType(b)
				if err != nil {
					return cty.NilVal, fmt.Errorf("tfstate value of %q: %w", addr, err)
				}
				return ctyjson.Unmarshal(b, ty)
			})
		},
	})
}
