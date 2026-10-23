---
name: tech-tfstate-lookup
description: fujiwara/tfstate-lookup research digest (reading Terraform state from file/s3/gs and looking up resource attributes). Use when implementing the tfstate() HCL function in dbfence internal/funcs.
---

# tfstate-lookup — Research Digest

## TL;DR

`tfstate.ReadURL(ctx, url)` loads a state from local path, `s3://`, `gs://`, `azurerm://`, `http(s)://`
or `remote://`; `(*TFState).Lookup(address)` returns an `*Object` whose `Value any` is JSON-shaped.
We convert `Value` to cty via JSON. Credentials come from each cloud SDK's default chain.

## Identity

- **Version**: v1.12.1 (published 2026-05-17, verified 2026-10-23)
- **Docs**: https://pkg.go.dev/github.com/fujiwara/tfstate-lookup/tfstate
- **Source**: https://github.com/fujiwara/tfstate-lookup — License MPL-2.0

## API We Use

```go
func ReadURL(ctx context.Context, loc string, opts ...ReadURLOption) (*TFState, error)
func ReadFile(ctx context.Context, file string) (*TFState, error)
func (s *TFState) Lookup(key string) (*Object, error)
type Object struct{ Value any }   // + String(), Bytes(), Query(jq)
```

Address syntax: `aws_db_instance.main.address`, `module.db.aws_secretsmanager_secret.x.arn`,
`output.dsn`, indexed `aws_instance.a[0].id` / `["key"]`.

## Pitfalls

- **Large dependency tree** (AWS, GCS, Azure SDKs) → acceptable; it is the reason we use it instead of re-implementing backends.
- **Sensitive values** are stored in plain JSON and not reliably flagged → `tfstate()` results are plain
  values; `password` values are redacted structurally in plan output regardless of source.
- **Missing address** returns a non-nil error or an Object with nil Value depending on path → treat nil Value as "not found" error.
- **Cache per URL**: parse each state once (`map[url]*TFState`), lookups are cheap.

## Integration Pattern

```go
// as built (internal/funcs)
type TFState interface{ Lookup(ctx context.Context, url, address string) ([]byte, error) } // JSON of obj.Value
// default impl caches *tfstate.TFState per URL (tfstate.ReadURL); WithTFState overrides
obj, err := st.Lookup(addr); b, _ := json.Marshal(obj.Value)
ty, _ := ctyjson.ImpliedType(b); v, _ := ctyjson.Unmarshal(b, ty)
```

## Confidence

- **High**: function signatures and schemes (pkg.go.dev).
- **Medium**: nil-Value behavior for missing keys — treated as an error.
- Tests: local fixture `internal/funcs/testdata/terraform.tfstate` and `s3://` via the kumo emulator (`AWS_ENDPOINT_URL_S3`).
