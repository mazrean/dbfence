---
name: tech-hcl-cty
description: hashicorp/hcl/v2 + zclconf/go-cty research digest (HCL parsing, EvalContext, custom functions, cty stdlib). Use when implementing or debugging internal/config or internal/funcs in dbfence, or anything touching hcl.EvalContext, function.Function or cty marks.
---

# HCL v2 + cty — Research Digest

## TL;DR

`hclparse` parses files, `gohcl`/`hcldec` decode blocks, expressions are evaluated against an
`hcl.EvalContext{Variables, Functions}`.

> As built: dbfence does **not** use cty marks. Redaction is structural (`password` values become
> `plan.Secret` fragments in SQL), and `validate` evaluates every function for real — there is no
> unknown-value mode. The mark notes below are research only.

## Identity

- **Version**: hcl/v2 v2.2x, go-cty v1.1x (cty/function v1.19 docs verified 2026-10-23) — pin via `go get`.
- **Docs**: https://pkg.go.dev/github.com/hashicorp/hcl/v2 , https://pkg.go.dev/github.com/zclconf/go-cty/cty
- **License**: MPL-2.0 (hcl), MIT (cty)

## API We Use

```go
p := hclparse.NewParser(); f, diags := p.ParseHCLFile(path)
body := hcl.MergeFiles(files)
content, diags := body.Content(&hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "role", LabelNames: []string{"name"}}, ...}})
attrs, diags := block.Body.JustAttributes()           // or gohcl.DecodeBody(body, ctx, &spec)
v, diags := attr.Expr.Value(&hcl.EvalContext{Variables: vars, Functions: fns})

function.New(&function.Spec{
    Params:   []function.Parameter{{Name: "id", Type: cty.String}},
    VarParam: &function.Parameter{Name: "json_key", Type: cty.String},
    Type:     function.StaticReturnType(cty.String),
    Impl: func(args []cty.Value, ret cty.Type) (cty.Value, error) { ... return cty.StringVal(s), nil },
})
stdlib.JSONDecodeFunc, stdlib.JSONEncodeFunc, stdlib.FormatFunc, stdlib.LookupFunc, stdlib.JoinFunc, stdlib.SplitFunc
v.Mark(m) ; v.HasMark(m) ; v.UnmarkDeepWithPaths() (cty.Value, []cty.PathValueMarks) ; v.ContainsMarked()
gocty.FromCtyValue(v, &goVal) ; ctyjson.Marshal / ctyjson.SimpleJSONValue (dynamic → Go for tfstate)
```

## Pitfalls

- **Marks propagation**: params with `AllowMarked=false` (default) get unmarked args and the marks are
  re-applied to the result → stdlib functions propagate sensitivity. Never set `AllowMarked` on our funcs
  unless we re-mark manually. *Source: cty/function docs (Parameter.AllowMarked).*
- **gocty with marks** errors on marked values → call `UnmarkDeepWithPaths()` first, keep the paths to set `model.Secret.Sensitive`.
- **Function impl has no ctx** → capture a `context.Context` in the Registry when building functions.
- **Variadic optional args** → use `VarParam` and check `len(args)` ≤ max; error otherwise.
- **Dynamic return (`tfstate`)** → `Type: function.StaticReturnType(cty.DynamicPseudoType)`; build value with `ctyjson.Unmarshal(json, ctyjson.ImpliedType(json))`.
- **Diagnostics**: return `hcl.Diagnostics`, print with `hcl.NewDiagnosticTextWriter(os.Stderr, p.Files(), 80, color)`; never put secret values in `Detail`.

## Integration Pattern

Two-pass decode in `internal/config` (as built): (1) `Content` with the block schema, then per labeled block
resolve `name` (and MySQL `host`) via `JustAttributes` → build `role`/`user` (same object), `database`, `schema`
variables (`role.x = {name, host, id}`, `schema.x = {name, database}`); (2) `gohcl.DecodeBody` each block with
those variables + `funcs.Registry.Functions()` (which already include the stdlib subset). Multiple files are
merged with `hcl.MergeFiles`; errors are rendered with `hcl.NewDiagnosticTextWriter`.

## Confidence

- **High**: mark re-application through stdlib functions (documented; unused in dbfence).
- **High**: two-pass decode and reference variables (covered by `internal/config` tests).
