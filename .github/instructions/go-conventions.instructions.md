---
applyTo: "**/*.go, go.mod, go.sum, go.work, go.work.sum"
---

# Go conventions

## Tooling

- Manage build / generate / lint tools via the Go 1.24+ `tool` directive in `go.mod` (see `using-go-tool-directive` skill). Do not maintain a `tools.go` file.
- Pin the `go` toolchain in `mise.toml`. Pin `gopls` in `mise.toml` (it backs the gopls MCP server registered by this package).

## Dependency injection

- Use [`mazrean/kessoku`](https://github.com/mazrean/kessoku) for compile-time DI. Kessoku generates parallel-execution injectors at compile time with zero runtime overhead.
- Add `kessoku` to the project's `go.mod` `tool` directive and invoke via `go generate ./...` (with `//go:generate go tool kessoku $GOFILE` markers next to injector files).
- For projects historically using `google/wire`, migrate via `go tool kessoku migrate ./...` — the migrator covers `wire.NewSet`, `wire.Bind`, `wire.Value`, `wire.InterfaceValue`, `wire.Struct`, and `wire.FieldsOf` patterns.
- Do not introduce new `wire` dependencies. Existing `wire`-based repos should plan a kessoku migration.

## Linting

- Each repo ships its own `tools/lint` Go module that combines the analyzers it cares about (typically `go vet` + `staticcheck` + `stylecheck` + project-specific analyzers) into a single binary.
- Invoke via `go tool lint ./...` from the repo root.
- Do NOT pin `golangci-lint` in `mise.toml`; the per-repo `tools/lint` module is the canonical linter.
- Treat lint failures as blockers before commit.

## Testing

- Run `go test -v ./...` from the module root; use `-race` in CI.
- Tests live next to code in `*_test.go`; prefer table-driven cases.

## Code intelligence

- The `gopls` MCP server (from `golang.org/x/tools/gopls`, command `gopls mcp`) is registered by this package. Pair it with the multi-language `serena` MCP at the consumer-repo level when needed.
