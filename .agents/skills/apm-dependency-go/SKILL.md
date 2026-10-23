---
name: apm-dependency-go
description: Lists the CLI tools that must appear in mise.toml for any repo depending on apm-plackage/go. Use when bootstrapping or auditing a Go repo's mise.toml.
---

# Go package — mise dependencies

```toml
[tools]
go = "1.24"
"go:golang.org/x/tools/gopls" = "latest"
```

## Notes

- `gopls` MUST be installed; it backs the `gopls` MCP server that this package registers (`gopls mcp`).
- `golangci-lint` is intentionally NOT pinned. The org-wide convention is a per-repo
  `tools/lint` Go module wired up via the Go 1.24+ `tool` directive (`go tool lint ./...`).
- `kessoku` (compile-time DI) is consumed via the project's `go.mod` `tool` directive
  (`go tool kessoku ...`) — do not pin it via mise either.
- If the repo also releases binaries via goreleaser, also depend on `apm-plackage/goreleaser`.
