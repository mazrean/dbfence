---
applyTo: ".goreleaser.{yml,yaml}"
---

# goreleaser conventions

- Keep `.goreleaser.yml` at the repo root.
- Use `goreleaser check` in CI before tagging a release.
- For Zig projects, follow the `releasing-zig-with-goreleaser` skill — goreleaser drives `zig build` per target.
- For Go projects with `cgo`, ensure cross-compile toolchains are pinned in mise or the build container.
