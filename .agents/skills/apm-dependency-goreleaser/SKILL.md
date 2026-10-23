---
name: apm-dependency-goreleaser
description: Lists the CLI tools that must appear in mise.toml for any repo depending on apm-plackage/goreleaser. Use when bootstrapping a release pipeline.
---

# goreleaser package — mise dependencies

```toml
[tools]
goreleaser = "latest"
```

## Notes

- `goreleaser` is sufficient for both Go and Zig release pipelines.
- For Zig releases via goreleaser, see the `releasing-zig-with-goreleaser` skill from `mazrean/agent-skills`.
- Pin a specific major (`goreleaser = "2"`) on long-lived repos to avoid breaking changes.
