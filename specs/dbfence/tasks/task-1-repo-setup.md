---
description: Repository setup (mise tasks, goreleaser, CI) for dbfence
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Skill
---

# Task 1: Repository setup (mise tasks, goreleaser, CI)

> **As built** (implementation deviates from the steps below):
> - mise tasks: `test` (`go test -short ./...`), `test:integration` (`go test ./...`), `test:ci` (`-race -coverprofile=coverage.out -covermode=atomic`), `lint`, `generate`, `release:check`, `release:build`, `release:publish`, `apicompat` (no-op: no public packages). `rtk` added to mise tools.
> - `.goreleaser.yaml`: binary `dbfence`, `CGO_ENABLED=0`, linux/darwin/windows × amd64/arm64, version from `runtime/debug.ReadBuildInfo` (no `-X` ldflag), `homebrew_casks` to `mazrean/homebrew-tap`.
> - CI runs `mise run test:ci` (Docker integration tests included), lint, goreleaser check/build + `--version` smoke test, apicompat.
> - Step 5 not done: `.claude/rules/dbfence.md` was not extracted (see `specs/dbfence/skills/prd-dbfence/references/RULES.md`).

<background_information>
- **PRD**: specs/dbfence/skills/prd-dbfence/SKILL.md
- **Design**: specs/dbfence/design-dbfence.md
- **Depends on**: none
- **Spec refs**: NFR-1
</background_information>

<instructions>
## Pre-check

Confirm the dependencies are checked `- [x]` in `specs/dbfence/tasks/overview.md` and their packages build
(`go build ./...`). If not, report which task must be completed first and stop without committing.

## Core Task

Make the repo buildable and checkable before any feature code. `AGENTS.md` and `CLAUDE.md`
already exist (written in Step 0) — verify they match reality, do not recreate them.

## Scope

Files to create or modify:
- `mise.toml`
- `.goreleaser.yaml`
- `.github/workflows/ci.yml`
- `go.mod` (tool directives)
- `main.go` at the repo root (stub `func main()` so the build has a target)
- `.claude/rules/dbfence.md` (extract from `specs/dbfence/skills/prd-dbfence/references/RULES.md`)
- `specs/dbfence/tasks/overview.md` (checklist flip only — see **Update Overview**)

Do NOT modify files outside this scope.

## Steps

1. Add mise tasks: `test` (`go test ./...`), `test:ci` (`go test -race -coverprofile=coverage.out ./...`), `lint` (`go tool lint ./...`), `release:build` (`goreleaser build --snapshot --clean`), `apicompat`.
2. Add `tool` directives for kessoku and `tools/lint` in `go.mod` (see `using-go-tool-directive` skill).
3. Create `.goreleaser.yaml` (binary `dbfence`, `main: .`, `CGO_ENABLED=0`, linux/darwin × amd64/arm64).
4. Fix CI: binary path `dist/dbfence_linux_amd64_v1/dbfence`, remove the `validate-skills` job.
5. Extract L2 rules to `.claude/rules/dbfence.md`; check `AGENTS.md` commands match `mise.toml`.

## Verify

Run these verification commands. ALL must pass before moving on:

```bash
go build ./...
mise run lint
mise run test
goreleaser check
mise run release:build
```

If verification fails, fix and re-run — do not proceed to commit.

## Update Overview

1. Open `specs/dbfence/tasks/overview.md`.
2. Flip the line starting with `- [ ] Task 1:` to `- [x] Task 1:`.
3. Do not touch other tasks' checkboxes or anything outside the Progress list.
4. Bundle this edit into the same atomic commit as the task changes.

## Commit

1. Review scope: `git status` and `git diff` — only files listed in **Scope** are changed.
2. Invoke the `committing-code` skill to produce and execute the commit.
3. Suggested message:

   ```text
   chore(dbfence): repository setup (mise tasks, goreleaser, CI)

   Implements Task 1 (repo-setup) for dbfence.
   Spec refs: NFR-1
   ```

4. Verify: `git log -1 --stat` — the overview.md flip must appear in the same commit.
</instructions>

## Done When

- [x] All **Verify** commands pass
- [x] `overview.md` checklist shows `- [x]` for this task
- [ ] `git status` is clean within task scope
- [ ] `git log -1` shows the task commit (with the overview.md flip) and a Conventional Commits message

## Safety & Fallback

- If verification fails, fix and re-run — do not commit a broken state
- If blocked by a dependency, report it and do NOT commit
- Do not modify files outside the defined scope
- Do not amend or rewrite prior task commits
- If unrelated changes are already staged, unstage them before committing
