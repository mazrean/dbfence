---
description: Model + HCL config decode (no functions) for dbfence
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Skill
---

# Task 2: Model + HCL config decode (no functions)

> **As built** (implementation deviates from the steps below):
> - Model is `model.Desired` / `model.Current` (`Role` vs `RoleState`, `Privilege` per privilege name, `RoleID{Name, Host}`); no `model.Secret`, no cty marks.
> - No `internal/diff/change.go` or `internal/driver/driver.go`: the contract is `diff.Dialect` (`internal/diff/diff.go`) and `app.Driver` (`internal/app/app.go`) embedding it.
> - `config.Load(path, fns)` returns `*Config{Desired, Engine, DSN}`; `connection` is unlabeled; `role`/`user` are synonyms on both engines; grant uses flat attrs (`role`, `database`, `schema`, `privileges`, `with_grant_option`).

<background_information>
- **PRD**: specs/dbfence/skills/prd-dbfence/SKILL.md
- **Design**: specs/dbfence/design-dbfence.md
- **Depends on**: Task 1
- **Spec refs**: FR-1, FR-2, FR-3, FR-4, FR-14 (ignore parsing)
</background_information>

<instructions>
## Pre-check

Confirm the dependencies are checked `- [x]` in `specs/dbfence/tasks/overview.md` and their packages build
(`go build ./...`). If not, report which task must be completed first and stop without committing.

## Core Task

Implement the neutral model and HCL loading per design (Interface Contracts, Data Model). Also add the
shared contracts other tasks build on: `diff.Change`/`Warning`/`Options` types and the `driver.Driver`
interface + `Statement` (types only, no logic). Two-pass decode, reference variables, per-engine validation.
Functions are NOT wired yet: use stdlib functions only. See `specs/dbfence/skills/tech-hcl-cty/SKILL.md`.

## Scope

Files to create or modify:
- `internal/model/*.go`
- `internal/config/*.go` + `testdata/`
- `internal/diff/change.go` (types only)
- `internal/driver/driver.go` (interface + Statement)
- `specs/dbfence/tasks/overview.md` (checklist flip only — see **Update Overview**)

Do NOT modify files outside this scope.

## Steps

1. Define `model` types exactly as in the design's Interface Contracts.
2. Write table-driven decode tests first (valid fixture with every block; unknown attr; bad reference; engine mismatch; sqlite engine).
3. Implement `config.Load` (parse, pass 1 labels → variables, pass 2 attributes) and `Validate`.
4. Mark `password` and `dsn` attributes sensitive; convert via `UnmarkDeepWithPaths` into `model.Secret`.
5. Compile `ignore` patterns as anchored regexps.

## Verify

Run these verification commands. ALL must pass before moving on:

```bash
go build ./...
go test ./internal/model/... ./internal/config/...
go tool lint ./...
```

If verification fails, fix and re-run — do not proceed to commit.

## Update Overview

1. Open `specs/dbfence/tasks/overview.md`.
2. Flip the line starting with `- [ ] Task 2:` to `- [x] Task 2:`.
3. Do not touch other tasks' checkboxes or anything outside the Progress list.
4. Bundle this edit into the same atomic commit as the task changes.

## Commit

1. Review scope: `git status` and `git diff` — only files listed in **Scope** are changed.
2. Invoke the `committing-code` skill to produce and execute the commit.
3. Suggested message:

   ```text
   feat(dbfence): model + HCL config decode (no functions)

   Implements Task 2 (model-config) for dbfence.
   Spec refs: FR-1, FR-2, FR-3, FR-4, FR-14 (ignore parsing)
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
