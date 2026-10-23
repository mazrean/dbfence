---
description: Diff + plan ordering, ignore, redaction for dbfence
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Skill
---

# Task 7: Diff + plan ordering, ignore, redaction

> **As built** (implementation deviates from the steps below):
> - `diff.Compute(desired, current, dialect, Options{Prune, ForcePassword})` returns an ordered `*plan.Plan`; SQL is rendered by the `Dialect` during diffing. Password comparison happens in `Dialect.AlterRole`.
> - Undeclared privileges of declared roles on declared objects are revoked (not just warned). Phase order: roles → databases → memberships → schemas → grants → revokes → drop schemas → drop databases → drop roles.
> - `plan` tests are unit tests (`plan_test.go`), not golden files.

<background_information>
- **PRD**: specs/dbfence/skills/prd-dbfence/SKILL.md
- **Design**: specs/dbfence/design-dbfence.md
- **Depends on**: Task 2 (uses a fake driver; Tasks 5/6 optional)
- **Spec refs**: FR-12 … FR-19, NFR-2
</background_information>

<instructions>
## Pre-check

Confirm the dependencies are checked `- [x]` in `specs/dbfence/tasks/overview.md` and their packages build
(`go build ./...`). If not, report which task must be completed first and stop without committing.

## Core Task

Implement pure `diff.Diff` (desired vs current → changes + warnings; prune; ignore + built-ins via driver-supplied
predicate; password compare via `Options.Verify`, warn-and-skip when unreadable, `ForcePassword`) and `plan`
(phase ordering from the design, `Render` per change, output format with `'<redacted>'` unless show-secrets).

## Scope

Files to create or modify:
- `internal/diff/*.go`
- `internal/plan/*.go` + `testdata/` (golden output)
- `specs/dbfence/tasks/overview.md` (checklist flip only — see **Update Overview**)

Do NOT modify files outside this scope.

## Steps

1. Table-driven diff tests: create/alter/drop per kind, unmanaged → warning, `Prune` → drop, ignore regex, privilege normalization (case, dupes, ALL), password equal/different/unreadable/forced.
2. Implement `Diff`.
3. Golden plan-output tests with a fake driver: ordering (forward + prune reverse), comments, warnings, `No changes.`, redaction on/off; grep output for the fixture secret.
4. Implement `plan` (ordering, printing, change count for exit code).

## Verify

Run these verification commands. ALL must pass before moving on:

```bash
go test ./internal/diff/... ./internal/plan/...
go tool lint ./...
```

If verification fails, fix and re-run — do not proceed to commit.

## Update Overview

1. Open `specs/dbfence/tasks/overview.md`.
2. Flip the line starting with `- [ ] Task 7:` to `- [x] Task 7:`.
3. Do not touch other tasks' checkboxes or anything outside the Progress list.
4. Bundle this edit into the same atomic commit as the task changes.

## Commit

1. Review scope: `git status` and `git diff` — only files listed in **Scope** are changed.
2. Invoke the `committing-code` skill to produce and execute the commit.
3. Suggested message:

   ```text
   feat(dbfence): diff + plan ordering, ignore, redaction

   Implements Task 7 (diff-plan) for dbfence.
   Spec refs: FR-12 … FR-19, NFR-2
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
