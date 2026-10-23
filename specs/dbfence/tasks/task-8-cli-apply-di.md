---
description: Apply, CLI and DI wiring for dbfence
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Skill
---

# Task 8: Apply, CLI and DI wiring

> **As built** (implementation deviates from the steps below):
> - Commands live in `internal/app` (`Validate`/`Plan`/`Apply`, confirmation prompt); the root `package main` is a thin kong CLI (`-f/--file` env `DBFENCE_FILE`, `--prune`, `--force-password`, `--show-secrets`, `plan --detailed-exitcode`, `apply --auto-approve`, `--version`).
> - `apply.Run` executes sequentially without transactions (no NoTx grouping), stopping at the first error.
> - kessoku injector `di.InitializeApp(ctx)` (funcs registry built async).
> - Integration tests use `ory/dockertest/v3` in `internal/app/app_integration_test.go`; skipped with `-short` or without Docker, fail when `CI` is set.
> - Not covered by tests: `--detailed-exitcode` exit 2, the non-`yes` prompt path, and `validate` with secret functions offline (no longer a requirement).

<background_information>
- **PRD**: specs/dbfence/skills/prd-dbfence/SKILL.md
- **Design**: specs/dbfence/design-dbfence.md
- **Depends on**: Task 3, Task 5, Task 6, Task 7
- **Spec refs**: FR-17, FR-19, FR-20, FR-21, FR-22
</background_information>

<instructions>
## Pre-check

Confirm the dependencies are checked `- [x]` in `specs/dbfence/tasks/overview.md` and their packages build
(`go build ./...`). If not, report which task must be completed first and stop without committing.

## Core Task

Implement `internal/apply` (show plan, confirm unless `--auto-approve`, execute in order, stop at first error,
redacted error output), root `package main` subcommands `plan`/`apply`/`validate` with flags from the PRD, exit codes incl.
`--detailed-exitcode`, and `internal/di` kessoku injector (`//go:generate go tool kessoku $GOFILE`) wiring config
loader, function registry and driver factory. End-to-end idempotency tests on both engines.

## Scope

Files to create or modify:
- `internal/apply/*.go`
- `main.go`, `cli.go`, `version.go` (repo root, `package main`)
- `internal/di/*.go` (+ generated file)
- `cli_test.go`, `version_test.go` (repo root)
- `specs/dbfence/tasks/overview.md` (checklist flip only — see **Update Overview**)

Do NOT modify files outside this scope.

## Steps

1. Apply tests with a fake driver: confirm `yes`/other, stop on error, NoTx grouping.
2. CLI tests: exit codes 0/1/2, `validate` offline with secret functions.
3. kessoku injector + `go generate ./...`.
4. Integration (dockertest `mysql:8.4` + `postgres:17`): plan → apply → plan shows `No changes.`; password change detected; unmanaged role warned, dropped with `--prune`; built-ins ignored.

## Verify

Run these verification commands. ALL must pass before moving on:

```bash
go generate ./...
go build ./...
mise run test
mise run lint
mise run release:build
```

If verification fails, fix and re-run — do not proceed to commit.

## Update Overview

1. Open `specs/dbfence/tasks/overview.md`.
2. Flip the line starting with `- [ ] Task 8:` to `- [x] Task 8:`.
3. Do not touch other tasks' checkboxes or anything outside the Progress list.
4. Bundle this edit into the same atomic commit as the task changes.

## Commit

1. Review scope: `git status` and `git diff` — only files listed in **Scope** are changed.
2. Invoke the `committing-code` skill to produce and execute the commit.
3. Suggested message:

   ```text
   feat(dbfence): apply, CLI and DI wiring

   Implements Task 8 (cli-apply-di) for dbfence.
   Spec refs: FR-17, FR-19, FR-20, FR-21, FR-22
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
