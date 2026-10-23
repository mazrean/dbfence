---
description: PostgreSQL driver (Inspect + Render + Exec) for dbfence
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Skill
---

# Task 5: PostgreSQL driver (Inspect + Render + Exec)

> **As built** (implementation deviates from the steps below):
> - `internal/driver/postgres/postgres.go` holds `Driver` (Inspect/Exec/Close, per-database connections) and `Dialect` (SQL rendering without a connection). Quoting via own `Ident`/`Literal`.
> - Password is a `plan.Secret` fragment, not `Statement.Secrets`. Unreadable `pg_authid` (any error) ⇒ `PasswordReadable=false`; the warning is emitted per role by `AlterRole`.
> - No driver-level golden tests or integration test: rendering is covered through `internal/diff` tests using `postgres.Dialect{}`; the PostgreSQL 17 integration test lives in `internal/app/app_integration_test.go` (dockertest).

<background_information>
- **PRD**: specs/dbfence/skills/prd-dbfence/SKILL.md
- **Design**: specs/dbfence/design-dbfence.md
- **Depends on**: Task 2, Task 4
- **Spec refs**: FR-12 … FR-18 (PG side), NFR-4
</background_information>

<instructions>
## Pre-check

Confirm the dependencies are checked `- [x]` in `specs/dbfence/tasks/overview.md` and their packages build
(`go build ./...`). If not, report which task must be completed first and stop without committing.

## Core Task

Implement `driver.Driver` for PostgreSQL with pgx stdlib. Per-database connections via DSN dbname swap.
Built-in exclusion list lives here. Research: `specs/dbfence/skills/tech-pgx/SKILL.md`. This task is larger than
200 LOC by nature — keep Inspect and Render as separate steps and files.

## Scope

Files to create or modify:
- `internal/driver/postgres/*.go`
- `internal/driver/postgres/testdata/` (golden SQL)
- `go.mod`, `go.sum`
- `specs/dbfence/tasks/overview.md` (checklist flip only — see **Update Overview**)

Do NOT modify files outside this scope.

## Steps

1. Render: golden tests per Change kind (create/alter/drop database, role, membership, schema, grant/revoke, prune REASSIGN/DROP OWNED); quote via `pgx.Identifier`, password as `Statement.Secrets`.
2. Inspect: catalog queries from tech-pgx; `pg_authid` 42501 ⇒ `HashReadable=false` + warning.
3. VerifyPassword: delegate to `internal/password`.
4. Integration test (skip on `testing.Short()`) with dockertest PostgreSQL 17 (as built: end-to-end in `internal/app`).

## Verify

Run these verification commands. ALL must pass before moving on:

```bash
go build ./...
go test -short ./internal/driver/postgres/...
go test ./internal/driver/postgres/...
go tool lint ./...
```

If verification fails, fix and re-run — do not proceed to commit.

## Update Overview

1. Open `specs/dbfence/tasks/overview.md`.
2. Flip the line starting with `- [ ] Task 5:` to `- [x] Task 5:`.
3. Do not touch other tasks' checkboxes or anything outside the Progress list.
4. Bundle this edit into the same atomic commit as the task changes.

## Commit

1. Review scope: `git status` and `git diff` — only files listed in **Scope** are changed.
2. Invoke the `committing-code` skill to produce and execute the commit.
3. Suggested message:

   ```text
   feat(dbfence): postgreSQL driver (Inspect + Render + Exec)

   Implements Task 5 (driver-postgres) for dbfence.
   Spec refs: FR-12 … FR-18 (PG side), NFR-4
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
