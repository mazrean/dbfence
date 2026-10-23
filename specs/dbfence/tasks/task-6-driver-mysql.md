---
description: MySQL driver (Inspect + Render + Exec) for dbfence
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Skill
---

# Task 6: MySQL driver (Inspect + Render + Exec)

> **As built** (implementation deviates from the steps below):
> - `internal/driver/mysql/mysql.go`: single connection; `NO_BACKSLASH_ESCAPES` detected from `sql_mode`; privileges read from `mysql.db` (not `SCHEMA_PRIVILEGES`); roles are `CREATE USER ... ACCOUNT LOCK` (no `CREATE ROLE`); `ALTER USER` always `IDENTIFIED WITH <plugin> BY`; grant option per db level.
> - No fallback when `mysql.user` is unreadable (Inspect fails).
> - No driver-level golden tests or integration test: covered by `internal/diff` tests with `mysql.Dialect{}` and the MySQL 8.4 dockertest integration test in `internal/app`.

<background_information>
- **PRD**: specs/dbfence/skills/prd-dbfence/SKILL.md
- **Design**: specs/dbfence/design-dbfence.md
- **Depends on**: Task 2, Task 4
- **Spec refs**: FR-12 … FR-18 (MySQL side), NFR-4
</background_information>

<instructions>
## Pre-check

Confirm the dependencies are checked `- [x]` in `specs/dbfence/tasks/overview.md` and their packages build
(`go build ./...`). If not, report which task must be completed first and stop without committing.

## Core Task

Implement `driver.Driver` for MySQL with go-sql-driver/mysql: accounts `'u'@'h'`, roles, `role_edges`,
SCHEMA_PRIVILEGES, `HEX(authentication_string)`. Built-in exclusion list lives here. Research:
`specs/dbfence/skills/tech-go-sql-driver-mysql/SKILL.md`. Keep Inspect and Render as separate steps/files.

## Scope

Files to create or modify:
- `internal/driver/mysql/*.go`
- `internal/driver/mysql/testdata/` (golden SQL)
- `go.mod`, `go.sum`
- `specs/dbfence/tasks/overview.md` (checklist flip only — see **Update Overview**)

Do NOT modify files outside this scope.

## Steps

1. Render: golden tests per Change kind incl. `SET DEFAULT ROLE ALL`; backtick quoting, literal escaping.
2. Inspect: catalog queries; error 1142 on `mysql.user` ⇒ hashes unreadable + warning.
3. VerifyPassword: delegate to `internal/password` by plugin.
4. Integration test (skip on `testing.Short()`) with dockertest MySQL 8.4 (as built: in `internal/app`).

## Verify

Run these verification commands. ALL must pass before moving on:

```bash
go build ./...
go test -short ./internal/driver/mysql/...
go test ./internal/driver/mysql/...
go tool lint ./...
```

If verification fails, fix and re-run — do not proceed to commit.

## Update Overview

1. Open `specs/dbfence/tasks/overview.md`.
2. Flip the line starting with `- [ ] Task 6:` to `- [x] Task 6:`.
3. Do not touch other tasks' checkboxes or anything outside the Progress list.
4. Bundle this edit into the same atomic commit as the task changes.

## Commit

1. Review scope: `git status` and `git diff` — only files listed in **Scope** are changed.
2. Invoke the `committing-code` skill to produce and execute the commit.
3. Suggested message:

   ```text
   feat(dbfence): mySQL driver (Inspect + Render + Exec)

   Implements Task 6 (driver-mysql) for dbfence.
   Spec refs: FR-12 … FR-18 (MySQL side), NFR-4
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
