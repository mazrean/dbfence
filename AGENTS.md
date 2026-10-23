# dbfence — Project Constitution

dbfence (`github.com/mazrean/dbfence`) is a Go CLI that declaratively manages the "outer frame" of
MySQL / PostgreSQL servers — databases, users/roles, memberships, grants, PostgreSQL schemas — from HCL.
`plan` prints the SQL diff against the live server (secrets redacted); `apply` executes it. No state file.

## Commands

- Test: `mise run test` (= `go test -short ./...`; single package: `go test -short ./internal/<pkg>/...`)
- Test incl. Docker integration: `mise run test:integration` (= `go test ./...`)
- Test (CI): `mise run test:ci` (`-race -coverprofile=coverage.out -covermode=atomic`; Docker required when `CI` is set)
- Lint: `mise run lint` (= `go tool lint ./...`); lint failures block commits
- Generate (kessoku DI): `mise run generate` (= `go generate ./...`)
- Release: `mise run release:check` / `release:build` (snapshot) / `release:publish`
- API compat: `mise run apicompat` (no-op: no public packages)
- Run: `go run . plan -f dbfence.hcl`

## Tech Stack

- Go (version pinned in `mise.toml`), tools via `go.mod` `tool` directive (kessoku, `tools/lint`)
- CLI: `alecthomas/kong`; config: `hashicorp/hcl/v2` + `zclconf/go-cty`
- Drivers: `jackc/pgx/v5` (stdlib), `go-sql-driver/mysql`
- Secrets: aws-sdk-go-v2 Secrets Manager, GCP Secret Manager, `fujiwara/tfstate-lookup`
- DI: `mazrean/kessoku`; integration tests: `ory/dockertest/v3` (`mysql:8.4`, `postgres:17`);
  AWS tests: `sivchari/kumo` in-process emulator (Secrets Manager, S3 tfstate) via `AWS_ENDPOINT_URL`

## Project Structure

```
main.go, cli.go   CLI (kong, package main at repo root; version.go reads runtime/debug build info): plan / apply / validate
internal/app/        commands, Driver/Opener interfaces, confirmation prompt
internal/config/     HCL load, references, validation -> desired model
internal/funcs/      env / aws_secretsmanager / gcp_secretmanager / tfstate (+cache, cty stdlib subset)
internal/model/      engine-neutral Desired / Current, Role, Database, Schema, Privilege
internal/driver/     mysql/ and postgres/: Driver (Inspect/Exec) + Dialect (SQL rendering)
internal/password/   stored-hash verification (SCRAM, md5, mysql_native, caching_sha2)
internal/diff/       desired vs current -> ordered *plan.Plan via diff.Dialect (no I/O)
internal/plan/       Statement / Secret fragments, redacted output (no I/O)
internal/apply/      sequential execution, stop at first error
internal/di/         kessoku injectors
tools/lint/          repo linter module
```

## Coding Standards

- Wrap errors with `fmt.Errorf("context: %w", err)`; never include secret values in errors or logs.
- Identifiers are quoted and literals escaped only through the engine Dialect; passwords go into SQL only as `plan.Secret`.
- One `plan.Statement` is exactly one SQL command, sent alone (`;` never chains statements); to run as another role set `AsRole`, never prepend `SET ROLE`.
- `diff` and `plan` do no I/O; engine-specific code only in `internal/driver/<engine>` and `internal/password`.
- Table-driven tests next to code; integration tests skip under `testing.Short()` or without Docker (fail if `CI` is set).

## Boundaries

- ALWAYS: run `mise run test` and `mise run lint` before considering work done.
- ALWAYS: use Conventional Commits via the `committing-code` skill; keep commits atomic.
- ASK FIRST: new dependencies, changes to the HCL schema or CLI flags.
- NEVER: add SQLite or other engines; add a state file; bypass hooks (`--no-verify`).

## Conditional Rules

Project conventions and code-area rules live in `.claude/rules/` (mirrored to `.github/instructions/`)
and load automatically for matching files. `AGENTS.md` is the single source of truth; `CLAUDE.md` only imports it.
