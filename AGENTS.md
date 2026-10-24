# dbfence — Project Constitution

dbfence (`github.com/mazrean/dbfence`) is a Go CLI that declaratively manages the "outer frame" of
MySQL / PostgreSQL servers — databases, users/roles, memberships, grants, PostgreSQL schemas — from HCL.
`plan` prints the SQL diff against the live server (secrets redacted); `apply` executes it. No state file.

## Commands

- Test: `mise run test` (= `go test -short ./...`; single package: `go test -short ./internal/<pkg>/...`)
- Test incl. Docker integration: `mise run test:integration` (= `go test ./...`)
- Test (CI): `mise run test:ci` (`-race -coverprofile=coverage.out -covermode=atomic`; Docker required when `CI` is set)
- Lint: `mise run lint` (= `go vet -vettool=$(go tool -n lint) ./...`; `go tool lint ./...` does the same but needs ~9 GB); it checks the host build, and `TestNoBuildConstrainedFiles` forbids build-constrained files so that every target compiles the same files; lint failures block commits
- Fuzz: `mise run test:fuzz` (each `Fuzz*` target for 30s; seed corpora run in `mise run test`)
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
internal/driver/     mysql/ and postgres/: Driver (Inspect/Exec) + Dialect (SQL rendering); internal/sqltest SQL lexer for tests
internal/password/   stored-hash verification (SCRAM, md5, mysql_native, caching_sha2)
internal/diff/       desired vs current -> ordered *plan.Plan via diff.Dialect (no I/O)
internal/policy/     independent safety check of a finished plan (Verify, no I/O)
internal/plan/       Statement / Secret fragments, redacted output (no I/O)
internal/secret/     secret registry + redacting, control-escaping output Writer
internal/apply/      sequential execution, stop at first error
internal/di/         kessoku injectors
tools/lint/          repo linter module (+ outputsink analyzer)
```

## Coding Standards

- Wrap errors with `fmt.Errorf("context: %w", err)`; never include secret values in errors or logs (HCL diagnostics quote source masked by `config.maskSecrets`, and none from files that do not parse and assign a secret attribute: a new secret attribute goes into `secretAttrs` and `secretAssign`).
- Identifiers are quoted and literals escaped only through the engine Dialect; passwords go into SQL only as `plan.Secret`.
- SQL is built only from `plan` fragments: SQL text is a constant `plan.Keyword`, runtime values enter only as `plan.QuotedIdent`/`EscapedLiteral`/`NewToken`/`Number` made by Dialect code under `internal/driver` (lint `sqlfragment`); outside `internal/plan` and tests, no pointers to Keyword-containing values, no non-`plan` generics instantiated with them, no slicing/indexing of a Keyword or non-constant Keyword `+`/`+=` (use `plan.Seq`), no `reflect`/`unsafe`/`encoding/gob` imports, no function declarations without a Go body and no non-Go files (`.s`, `.syso`, C); Dialect statements use `plan.New` with their `Kind` and a `Target` that records every name they render (grantor of `GRANTED BY`, owner) apart from `AsRole`/`DefaultRoles`.
- One `plan.Statement` is exactly one SQL command, sent alone (`;` never chains statements); to run as another role set `AsRole`, never prepend `SET ROLE`.
- Every protection promised in README ("What `--prune` never drops", the connected user) is also an invariant in `internal/policy.Verify`, which reads only statement `Kind`/`Target`/`RoleChange`/`DefaultRoles`/`AsRole`, never SQL text, and shares no code with `diff`; diff tests run every plan through it.
- Data read from the server is untrusted: Inspect ends with `model.Current.DropUntrusted`, names failing `model.CheckName` are never put into SQL (guard state-derived names such as grantors), and `policy.Verify` rejects statements naming them.
- `diff` and `plan` do no I/O; engine-specific code only in `internal/driver/<engine>` and `internal/password`.
- All output goes through the redacting `secret.Writer` streams wired in `internal/di/di.go` (`app.IO`); never use `os.Stdout`/`os.Stderr`/`fmt.Print*`/`print` elsewhere (lint `outputsink`); route library loggers to the `Output.Err` stream in `NewOutput` (the lint cannot see them, e.g. `mysql.SetLogOutput`), and `secret.Register` every new secret source; add an HCL function whose arguments name a secret rather than hold it to `lookupFuncs` in `internal/config/sanitize.go`.
- Table-driven tests next to code; integration tests skip under `testing.Short()` or without Docker (fail if `CI` is set).

## Boundaries

- ALWAYS: run `mise run test` and `mise run lint` before considering work done.
- ALWAYS: use Conventional Commits via the `committing-code` skill; keep commits atomic.
- ASK FIRST: new dependencies, changes to the HCL schema or CLI flags.
- NEVER: add SQLite or other engines; add a state file; bypass hooks (`--no-verify`).

## Conditional Rules

Project conventions and code-area rules live in `.claude/rules/` (mirrored to `.github/instructions/`)
and load automatically for matching files. `AGENTS.md` is the single source of truth; `CLAUDE.md` only imports it.
