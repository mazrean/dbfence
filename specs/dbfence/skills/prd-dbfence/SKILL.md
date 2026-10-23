---
name: prd-dbfence
description: PRD for dbfence, a declarative CLI that manages the "outer frame" of MySQL/PostgreSQL servers (databases, users/roles, memberships, grants, PostgreSQL schemas) from HCL and plans/applies the diff against the live server. Use when implementing, testing, or reviewing any dbfence code (config, funcs, diff, plan, apply, drivers, CLI).
---

# dbfence - PRD

## TL;DR

dbfence lets platform/DB operators declare databases, users/roles, role memberships, grants and
PostgreSQL schemas in HCL and converge a live MySQL or PostgreSQL server to that declaration.
`plan` prints the exact SQL it would run (secrets redacted); `apply` runs it. Table DDL is out of
scope — existing schema-migration tools already cover it, but nothing simple covers the frame around it.

## Requirements

### Functional Requirements

**Configuration**

- **FR-1**: The system SHALL load one or more HCL files (`-f`/`--file` or env `DBFENCE_FILE`, default
  `dbfence.hcl`; a file or a directory of `*.hcl`) declaring one unlabeled `connection` block and
  `database`, `role`/`user` (synonyms; shared namespace), `schema` (PostgreSQL), `grant` and `ignore` blocks.
  - Acceptance: a fixture file containing every block type decodes into the desired model without error;
    an unknown block or attribute yields an error with file:line.
- **FR-2**: The system SHALL resolve references between blocks (`role.x.name|host|id`, `user.x.*`,
  `database.x.name`, `schema.x.name|database`) and reject references to undeclared resources.
  - Acceptance: `owner = role.missing.name` fails `validate` with an HCL diagnostic; a grant whose role,
    database or schema is not declared fails `validate`; an owner / `member_of` string naming a role that is
    neither declared nor existing fails `plan`.
- **FR-3**: The system SHALL reject engine-incompatible declarations (e.g. `schema` blocks, grant `schema`,
  database `owner` or PG role attributes for MySQL; `host`, `auth_plugin`, `charset` for PostgreSQL) at `validate` time.
  - Acceptance: a MySQL config with a `schema` block exits non-zero from `validate`.
- **FR-4**: The system SHALL support only the engines `mysql` and `postgres`.
  - Acceptance: `engine = "sqlite"` fails `validate`.

**Functions**

- **FR-5**: The system SHALL provide `env(name, [default])`; an unset variable without default is an error.
  - Acceptance: unit test with/without `t.Setenv`.
- **FR-6**: The system SHALL provide `aws_secretsmanager(id, [json_key])` returning the secret string,
  or the value at `json_key` when the secret is JSON.
  - Acceptance: mocked client test; missing key is an error.
- **FR-7**: The system SHALL provide `gcp_secretmanager(name, [version])` (default version `latest`).
  - Acceptance: mocked client test asserting the requested version resource name.
- **FR-8**: The system SHALL provide `tfstate(url, address)` returning the looked-up value as a
  dynamic HCL value, for local files, `s3://` and `gs://` state URLs.
  - Acceptance: local fixture state; `tfstate("file.tfstate", "aws_db_instance.main.address")` returns the string.
- **FR-9**: The system SHALL ship standard HCL helper functions (at least `jsondecode`, `jsonencode`,
  `format`, `lookup`, `join`, `split`).
  - Acceptance: `jsondecode(env("X")).password` evaluates.
- **FR-10**: The system SHALL fetch each distinct (function, arguments) pair at most once per process.
  - Acceptance: mock counter is 1 after two identical calls.
- **FR-11**: Every `password` value SHALL be redacted in plan/apply output regardless of its source
  (literal, `env`, secret managers, `tfstate`, `jsondecode(...)`). Redaction is structural (the password is a
  `plan.Secret` fragment of the statement), not based on value tracking.
  - Acceptance: plan output contains `PASSWORD '<redacted>'` and not the password (integration test).

**Diff / Plan**

- **FR-12**: The system SHALL compare desired state with the live server (no state file) and produce
  create / alter / drop / grant / revoke changes for databases, users/roles, memberships, grants and schemas.
  - Acceptance: fixture desired+current → expected change list (table-driven).
- **FR-13**: Live resources not declared in HCL SHALL produce a warning by default and a drop change only
  with `--prune`.
  - Acceptance: unmanaged role → `-- warning: unmanaged role "foo" (use --prune to drop it)`; with `--prune` the plan contains its DROP.
- **FR-13a**: For declared roles on declared databases/schemas, privileges present on the server but not
  declared SHALL be revoked (PostgreSQL owner privileges are implicit and ignored). When `member_of` is set,
  undeclared memberships of that role SHALL be revoked.
  - Acceptance: a drifted `GRANT CREATE` is reverted by the next apply (integration test).
- **FR-14**: Built-in/system resources (see BACKGROUND.md) and names matching `ignore` patterns (regex,
  anchored) SHALL never be warned about or pruned. The connecting user SHALL never be pruned.
  - Acceptance: `postgres`, `pg_*`, `rds_*`, `mysql.sys` and an `ignore`-matched role are absent from warnings and DROPs.
- **FR-15**: The system SHALL compare passwords by hash when the stored hash is readable
  (PostgreSQL SCRAM-SHA-256 and md5; MySQL `mysql_native_password` and `caching_sha2_password`).
  - Acceptance: same password → no change; different password → `ALTER ... PASSWORD` change.
- **FR-16**: When stored hashes are unreadable (PostgreSQL non-superuser) or in an unsupported format
  (e.g. MySQL `auth_socket`) the system SHALL warn and skip password diffs; `--force-password` SHALL always
  emit password changes for declared passwords.
  - Acceptance: unreadable verifier → one warning per role with a declared password, no change; with flag → change present.
- **FR-17**: `plan` SHALL print warnings (`-- warning: ...`) then each change as `-- [<action>] <resource>`
  (actions `create`/`update`/`drop`/`grant`/`revoke`) followed by its statements (`-- (on database "x")` when run
  in another PG database), with passwords shown as `'<redacted>'` unless `--show-secrets`.
  - Acceptance: plan render and statement redaction unit tests.
- **FR-18**: Statements SHALL be ordered so that dependencies exist before use: roles → databases →
  memberships → schemas → grants → revokes → drop schemas → drop databases → drop roles.
  - Acceptance: golden test; applying the plan on a fresh server succeeds.
- **FR-19**: `plan --detailed-exitcode` SHALL exit 0 for no changes, 2 for changes, 1 for errors.
  Warnings alone do not count as changes.
  - Acceptance: CLI test for all three codes.

**Apply**

- **FR-20**: `apply` SHALL show the plan, ask for confirmation (only `yes` is accepted; skippable with
  `--auto-approve`), and execute the statements sequentially without a transaction, stopping at the first error.
  - Acceptance: answering anything but `yes` executes nothing.
- **FR-21**: Applying then re-planning SHALL report zero changes (idempotency).
  - Acceptance: integration test on MySQL 8.4 and PostgreSQL 17.
- **FR-22**: `validate` SHALL load and check the configuration without connecting to the database. It
  evaluates all functions for real, so it may call secret managers / read tfstate.
  - Acceptance: `validate -f valid.hcl` exits 0 and prints a summary (CLI test).

### Non-Functional Requirements

- **NFR-1**: Single static binary `dbfence` for linux/darwin/windows (amd64, arm64); no cgo; Homebrew cask in `mazrean/homebrew-tap`.
  - Metric: `goreleaser build --snapshot` succeeds with `CGO_ENABLED=0`.
- **NFR-2**: No secret value ever appears in plan output, logs or error messages unless `--show-secrets`.
  - Metric: tests grep output for the fixture secret value → 0 hits.
- **NFR-3**: `plan` against a server with ≤ 100 databases and ≤ 1000 roles completes in < 10 s on LAN.
  - Metric: integration benchmark (informational).
- **NFR-4**: All identifiers quoted and literals escaped per engine.
  - Metric: names containing quotes/backticks round-trip in integration tests.

## User Stories

- As an operator, I want to preview the SQL before changing production, so that I can review it.
  - Given a config adding role `app`, when I run `dbfence plan`, then the output contains
    `-- [create] role "app"` followed by `CREATE ROLE "app" WITH ... PASSWORD '<redacted>';` and nothing is executed.
  - Given the server already matches the config, when I run `dbfence plan --detailed-exitcode`, then it prints
    `-- No changes. The server matches the configuration.` and exits 0.
- As an operator, I want unmanaged accounts surfaced but not destroyed by default, so that adoption is safe.
  - Given a live role `legacy` not in HCL, when I run `plan`, then a warning is printed and no DROP appears.
  - Given the same, when I run `plan --prune`, then the plan contains `DROP ROLE "legacy"` (after
    `REASSIGN OWNED`/`DROP OWNED` in each database on PostgreSQL).
- As an operator, I want secrets pulled from AWS/GCP secret managers or Terraform state, so that HCL contains no secrets.
  - Given `password = aws_secretsmanager("prod/app", "password")`, when I run `plan`, then the secret is fetched
    once and shown as `'<redacted>'`.
- As an operator on RDS/Cloud SQL, I want password handling to degrade gracefully.
  - Given a non-superuser PostgreSQL connection, when I run `plan`, then I get
    `-- warning: cannot read the password verifier of role "app" (superuser required); password not compared, use --force-password to set it`.

## Constraints

- Engines: MySQL 8.0+/8.4 and PostgreSQL 13+ (tested on MySQL 8.4, PostgreSQL 17).
- No state file: the live server is the only source of "current".
- Configuration language is HCL (native syntax).
- CLI: `plan`, `apply`, `validate`; flags `-f/--file`, `--prune`, `--show-secrets`, `--force-password`,
  `--auto-approve` (apply), `--detailed-exitcode` (plan), `--version`.

## Non-Goals

- SQLite (explicit user decision) and any other engine.
- Table/column definitions or data migration.
- Table/column-level grants in v1 (database- and schema-level only); `ALTER DEFAULT PRIVILEGES`.
- A state file, locking, or Terraform-provider mode.
- Managing server parameters, replication, extensions.

## Open Questions

- [x] SQLite support? -> Decision: out of scope.
- [x] Unmanaged resources? -> Decision: warn by default, drop with `--prune`.
- [x] Password drift? -> Decision: hash comparison with warn-and-skip fallback, `--force-password` override.
- [x] Should MySQL accounts be a dedicated `user` block or `role` with `host`? -> Decision: `role`/`user` are synonyms on both engines; `host` attr on MySQL.
- [ ] Table-level grants in v1.1?

## Deep Reference

**Background & research**: See [BACKGROUND.md](references/BACKGROUND.md)
**Code-area constraints**: See [RULES.md](references/RULES.md)
**Technical design**: `specs/dbfence/design-dbfence.md`
