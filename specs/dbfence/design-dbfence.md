---
title: "dbfence - Technical Design"
status: implemented
prd: specs/dbfence/skills/prd-dbfence/SKILL.md
component-skills:
  - specs/dbfence/skills/tech-hcl-cty/SKILL.md
  - specs/dbfence/skills/tech-tfstate-lookup/SKILL.md
  - specs/dbfence/skills/tech-aws-secretsmanager/SKILL.md
  - specs/dbfence/skills/tech-gcp-secretmanager/SKILL.md
  - specs/dbfence/skills/tech-pgx/SKILL.md
  - specs/dbfence/skills/tech-go-sql-driver-mysql/SKILL.md
  - specs/dbfence/skills/tech-password-hashing/SKILL.md
last-updated: 2026-10-23
---

# dbfence - Technical Design

> This document describes the code as built. Where the original pre-implementation design differed,
> the ADR log records the change.

## TL;DR

A pipeline: `config.Load` (HCL → `model.Desired` + engine + DSN), `Driver.Inspect` (live server →
`model.Current`), `diff.Compute` (desired vs current → ordered `*plan.Plan`, rendering SQL through the
engine's `diff.Dialect`), then `apply.Run` (execute). Engine knowledge is isolated in two drivers.
Redaction is structural: passwords are carried as `plan.Secret` fragments of a statement and printed as
`'<redacted>'` unless `--show-secrets`, so it never depends on string matching. No cty marks are used.
Trade-off: no state file means every run inspects the whole server (cheap at this scale).

## Decision Summary

| Decision | Choice | Rationale | Research |
|----------|--------|-----------|----------|
| Config language | `hashicorp/hcl/v2` + `zclconf/go-cty` | Terraform-familiar syntax, functions, references | `specs/dbfence/skills/tech-hcl-cty/` |
| Terraform state lookup | `fujiwara/tfstate-lookup` | `ReadURL` handles file/s3/gs/http/remote | `specs/dbfence/skills/tech-tfstate-lookup/` |
| AWS secrets | `aws-sdk-go-v2/service/secretsmanager` | Official SDK, default credential chain | `specs/dbfence/skills/tech-aws-secretsmanager/` |
| GCP secrets | `cloud.google.com/go/secretmanager/apiv1` | Official client, ADC | `specs/dbfence/skills/tech-gcp-secretmanager/` |
| PostgreSQL driver | `jackc/pgx/v5` (via `stdlib`) | Pure Go, `ParseConfig` for per-database connections | `specs/dbfence/skills/tech-pgx/` |
| MySQL driver | `go-sql-driver/mysql` | De-facto standard, pure Go | `specs/dbfence/skills/tech-go-sql-driver-mysql/` |
| Password verification | own `internal/password` (stdlib crypto + `x/text/secure/precis`) | No maintained lib covers all four formats | `specs/dbfence/skills/tech-password-hashing/` |
| DI | `mazrean/kessoku` | Repo convention (`.claude/rules/go-conventions.md`) | — |
| CLI | `alecthomas/kong` | Declarative subcommands/flags, env defaults, `--version` | — |
| Integration tests | `ory/dockertest/v3` (postgres:17, mysql:8.4) | Disposable real servers | — |
| AWS tests | `sivchari/kumo` in-process emulator | Real SDK code paths (Secrets Manager, S3 tfstate) without network | — |

## Component Overview

```text
            -f file|dir (*.hcl)
               │
               v
 ┌──────────────────────┐   funcs (env/aws/gcp/tfstate + stdlib, cached)
 │ internal/config      │<──── internal/funcs ──> AWS SM / GCP SM / tfstate URL
 └─────────┬────────────┘
           │ model.Desired + Engine + DSN
           v
 ┌──────────────────────┐  Inspect   ┌──────────────────────────────────┐
 │ internal/diff        │<───────────│ internal/driver/{mysql,postgres} │──> live DB
 │ Compute (no I/O)     │  Current   │  Driver = Dialect + Inspect/Exec │
 │ calls diff.Dialect   │───────────>│  uses internal/password          │
 └─────────┬────────────┘  SQL       └──────────────────────────────────┘
           │ *plan.Plan (ordered Changes of Statements, Warnings)
           v
 ┌──────────────────────┐            ┌──────────────────────┐
 │ internal/plan        │───────────>│ internal/apply       │──> live DB (Driver.Exec)
 │ Statement/Secret,    │            └──────────────────────┘
 │ Render (redaction)   │
 └──────────────────────┘
 internal/app wires the commands; the root `package main` (kong; `main.go`, `cli.go`, `version.go`) calls it; internal/di (kessoku) builds *app.App
```

### config
- **Location**: `internal/config/`
- **Interface**: `Load(path string, fns map[string]function.Function) (*Config, error)`;
  `Config{Desired *model.Desired; Engine model.Engine; DSN string}`. Errors are rendered HCL diagnostics (file:line).
- `path` is a file or a directory (all `*.hcl`, sorted, merged).
- Pass 1 resolves names (`name` attr overrides the label; `host` for MySQL accounts) and builds reference
  variables; pass 2 decodes all attributes with those variables plus the functions.
- Functions are always evaluated for real, including by `validate` (it may call cloud APIs).
- Load-time validation: engine-only attributes/blocks, duplicate declarations, grants must target declared
  databases/schemas/roles, schemas must belong to declared databases, privilege names valid per engine.
  Owners and `member_of` targets are checked later by `diff` (they may be existing, undeclared roles).

### funcs
- **Location**: `internal/funcs/`
- **Interface**: `NewRegistry(ctx, opts ...Option) *Registry`; `(*Registry).Functions() map[string]function.Function`.
  Options `WithEnv`, `WithAWS`, `WithGCP`, `WithTFState` replace backends (tests).
- Functions: `env(name, [default])`, `aws_secretsmanager(secret_id, [json_key])`,
  `gcp_secretmanager(name, [version])`, `tfstate(url, address)` (dynamic value), plus a cty stdlib subset
  (`jsondecode`, `jsonencode`, `format`, `lookup`, `join`, `split`, `base64decode/encode`, `merge`, …).
- Results of aws/gcp/tfstate are memoized per Registry by (function, args); clients are built lazily once.
  Each tfstate URL is read once.

### driver/postgres, driver/mysql
- **Location**: `internal/driver/<engine>/`. Each package has a `Driver` (connection: `Open`, `Inspect`,
  `Exec`, `Close`) embedding a `Dialect` that renders SQL and knows built-in names; the Dialect needs no
  connection (unit tests use `postgres.Dialect{}` / `mysql.Dialect{}` directly).
- **Research**: tech-pgx / tech-go-sql-driver-mysql, tech-password-hashing.

### password
- **Location**: `internal/password/`. `MatchPostgres(verifier, user, plain) (bool, error)`,
  `MatchMySQL(plugin string, authString []byte, plain string) (bool, error)`; unknown formats return `ErrUnsupported`.

### diff / plan / apply / app
- **diff** (`internal/diff/`): `Compute(desired *model.Desired, current *model.Current, d Dialect, opts Options) (*plan.Plan, error)` — no I/O.
- **plan** (`internal/plan/`): `Statement`, `Secret`, `Change`, `Plan`, `Render(w, showSecrets)`.
- **apply** (`internal/apply/`): `Run(ctx, Executor, *plan.Plan, w, showSecrets)` — sequential, no transaction, stops at the first error.
- **app** (`internal/app/`): `Validate`, `Plan`, `Apply`; owns the `Driver`/`Opener` interfaces and the confirmation prompt.

## Interface Contracts

```go
// internal/model
type Engine string // "mysql" | "postgres"
type RoleID struct{ Name, Host string } // Host "" on PG; String() = "name" or "name@host"

type Database struct {
    Name string
    Owner, Encoding, LcCollate, LcCtype string // PG only
    Charset, Collation string                  // MySQL only
}
type Role struct { // desired; nil pointer = unmanaged
    Login    *bool
    Password *string
    Superuser, CreateDB, CreateRole, Inherit, Replication, BypassRLS *bool // PG only
    ConnectionLimit *int                                                  // PG only
    ID         RoleID
    AuthPlugin string   // MySQL only
    MemberOf   []RoleID // nil = memberships unmanaged
}
type RoleState struct { // current
    ID RoleID; AuthPlugin string
    PasswordHash []byte; PasswordReadable bool
    MemberOf []RoleID
    Login, Superuser, CreateDB, CreateRole, Inherit, Replication, BypassRLS bool; ConnectionLimit int
}
type Schema struct{ Database, Name, Owner string } // PG only
type ObjectType string // "database" | "schema"
type Object struct{ Type ObjectType; Database, Schema string }
type Privilege struct{ Grantee RoleID; Object Object; Name string; GrantOption bool }
type Ignore struct{ Roles, Databases, Schemas []string }
type Desired struct{ Engine Engine; Databases []Database; Roles []Role; Schemas []Schema; Privileges []Privilege; Ignore Ignore }
type Current struct {
    CurrentUser RoleID // never reported or pruned
    Databases []Database; Roles []RoleState
    Schemas []Schema; Privileges []Privilege // schemas only for inspected databases
    InspectedDatabases []string
}

// internal/plan
type Secret string // SQL fragment shown as '<redacted>' unless showSecrets
type Statement struct{ Database string /* "" = configured connection */ ; parts []any }
func SQL(database string, parts ...any) Statement // parts: string | Secret
func (s Statement) SQL() string                   // executable text
func (s Statement) Display(showSecrets bool) string
type Action string // create | update | drop | grant | revoke
type Change struct{ Action Action; Resource string; Statements []Statement }
type Plan struct{ Changes []Change; Warnings []string }

// internal/diff
type Options struct{ Prune, ForcePassword bool }
type Dialect interface {
    IsSystemRole(id model.RoleID) bool
    IsSystemDatabase(name string) bool
    IsSystemSchema(name string) bool
    CreateRole(r model.Role) []plan.Statement
    AlterRole(r model.Role, cur model.RoleState, force bool) ([]plan.Statement, []string) // includes password compare
    DropRole(id model.RoleID, survivingDatabases []string) []plan.Statement
    GrantMembership(member, role model.RoleID) []plan.Statement
    RevokeMembership(member, role model.RoleID) []plan.Statement
    CreateDatabase(db model.Database) []plan.Statement
    AlterDatabase(db, cur model.Database) ([]plan.Statement, []string)
    DropDatabase(name string) []plan.Statement
    CreateSchema(s model.Schema) []plan.Statement
    AlterSchema(s, cur model.Schema) []plan.Statement
    DropSchema(s model.Schema) []plan.Statement
    Grant(grantee model.RoleID, obj model.Object, privs []string, grantOption bool) []plan.Statement
    Revoke(grantee model.RoleID, obj model.Object, privs []string) []plan.Statement
    RevokeGrantOption(grantee model.RoleID, obj model.Object, privs []string) []plan.Statement
}

// internal/app
type Driver interface {
    diff.Dialect
    Inspect(ctx context.Context, desired *model.Desired) (*model.Current, error)
    Exec(ctx context.Context, database, query string) error
    Close() error
}
type Opener interface{ Open(ctx context.Context, engine model.Engine, dsn string) (Driver, error) }

// internal/funcs
type AWSSecretsManager interface{ GetSecretString(ctx context.Context, secretID string) (string, error) }
type GCPSecretManager interface{ AccessSecretVersion(ctx context.Context, name string) (string, error) }
type TFState interface{ Lookup(ctx context.Context, url, address string) ([]byte, error) } // JSON value
```

## Data Model (HCL schema v1)

| Block | Labels | Attributes | Engine |
|-------|--------|------------|--------|
| `connection` | none (exactly one) | `engine` (req, `mysql`/`postgres`), `dsn` (req) | both |
| `database` | name | `name`; PG: `owner`, `encoding`, `lc_collate`, `lc_ctype`; MySQL: `charset`, `collation` | both |
| `role` / `user` | name (shared namespace) | `name`, `login` (default: `user` true, `role` false), `password`, `member_of` (list of ids); PG: `superuser`, `createdb`, `createrole`, `inherit`, `replication`, `bypassrls`, `connection_limit`; MySQL: `host` (default `"%"`), `auth_plugin` | both |
| `schema` | name | `name`, `database` (req), `owner` | PG only |
| `grant` | none | `role` (req, id), `database` (req), `schema` (PG only, optional), `privileges` (req, list), `with_grant_option` | both |
| `ignore` | none | `roles`, `databases`, `schemas` (lists of regexps, anchored full match) | both |

- `role` and `user` are synonyms on both engines; they differ only in the `login` default. On MySQL both
  become accounts via `CREATE USER` (a non-login `role` gets `ACCOUNT LOCK`); there is no `CREATE ROLE` path.
- References: `role.<l>` / `user.<l>` expose `name`, `host`, `id` (`id` = `"name@host"` on MySQL, `name` on PG);
  `database.<l>.name`; `schema.<l>.name` and `schema.<l>.database`. Referencing an undeclared label is an HCL error.
- `member_of` and `grant.role` take ids; on MySQL a string `"name@host"` is parsed (host defaults to `%`).
- Privileges are upper-cased, whitespace-normalized and deduplicated; `ALL` / `ALL PRIVILEGES` expand to the
  engine's set; PG `TEMP` → `TEMPORARY`. v1 objects: database (MySQL `` `db`.* ``; PG `CONNECT, CREATE, TEMPORARY`)
  and schema (PG `CREATE, USAGE`).
- `ignore.roles` matches the role name, or on MySQL also `name@host`; `ignore.schemas` matches the schema name.

### Diff semantics

- Declared objects missing on the server → create; differing managed attributes → update.
- Privileges of declared roles on declared databases/schemas that are not declared are **revoked**.
  Grant option differences are converged (grant `WITH GRANT OPTION` / `REVOKE GRANT OPTION`).
  On PG, privileges held by the object owner are implicit and ignored.
- If `member_of` is set, undeclared memberships of that role are revoked; if omitted, memberships are unmanaged.
- Unmanaged roles/databases/schemas (schemas only inside declared, existing databases) → warning;
  `--prune` drops them. Built-in/system objects (`Dialect.IsSystem*`), `ignore` matches and the connected user
  are never reported. Built-ins are not filtered from `Current`, so a declared built-in is diffed normally.
- Owners and `member_of` targets must be declared or exist; otherwise `Compute` returns an error.
- PG `encoding`/`lc_collate`/`lc_ctype` are create-only; a difference produces a warning.
- Passwords: compared via `internal/password` when the stored verifier is readable. Unreadable (PG non-superuser)
  or unsupported format → warning per role, no change; `--force-password` always sets declared passwords.
  MySQL: declaring a different `auth_plugin` forces a password reset.

### Inspect queries

- **PostgreSQL** (configured connection): `current_user`; `pg_database` (non-template, connectable:
  owner, encoding, datcollate, datctype); `pg_roles` (login and role attributes); `pg_authid.rolpassword`
  (on error ⇒ all roles `PasswordReadable=false`); `pg_auth_members`; `aclexplode(datacl)` joined to `pg_roles`
  (PUBLIC ignored). For each declared database that exists: a separate connection (DSN dbname replaced,
  cached, max 1 conn) reads `pg_namespace` (excluding `pg_*`, `information_schema`) and `aclexplode(nspacl)`.
- **MySQL** (single connection, `SetMaxOpenConns(1)`): `@@SESSION.sql_mode` (`NO_BACKSLASH_ESCAPES` drives
  literal escaping), `CURRENT_USER()`, `information_schema.SCHEMATA`, `mysql.user`
  (`User, Host, plugin, HEX(authentication_string), account_locked`; login = not locked), `mysql.role_edges`,
  `mysql.db` (per-column `*_priv` flags; `Grant_priv` is the grant option for the whole db level).
  Global (`*.*`) privileges are not inspected.

### Statement order (plan)

Changes are stable-sorted by phase (generation order is kept within a phase):

1. roles (CREATE / ALTER)
2. databases (CREATE / ALTER)
3. memberships (GRANT / REVOKE; MySQL also `SET DEFAULT ROLE ALL TO <member>`)
4. schemas (CREATE / ALTER OWNER, run in the target database)
5. grants
6. revokes (privileges and grant options)
7. drop schemas (`--prune`)
8. drop databases (`--prune`)
9. drop roles (`--prune`; PG first runs `REASSIGN OWNED BY x TO CURRENT_USER` and `DROP OWNED BY x`
   in every surviving connectable database)

### Output

```text
-- warning: unmanaged role "foo" (use --prune to drop it)

-- [create] role "app"
CREATE ROLE "app" WITH LOGIN PASSWORD '<redacted>';

-- [create] schema "api" in database "app"
-- (on database "app")
CREATE SCHEMA "api" AUTHORIZATION "owner";
```

An empty plan prints `-- No changes. The server matches the configuration.` `apply` prints the plan,
asks `Apply these changes? Only 'yes' is accepted:` unless `--auto-approve`, then runs statements
sequentially without a transaction (`[n/total] <redacted SQL>`), stopping at the first error.

### CLI

`dbfence {validate|plan|apply}` (kong). Common: `-f/--file` (env `DBFENCE_FILE`, default `dbfence.hcl`).
`plan`/`apply`: `--prune`, `--force-password`, `--show-secrets`. `plan --detailed-exitcode` (exit 2 on changes).
`apply --auto-approve`. `--version`. Exit codes: 0 ok, 1 error, 2 changes (with `--detailed-exitcode`).

## Open Questions

- [ ] Global (`*.*`) MySQL privileges: not inspected in v1.
- [ ] Multiple `connection` blocks (multi-server) — v1 accepts exactly one.
- [ ] Table-level grants / `ALTER DEFAULT PRIVILEGES`.

---
<!-- Below this line = L4 (deep reference) -->

## Alternatives Considered

### State file (Terraform-style)
- **Rejected because**: users want drift always visible; no locking/storage concerns.

### YAML/TOML config
- **Rejected because**: no expression language for secrets/references.

### Regex-based redaction of printed SQL
- **Rejected because**: fails for escaped literals; structured `plan.Secret` fragments are exact.

### cty sensitive marks
- **Rejected during implementation**: the only secret that reaches output is the password literal in SQL,
  which is already structural; marks added complexity without closing a real leak.

### `database/sql` pooling across PG databases
- **Rejected because**: PG cannot switch database on a connection; one `*sql.DB` per database, opened lazily, closed at end.

## Migration Plan

1. Greenfield — no migration. Rollback = do not run `apply`; every `apply` is preceded by a reviewable plan.

## ADR Log

| Date | Decision | Context | Consequences |
|------|----------|---------|--------------|
| 2026-10-23 | MySQL + PostgreSQL only | User decision; SQLite has no users/grants | No sqlite deps |
| 2026-10-23 | Warn on unmanaged, `--prune` to drop | Safe adoption of existing servers | Built-in exclusion lists required |
| 2026-10-23 | Hash comparison with fallback | Managed DBs hide hashes | `--force-password` escape hatch |
| 2026-10-23 | `role`/`user` synonyms on both engines (shared namespace) | Simpler than engine-specific blocks | MySQL roles are locked accounts via `CREATE USER` |
| 2026-10-23 | Undeclared privileges on declared objects are revoked | Grants are fully declarative for managed pairs | Only owner privileges (PG) are implicit |
| 2026-10-23 | No cty marks; `validate` evaluates functions | Redaction is structural in `plan.Statement` | `validate` may call cloud APIs |
| 2026-10-23 | kong CLI instead of stdlib `flag` | Env-backed flags, help, `--version` | New dependency |
| 2026-10-23 | No transactions in apply | CREATE/DROP DATABASE cannot run in one; MySQL DCL auto-commits | Partial apply possible; re-plan shows the rest |
| 2026-10-23 | dockertest + kumo for tests | Real servers / real AWS SDK paths | Integration tests need Docker (required in CI) |

## Addendum: MySQL without system-table access

`Inspect` treats MySQL access-denied errors (1044/1142/1143/1227) on `mysql.user`, `mysql.role_edges` and `mysql.db` as missing knowledge, not as failures. It records them in `model.Current.Unreadable`:

- `RoleAttributes`: `mysql.user` can't be read. Accounts come from `information_schema.USER_ATTRIBUTES` and are marked `RoleState.AttributesUnknown`. MySQL `AlterRole` then emits nothing, unless `--force-password` is set.
- `Roles`: the account list is incomplete. That is either `USER_ATTRIBUTES` being denied or missing, or it showing only the current account. `diff` uses `Dialect.EnsureRole` (`CREATE USER IF NOT EXISTS`) and skips reference checks and role pruning.
- `Memberships` / `Privileges`: the declared items are re-granted (idempotent), and nothing is revoked.

`diff.warnUnreadable` emits one warning per facet. Plans do not converge while any facet is unreadable. Covered by `TestComputeMySQLUnreadable` and the dockertest `TestMySQLWithoutSystemTableAccess`.

