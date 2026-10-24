---
name: managing-dbfence
description: Writes and operates dbfence HCL configurations that declaratively manage MySQL / PostgreSQL databases, users, roles, role memberships, database/schema grants and PostgreSQL schemas, and runs `dbfence validate`, `plan` and `apply` safely. Use when editing dbfence `*.hcl` files, adding or removing a database user/role/grant, locking down PUBLIC, reading a dbfence plan or its warnings, or when the user mentions dbfence.
---

# Managing dbfence

dbfence (`github.com/mazrean/dbfence`) manages the *outer frame* of a MySQL 8.0+ or PostgreSQL server
from HCL: databases, users / roles, memberships, database- and schema-level privileges, PostgreSQL schemas.
It keeps **no state file**: every run compares the HCL with the live server.

Out of scope: tables, table/column/function privileges, data. Those belong to the schema migration tool.

## Workflow

Always follow this loop. Never skip `plan`.

1. **Edit** the `*.hcl` files. dbfence reads every `*.hcl` directly in one directory (not subdirectories)
   and merges them; no other HCL (Terraform, Packer, ...) may share that directory.
2. **Validate**: `dbfence -C <dir> validate` (does not connect to the database, but evaluates every
   function, so `env` variables and secret stores must be reachable; prints a summary such as
   `The configuration is valid (postgres: 1 database, 3 roles, 1 schema, 3 privileges).`).
3. **Plan**: `dbfence -C <dir> plan` — prints the SQL it would run. Read every
   `-- warning:` line and every `-- [drop]` / `-- DESTRUCTIVE:` line; see [operations.md](references/operations.md).
4. **Show the plan to the user** and get explicit approval for anything that revokes, drops or changes a password.
5. **Apply**: `dbfence -C <dir> apply`. It asks for `yes` on stdin; a closed stdin cancels with exit 1.
   An agent without a TTY needs `--auto-approve` — only use it right after the user approved the
   exact plan just printed, with no HCL change in between.
6. **Re-plan** to confirm `-- No changes. The server matches the configuration.`

In CI or checks: `dbfence plan --detailed-exitcode` → 0 no changes, 2 changes, 1 error.

## Minimal configuration

```hcl
connection "postgres" {                 # or "mysql"; exactly one per directory
  host     = env("DB_HOST")
  user     = "admin"
  password = secretenv("DB_ADMIN_PASSWORD")
  tls      = "verify-full"
}

role "app_owner" {}                     # role = NOLOGIN (MySQL: ACCOUNT LOCK)
role "readonly" {}

user "app" {                            # user = LOGIN
  password  = aws_secretsmanager("prod/db/app", "password")
  member_of = [role.readonly.id]
}

database "app" {
  owner = role.app_owner.name           # PostgreSQL only
}

grant {
  role       = user.app.id
  database   = database.app.name
  privileges = ["CONNECT", "TEMPORARY"]
}
```

Blocks: `connection`, `role`, `user`, `database`, `schema` (PostgreSQL), `grant`, `ignore`.
Full attribute list: [hcl-reference.md](references/hcl-reference.md). Ready-made patterns: [recipes.md](references/recipes.md).

## Rules agents get wrong

The syntax looks like Terraform, but the semantics are not.

- **No `variable`, `locals`, `output`, `module`, `count`, `for_each`, `var.`**. Only literals, references to
  declared blocks, and the functions in [hcl-reference.md](references/hcl-reference.md#functions).
  Parameterise with `env(...)` instead.
- **Passwords**: use `secretenv`, `aws_secretsmanager`, `gcp_secretmanager` or `tfstate` — never a literal
  committed to the repo and never `env` (its value is not redacted). Never pass `--show-secrets`.
  Omit `password` to leave it unmanaged; `password = ""` is an error on PostgreSQL.
- **`role` and `user` are the same block** except the `login` default (`false` / `true`). `login` is
  *always* managed: declaring an existing login account as `role` without `login = true` disables its login.
- **Lists are complete, not additive**:
  - `member_of`, once set, is the full membership list; unlisted memberships are revoked.
    (MySQL: it also becomes exactly the account's default roles.)
  - On every declared database/schema, a declared role's privileges not listed in a `grant` block are revoked.
  - Omitting `member_of` or an attribute leaves it unmanaged (except `login`).
- **References**: `role.<label>` / `user.<label>` expose `name`, `host`, `id`; `database.<label>.name`;
  `schema.<label>.name` / `.database`. Use `.id` in `member_of` and `grant.role` (on MySQL `id` is
  `name@host`; a bare name means `name@%`). Use `.name` for `owner` and `database`.
  `name` and `host` accept only literals and functions, not references.
- **Labels must be identifier-safe**. For names with upper case, dots, spaces: `user "analyst" { name = "analyst.alice" }`.
- **Grant targets must be declared**: the `database` (and `schema`) of a `grant` must have its own block
  (except MySQL `database_pattern`). Grants to an object's owner have no effect.
- **`ALL`** expands to every privilege of that object type. `GRANT OPTION` is not a privilege;
  use `with_grant_option = true`.
- **Engine-only attributes** are validation errors on the other engine. PostgreSQL only: `schema` blocks,
  `owner`, `encoding`/`lc_*`, `superuser`, `createdb`, `createrole`, `inherit`, `replication`, `bypassrls`,
  `connection_limit`, `inherit`/`set` in `member_of` (16+), `role = "PUBLIC"`. MySQL only: `host`,
  `auth_plugin`, `charset`, `collation`, `database_pattern`, `connection.socket`.
- **MySQL patterns**: `database_pattern = "tenant\\_%"` (HCL `\\` → SQL `\`). `database` names are escaped
  automatically and never act as wildcards. MySQL uses only the most specific `mysql.db` row per account
  and database, so a role does not add up a pattern grant and a database grant.
- **PostgreSQL PUBLIC**: PUBLIC holds `CONNECT`, `TEMPORARY` on every database and `USAGE` on schema `public`
  by default. Lock down with `grant { role = "PUBLIC", database = ..., privileges = [] }`; to manage
  schema `public`, declare `schema "public" { database = database.app.name }`.

## Dropping things

- Removing a block does **not** drop the object; plan prints `-- warning: unmanaged user "x" (use --prune to drop it)`.
- `--prune` drops undeclared databases, schemas and roles. Treat it as destructive: plan with `--prune`
  first, show the `-- DESTRUCTIVE:` summary, and apply only with the user's explicit consent.
- To silence warnings for objects managed elsewhere (monitoring agents, cloud-provider roles), add
  `ignore { roles = ["datadog", "rds_.*"] }` (anchored regexps). Built-in objects are never reported or pruned.
- `--prune` cannot be combined with `--target`.

## Partial changes

`--target role.<label>` / `user.<label>` / `database.<label>` / `schema.<label>` (repeatable) plans only that
block's changes plus the creates they need. `grant` and `ignore` have no address. Run a full `plan`
afterwards to see what is left.

## Errors

- `dbfence: error: ...` + exit 1: configuration or connection error; fix the HCL and re-run `validate`.
- `internal safety check failed: ... (this is a bug in dbfence; please report it)`: apply executes nothing.
  Do not try to work around it; report it to the user.
- A failed `apply` stops at the first error and says how many statements ran (no transaction). Run `plan`
  again to see what is left.

## Support files

- [references/hcl-reference.md](references/hcl-reference.md): every block, attribute, reference and function, per engine.
- [references/recipes.md](references/recipes.md): PostgreSQL and MySQL patterns (owner/bundle roles, migrator,
  PUBLIC lock-down, host-restricted accounts, wildcard grants, IAM users, ignore).
- [references/operations.md](references/operations.md): CLI flags, plan output format, exit codes,
  common warnings and fixes, required server privileges.
