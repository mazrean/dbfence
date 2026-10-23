# dbfence

Declarative management of the *outer frame* of MySQL and PostgreSQL servers —
databases, users / roles, role memberships, privileges and PostgreSQL schemas —
written in HCL. Tables are out of scope; use your schema migration tool for those.

- `plan` compares the configuration with the live server and prints the SQL it would run (dry run). Passwords are redacted.
- `apply` runs that SQL.
- dbfence keeps no state file. It always compares the HCL with the live server.

Supported engines: MySQL 8.0+ and PostgreSQL. Membership `inherit` / `set` options need PostgreSQL 16+.

## Install

```sh
go install github.com/mazrean/dbfence@latest
```

## Usage

```sh
dbfence validate -f dbfence.hcl          # load and evaluate the configuration
dbfence plan     -f dbfence.hcl          # dry run: print the SQL
dbfence apply    -f dbfence.hcl          # print the SQL, ask for "yes", then execute
```

| Flag | Commands | Meaning |
|---|---|---|
| `-f`, `--file` (`$DBFENCE_FILE`) | all | A configuration file, or a directory of `*.hcl` files (default `dbfence.hcl`; an empty value also means the default) |
| `--prune` | plan, apply | Drop databases, schemas and roles that are not declared (without it they only produce warnings) |
| `--force-password` | plan, apply | Set declared passwords even if they cannot be verified or already match. The plan then always contains a password statement for every role that declares one |
| `--show-secrets` | plan, apply | Print passwords instead of `'<redacted>'` |
| `--detailed-exitcode` | plan | Exit with 2 when there are changes. Warnings alone exit with 0 |
| `--auto-approve` | apply | Skip the confirmation prompt |
| `--version` | — | Print the version |

### Output and exit codes

`plan` writes annotated SQL to stdout (abridged):

```sql
-- warning: unmanaged user "stray" (use --prune to drop it)

-- [create] user "app"
CREATE ROLE "app" WITH LOGIN CONNECTION LIMIT 20 PASSWORD '<redacted>';

-- [create] schema "api" in database "app"
-- (on database "app")
CREATE SCHEMA "api" AUTHORIZATION "app_owner";

-- ...

-- [revoke] CONNECT, TEMPORARY on database "app" from PUBLIC
REVOKE CONNECT, TEMPORARY ON DATABASE "app" FROM PUBLIC;

-- Plan: 5 to create, 0 to change, 4 to grant, 1 to revoke, 0 to drop (10 statements).
```

- Each change starts with `-- [create|update|grant|revoke|drop] <resource>`. Statements that must run in another database are preceded by `-- (on database "x")`.
- Unmanaged roles are reported as `unmanaged user "x"` when they can log in, and `unmanaged role "x"` otherwise.
- A PostgreSQL revoke that cascades is preceded by `-- CASCADE: privileges on <object> that "<grantor>" granted to ... are revoked too; declared ones are granted again` (or `memberships in "<role>" that ...`). Such explanatory comment lines are only printed; they are not part of the SQL sent to the server.
- When something is dropped, the summary is followed by `-- DESTRUCTIVE: this plan drops N objects: ...`.
- An empty plan prints `-- No changes. The server matches the configuration.`, or, when there are warnings, `-- No changes to apply. See the N warnings above ...`.
- Warnings are also written to stderr as `warning: ...`, so they stay visible when stdout is redirected.
- Control characters in names read from the server, such as escape sequences or line breaks, are printed as Go escapes (`\x1b`, `\n`) in the plan, warnings, `apply` progress and errors. The SQL sent to the server is unchanged.

`apply` prints the same plan, asks for `yes` (anything else, or a closed stdin, cancels with exit 1), and prints `[k/N] <statement>` for each statement (its comment lines first). Statements run one by one, without a transaction, and apply stops at the first error. The error says how many statements were applied; run `plan` again to see what is left. An interrupted apply stops before the next statement, and the error ends with the cause, such as `interrupt signal received`.

`validate` prints a summary such as `The configuration is valid (postgres: 1 database, 3 roles, 1 schema, 3 privileges).`

Errors are printed to stderr as `dbfence: error: ...` (configuration diagnostics follow unindented) and exit with 1. `plan --detailed-exitcode` exits with 2 when the plan has changes; everything else that succeeds exits with 0.

## Configuration

```hcl
connection {
  engine = "postgres"                                   # "postgres" or "mysql"
  dsn    = format("postgres://%s:%s@db.internal:5432/postgres", urlencode("admin"), urlencode(secretenv("PGPASSWORD")))
}

role "app_owner" {}                                    # role: NOLOGIN

user "app" {                                           # user: LOGIN
  password         = jsondecode(gcp_secretmanager("projects/p/secrets/app")).password
  member_of        = [role.readonly.id, { role = role.app_owner.id, inherit = false }]
  connection_limit = 20                                # PostgreSQL only
}

role "readonly" {}

database "app" {
  owner    = role.app_owner.name                       # PostgreSQL only
  encoding = "UTF8"                                    # PostgreSQL: encoding / lc_collate / lc_ctype
}

schema "api" {                                         # PostgreSQL only
  database = database.app.name
  owner    = role.app_owner.name
}

grant {
  role       = user.app.id
  database   = database.app.name
  privileges = ["CONNECT", "TEMPORARY"]
}

grant {
  role       = role.readonly.id
  database   = schema.api.database
  schema     = schema.api.name
  privileges = ["USAGE"]
}

grant {                                                # PostgreSQL only: undeclared roles may not connect
  role       = "PUBLIC"
  database   = database.app.name
  privileges = []
}

ignore {                                               # unmanaged objects to neither warn about nor prune
  roles = ["datadog", "rds_.*"]                        # anchored regular expressions
}
```

A MySQL `dsn` is a go-sql-driver/mysql DSN such as `admin:pw@tcp(db.internal:3306)/`. The `mysql://` URL form is not supported. A DSN that cannot be parsed is reported as `invalid DSN` without quoting any part of it, because the driver splits it at the last `/`: a password that contains `/` needs the `/` before the database name, as in `admin:a/b@tcp(db.internal:3306)/`. The network must be `tcp`, `tcp4`, `tcp6` or `unix`.

### Blocks

- **`connection`**: required, exactly one. `engine` and `dsn` (a pgx URL/DSN, or a go-sql-driver/mysql DSN; it must not be empty).
  Connecting times out after 10 seconds unless the DSN sets `connect_timeout` (PostgreSQL) or `timeout` (MySQL). On MySQL the timeout covers the handshake and session setup as well as the dial (`connect to mysql: timed out after 10s`). PostgreSQL reports a host's timeout once, even with `sslmode=prefer`.
- **`role "<label>"` / `user "<label>"`**: these two are the same thing, except for the login default.
  - `name` overrides the label. Use it, with an identifier-safe label, for names with upper case, spaces or quotes, because only such labels can be referenced (`user.<label>.name`).
  - `password`, `login` and `member_of` work on both engines.
  - PostgreSQL only: `superuser`, `createdb`, `createrole`, `inherit`, `replication`, `bypassrls` and `connection_limit` (-1 or more).
  - MySQL only: `host` (default `"%"`, lower-cased, must not be empty or contain `@`) and `auth_plugin` (letters, digits and `_`). On MySQL a non-login role is a locked account. `auth_plugin` works without a password for passwordless plugins; a login account with neither gets a warning.
  - Attributes you leave out are not managed, except `login`: it is always managed, and defaults to `false` for `role` (NOLOGIN / ACCOUNT LOCK) and `true` for `user`. Declaring an existing login account as a `role` without `login = true` disables its login.
  - `name` and `host` accept only literals and functions, not references to other blocks.
  - Names are checked against the engine limits: 63 bytes on PostgreSQL; 32 characters for MySQL users, 64 for databases and 255 for hosts. PostgreSQL role names `public` (in any case), `none` and `pg_*` are reserved.
  - `password = ""` is an error on PostgreSQL. Omit `password` to leave it unmanaged.
- **`member_of`**: a list of role ids, or objects `{ role = <id>, admin = bool, inherit = bool, set = bool }`; both can be mixed.
  - When `member_of` is set, it must be complete: memberships that aren't listed are revoked. Cycles, duplicates and self-membership are errors.
  - Options written in an object are managed; omitted ones (and the string form) are left alone.
  - `admin` (`WITH ADMIN OPTION`) works on both engines. On PostgreSQL, revoking it cascades to the memberships the member granted with it, and declared ones are granted again. On MySQL, removing it revokes the role and grants it again. The connected user's ADMIN OPTION is never revoked (a warning is printed).
  - `inherit` and `set` are PostgreSQL 16+ only (a validation error on MySQL; plan fails on older PostgreSQL). On PostgreSQL 16+ the role's `inherit` attribute is only the default for new grants, so dbfence also sets `inherit` on the role's existing memberships to match, except those that declare their own `inherit`. A warning is printed while the two disagree.
  - On PostgreSQL 16+ each grantor's grant is changed with `GRANTED BY`; an option counts as held when any grant has it.
  - On MySQL the declared `member_of` becomes exactly the account's default roles (`SET DEFAULT ROLE`), so the roles are active without `SET ROLE`. The connected account's default roles are never narrowed: they also keep the memberships it keeps and its current default roles.
- **`database "<label>"`**: `name`, `owner`, `encoding`, `lc_collate` and `lc_ctype` (PostgreSQL; the last three are create-only; none may be empty), or `charset` and `collation` (MySQL; letters, digits and `_`).
- **`schema "<label>"`**: PostgreSQL only. Takes `database`, `name` and `owner`. `schema "public"` (or another template schema) can also be declared in a database the plan creates; only its owner and grants are planned.
- **`grant`**: takes `role`, `database` (or `database_pattern` on MySQL), an optional `schema` (PostgreSQL), `privileges` and `with_grant_option`.
  - `ALL` expands to every privilege of that object type. `GRANT OPTION` is not a privilege; use `with_grant_option = true`.
  - A declared role's privileges on declared databases or schemas that aren't listed are revoked. Grants to an object's owner have no effect (a warning is printed).
  - The database (and schema) must be declared.
  - MySQL: only database-level privileges (`ON db.*`) are managed. Every grant block for the same account and database (or pattern) must use the same `with_grant_option`, because MySQL keeps one grant option per database. `_` and `%` in `database` names are escaped (`my\_app`), so a `database` grant never acts as a wildcard. With `partial_revokes` ON, MySQL reads names literally, so escaped rows of declared databases are revoked and granted again on the literal name.
- **`grant` with `database_pattern`** (MySQL only): a wildcard grant such as `ON tenant\_%.*`.
  - The pattern is used verbatim: `%` and `_` are wildcards and `\` escapes them (write `"tenant\\_%"` in HCL for `tenant\_%`). It needs at least one wildcard, and the databases it matches need not be declared.
  - A declared role's privileges on a declared pattern that aren't listed are revoked. Patterns that no grant block declares are not managed; a warning is printed when one held by a declared account matches a declared database.
  - MySQL does not add up database-level grants: for an account it uses only the most specific `mysql.db` row that matches a database. When an account has both a `database` grant and a matching pattern, or two matching patterns, plan warns that the pattern's privileges don't apply to that database.
  - Needs `partial_revokes` OFF (plan fails otherwise, because MySQL then reads `%` and `_` literally). Wildcards in database-level grants are deprecated since MySQL 8.2 and are to become literals in a future release.

  ```hcl
  grant {
    role             = user.app.id
    database_pattern = "tenant\\_%"          # tenant_a, tenant_b, ... (not tenantX)
    privileges       = ["SELECT", "INSERT"]
  }
  ```
- **`grant` to `PUBLIC`** (PostgreSQL only): `role = "PUBLIC"` (any case, no role block needed).
  - PUBLIC is managed only on databases and schemas that have at least one PUBLIC grant block. There, PUBLIC's undeclared privileges are revoked; elsewhere they are left alone.
  - `privileges = []` (allowed only for PUBLIC) revokes everything PUBLIC holds on that object. It cannot be combined with another PUBLIC grant block on the same object.
  - `with_grant_option = true` is invalid for PUBLIC.
  - PostgreSQL's defaults are visible: `CONNECT` and `TEMPORARY` on every database, and `USAGE` on schema `public` (`CREATE` and `USAGE` before PostgreSQL 15). To manage the `public` schema's PUBLIC grants, declare `schema "public" { database = ... }`.
  - When a role loses a privilege that PUBLIC still holds on an unmanaged object, the plan warns that the role keeps it through PUBLIC. Add a PUBLIC grant block (for example `privileges = []`) to take it away.
- **`ignore`**: takes `roles`, `databases` and `schemas` (PostgreSQL) regexps. Each pattern must be a valid regexp on its own and is anchored to the whole string; `.` also matches a newline.
  - On MySQL, `roles` patterns match the name or `name@host`: `"datadog"` ignores every host, `"datadog@%"` only the host `%` (`%` is a literal here), and `"datadog@10\\.0\\.0\\.%"` one host. An account with an empty host (shown as `"name"@""`) matches `"name@"`.
  - `schemas` patterns match the schema name or `<database>.<schema>`: `"staging"` ignores it in every database, `"analytics\\.staging"` only in `analytics` (escape the dot; an unescaped `.` matches any character).
  - Declared databases and schemas stay managed even when a pattern matches them.

References: `role.<label>` and `user.<label>` expose `name`, `host` and `id`. `id` is `name@host` on MySQL; use it in `member_of` and `grant.role`, because a bare name means `name@%`. `database.<label>.name` and `schema.<label>.name` / `.database` are also available. On MySQL, `role = "public"` without a host is an error; write `"public@%"` or use `.id`.

### What `--prune` never drops

Built-in objects are never reported or pruned:

- PostgreSQL roles `postgres`, `pg_*`, `rdsadmin`, `rdsrepladmin`, `rdstopmgr`, `rds_*`, `cloudsql*`, `azure*` and `alloydb*`; databases `postgres`, `template0`, `template1`, `rdsadmin`, `cloudsqladmin`, `azure_maintenance`, `azure_sys` and `alloydbadmin`; schemas `public`, `information_schema` and `pg_*`.
- MySQL accounts `root`, `mariadb.sys`, `debian-sys-maint`, `mysql.*`, `rds*`, `aws_*`, `cloudsql*` and `azure_*`; databases `mysql`, `sys`, `information_schema`, `performance_schema` and `ndbinfo`.

Also kept, with a warning under `--prune` (both engines; on MySQL the database is the DSN's, read through `DATABASE()`): the connected user and the database it is connected to, roles the configuration references without declaring them, roles granted to the connected user, and owners of ignored databases or schemas. Changes to the connected user that would lock it out are skipped.

PostgreSQL `--prune` of a role runs `REASSIGN OWNED BY ... TO CURRENT_USER` and `DROP OWNED` in every connectable database, then `DROP ROLE`. Privileges and memberships the pruned role granted to others are revoked by `DROP OWNED`, except grants it made while holding an owner's privileges through a membership with INHERIT. dbfence therefore revokes those memberships first (with `CASCADE` on PostgreSQL 16+ for memberships it granted from them). Afterwards it grants the declared ones again (memberships only on PostgreSQL 16+), unless the grantee still holds the privilege from another grantor such as the owner; this needs the connected user to be allowed to grant them, and a warning is printed when owner memberships or re-grants cannot be handled. Roles that own objects or hold privileges in databases dbfence cannot connect to (no `CONNECT`, `ALLOW_CONNECTIONS false`, templates, provider databases) or that are ignored are named in a warning, even without `--prune`: `DROP ROLE` fails for them until those objects are reassigned or dropped in that database.

### Functions

| Function | Returns |
|---|---|
| `env(name, [default])` | An environment variable. It is an error if the variable is unset and no default is given |
| `secretenv(name, [default])` | Like `env`, for a variable that holds a secret such as a password or DSN: its value is treated as a secret (see below) |
| `aws_secretsmanager(secret_id, [json_key])` | An AWS Secrets Manager secret string, or one key of a JSON secret (a string, number or boolean; use `jsondecode(aws_secretsmanager(id))` for objects and arrays). Standard AWS credentials and `AWS_ENDPOINT_URL` apply |
| `gcp_secretmanager(name, [version])` | A GCP Secret Manager payload. `name` is `projects/<p>/secrets/<s>[/versions/<v>]` (regional `locations/` names are not supported), and `version` defaults to `latest` |
| `tfstate(url, address)` | A value from a Terraform state on `s3://`, `gs://`, a local path, and so on. Relative paths are resolved against the configuration directory. Examples: `aws_db_instance.main.address`, `output.db_host` |
| `urlencode(str)` | `str` percent-encoded for any URL part, including the user and password of a DSN. A space becomes `%20` (not `+` as in Terraform) and `+` becomes `%2B` |

Without `urlencode`, a password containing `@ : / ? # % +` or a space produces a wrong PostgreSQL URL.

A subset of the cty standard library is also available: `abs`, `base64decode`, `base64encode`, `chomp`, `coalesce`, `concat`, `contains`, `csvdecode`, `distinct`, `flatten`, `format`, `formatlist`, `join`, `jsondecode`, `jsonencode`, `keys`, `length`, `lookup`, `lower`, `merge`, `regex`, `replace`, `split`, `substr`, `tolist`, `tomap`, `tonumber`, `toset`, `tostring`, `trimspace`, `upper` and `values`. `lookup(map, key, default)` requires all three arguments.

Results of `secretenv`, `aws_secretsmanager`, `gcp_secretmanager` and `tfstate`, and every value computed from them, are treated as secrets: when a function fails on such a value (for example `tonumber(secretenv("PW"))`), its error is replaced by `the error is not shown because the arguments include a secret value`, and a duplicate key error of a `for` expression does not show a secret-derived key. `env` is not: use `secretenv` for environment variables that hold passwords or DSNs.

Each secret is fetched once per run. Secret payloads and `base64decode` results must be valid UTF-8, and strings are NFC-normalised (a password in decomposed Unicode form reaches the server composed).

### Passwords

dbfence compares a declared password with the stored verifier without changing it:

- **PostgreSQL**: `SCRAM-SHA-256` and `md5`, read from `pg_authid`. Reading them needs superuser. Under `password_encryption = scram-sha-256` an `md5` verifier counts as a mismatch, so setting the password again upgrades it to SCRAM. A password that looks like a verifier (`md5` + 32 characters, or `SCRAM-SHA-256$...`) is an error, because PostgreSQL would store it as is.
- **MySQL**: `caching_sha2_password`, `mysql_native_password` and `sha256_password`, read from `mysql.user`. Other plugins cannot be compared and always produce a warning. When a password is declared and the account still has a secondary password kept by `RETAIN CURRENT PASSWORD` (MySQL 8.0.14+), plan adds `ALTER USER ... DISCARD OLD PASSWORD`, so that only the declared password logs in.

Passwords are sent in plaintext (`PASSWORD '...'`, `IDENTIFIED BY '...'`), so that the server hashes them with its own settings (`password_encryption`, `scram_iterations`) and password policies apply (`passwordcheck` / `credcheck`, MySQL `validate_password`). As a consequence, PostgreSQL statement logging (`log_statement = ddl` or `all`, and `log_min_error_statement` for failed statements) records the password; MySQL rewrites passwords in its logs. Disable such logging for the dbfence session or role if that matters.

When a statement with a password fails, the server's message is shown up to its first quote, and nothing after it (later lines included), because servers quote parts of the statement in their messages. Policy rejections such as `Your password does not satisfy the current policy requirements` contain no quotes and are shown in full. `--show-secrets` shows the whole message.

If the verifier can't be read (for example on RDS or Cloud SQL, where the admin is not a superuser), plan prints one warning listing the roles whose passwords are not compared. `--force-password` sets the password anyway.

### Required privileges (PostgreSQL)

Without superuser, changes the connected user may not make are not planned and produce a warning instead:

- Altering a role needs ADMIN OPTION on it (superuser for superuser roles).
- Changing a privilege grant made by another grantor needs superuser, or, for revokes, `SET` on that grantor.
- Granting or revoking a membership needs ADMIN OPTION on the role on PostgreSQL 16+ (revoking another grantor's membership grant needs superuser); before 16, ADMIN OPTION or CREATEROLE for a role that is not a superuser. Membership re-grants after a `CASCADE` follow the same rules.
- Creating schemas in, or granting on, objects owned by another role needs that owner's privileges. The warning names the `GRANT` to run: on PostgreSQL 16+ `GRANT <owner> TO <user> WITH INHERIT TRUE, SET TRUE` (`WITH SET TRUE, INHERIT FALSE` when only an owner change needs it, `WITH INHERIT TRUE` when only its privileges are needed); before 16 a plain `GRANT <owner> TO <user>`.
- Pruning a role needs the connected user to have that role's privileges; a warning names the `GRANT` to run.

Privileges and memberships are revoked per grantor.

### Required privileges (MySQL)

dbfence works best when it can read `mysql.user`, `mysql.db`, `mysql.role_edges` and `mysql.default_roles`.
If it can't read them, it falls back as follows:

| Can't read | Fallback |
|---|---|
| `mysql.user` | Accounts are listed from `information_schema.USER_ATTRIBUTES` (needs `CREATE USER`). Login state, authentication plugin and passwords of existing accounts are not compared (`--force-password` still sets the password) |
| `mysql.user`, and the account list is not complete | `USER_ATTRIBUTES` hides accounts that hold `SYSTEM_USER` unless the connected user has it too. Declared accounts are then created with `CREATE USER IF NOT EXISTS` on every run, and existing ones are not updated. Unmanaged accounts are not reported or pruned |
| `mysql.role_edges` | Declared memberships are granted on every run (`GRANT` is idempotent). Undeclared memberships are not revoked |
| `mysql.default_roles` | `SET DEFAULT ROLE` is issued on every run for declared accounts with `member_of` |
| `mysql.db` | Declared privileges are granted on every run. Undeclared privileges are not revoked |

Each fallback is reported as a warning in `plan`. Statements that are re-asserted on every run (`CREATE USER IF NOT EXISTS`, declared memberships, default roles and grants) always appear in the plan, so `--detailed-exitcode` returns 2 while there are any. A fallback with nothing to re-assert (for example, only `mysql.user` is unreadable and no password is forced) can leave the plan empty, and the exit code is then 0 despite the warnings.

## Upgrading

- MySQL: database grants written by earlier versions without escaping (`GRANT ... ON my_app.*`, a wildcard) are revoked and granted again escaped (`my\_app`). The plan shows them under `database pattern "my_app"`.
- PostgreSQL role and user names equal to `public` in any case are reserved, because grant blocks read them as PUBLIC.
- PostgreSQL passwords are sent in plaintext and hashed by the server again, so server-side password policies apply. Statement logging can record them (see Passwords).
- MySQL `role = "public"` without a host is an error; write `"public@%"`.
- PostgreSQL's default privileges of PUBLIC are now read. Where a grant block manages PUBLIC, undeclared defaults are revoked; elsewhere the only new output is the "keeps ... through PUBLIC" warning when a role loses a privilege PUBLIC still holds.

## Development

```sh
mise run test               # unit tests (-short)
mise run test:integration   # also starts MySQL 8.4 / PostgreSQL 17 containers with dockertest
mise run lint               # go tool lint ./...
mise run generate           # regenerate kessoku injectors
```
