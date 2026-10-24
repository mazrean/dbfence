# dbfence HCL reference

## Contents

- [Files](#files)
- [connection](#connection)
- [role / user](#role--user)
- [member_of](#member_of)
- [database](#database)
- [schema (PostgreSQL)](#schema-postgresql)
- [grant](#grant)
- [ignore](#ignore)
- [References](#references)
- [Functions](#functions)
- [Name limits](#name-limits)

Legend: **PG** = PostgreSQL only, **My** = MySQL only. Using an engine-only attribute on the other engine is a
validation error.

## Files

- Every `*.hcl` file directly in the configuration directory (`-C DIR`, default `.`) is merged into one
  configuration. Subdirectories are not read. Splitting into `connection.hcl`, `roles.hcl`, `databases.hcl`,
  `grants.hcl` is only for readability.
- There are no `variable`, `locals`, `output`, `module`, `provider`, `count`, `for_each` or `dynamic`
  constructs. Expressions may use literals, references (below), functions, and HCL operators/conditionals/`for`.

## connection

Exactly one; the label is the engine: `connection "postgres"` or `connection "mysql"`.

| Attribute | Notes |
|---|---|
| `host` | Required, not empty. PG: a value starting with `/` is a Unix socket directory |
| `socket` | **My**: Unix socket path instead of `host`/`port` |
| `user` | Required, not empty |
| `port` | Default 5432 / 3306 |
| `database` | PG default `"postgres"`; My: none. On MySQL it is the database `--prune` keeps as "connected" |
| `tls` | `"disable"`, `"prefer"`, `"require"`, `"verify-full"`; PG also `"allow"`, `"verify-ca"`. Default `"prefer"`, `"require"` with IAM, `"disable"` with `socket`. `"verify-full"` cannot be used with `socket` |
| `tls_ca_file` | PEM CA bundle (e.g. RDS / Cloud SQL), only with `verify-ca`/`verify-full`. Relative to the config dir |
| `connect_timeout` | Seconds, default 10 |
| `password` | Optional; without it (and without IAM) connects without a password |
| `aws_iam { region = "..." }` | Block: RDS IAM auth token for `host`/`port`/`user`. `region` defaults to `AWS_REGION`. Needs `host` |
| `gcp_iam {}` | Block: Cloud SQL IAM access token from application default credentials. `user` is the IAM database user name |

Use one of `password`, `aws_iam`, `gcp_iam`. IAM tokens are sent as cleartext passwords, so `tls` must be
`"require"` or a verifying mode (except over a MySQL `socket`).

PostgreSQL `PG*` env vars and `~/.pgpass` are **not** read for these attributes; TLS cert settings
(`PGSSLROOTCERT`, `PGSSLCERT`, `PGSSLKEY`, `~/.postgresql/`), `PGOPTIONS`, `PGSERVICE` still apply.

## role / user

`role "<label>"` and `user "<label>"` are the same block; `login` defaults to `false` for `role`
(PG `NOLOGIN`, My `ACCOUNT LOCK`) and `true` for `user`. Role and user labels share one namespace.

| Attribute | Engine | Notes |
|---|---|---|
| `name` | both | Overrides the label. Literal or function only |
| `login` | both | Always managed (see default above) |
| `password` | both | Omit to leave unmanaged. `""` is an error on PG. A value that looks like a verifier (`md5…`, `SCRAM-SHA-256$…`) is an error |
| `member_of` | both | See below |
| `superuser`, `createdb`, `createrole`, `inherit`, `replication`, `bypassrls` | **PG** | bool |
| `connection_limit` | **PG** | -1 or more |
| `host` | **My** | Default `"%"`, lower-cased, not empty, no `@`. Literal or function only |
| `auth_plugin` | **My** | Letters, digits, `_`. Works without `password` for passwordless plugins |
| `aws_iam {}` | both | Block: logs in with an RDS IAM token. PG: member of `rds_iam` (granted automatically, not needed in `member_of`); My: `IDENTIFIED WITH AWSAuthenticationPlugin AS 'RDS'`. Not with `password`/`auth_plugin`; needs login |
| `gcp_iam {}` | both | Block: an **existing** Cloud SQL IAM user/service account/group (dbfence never creates it; create with `gcloud sql users create NAME --instance=INSTANCE --type=cloud_iam_user` or Terraform). Set `name` to the Cloud SQL DB user name (PG: the email, without `.gserviceaccount.com` for a service account; My: part before `@`). A group is a `role`. Not with `password`/`auth_plugin`/`aws_iam` |

Attributes left out are not managed, except `login`.

## member_of

A list mixing role ids and objects:

```hcl
member_of = [
  role.readonly.id,
  { role = role.app_owner.id, admin = false, inherit = false, set = true },
]
```

- Once set it is **complete**: unlisted memberships are revoked. Cycles, duplicates, self-membership are errors.
- Options written in an object are managed; omitted options (and the string form) are left alone.
- `admin` (`WITH ADMIN OPTION`): both engines.
- `inherit`, `set`: **PG 16+** only (validation error on MySQL; plan fails on older PostgreSQL).
- MySQL: `member_of` becomes exactly the account's default roles (`SET DEFAULT ROLE`), so roles are active
  without `SET ROLE`.
- The connected user's own ADMIN OPTION / INHERIT / SET are never removed (warning instead).

## database

| Attribute | Engine | Notes |
|---|---|---|
| `name` | both | Overrides the label |
| `owner` | **PG** | Use `role.<label>.name` |
| `encoding`, `lc_collate`, `lc_ctype` | **PG** | Create-only; not empty |
| `charset`, `collation` | **My** | Letters, digits, `_` |

## schema (PostgreSQL)

| Attribute | Notes |
|---|---|
| `database` | Required: `database.<label>.name` |
| `name` | Overrides the label |
| `owner` | `role.<label>.name` |

`schema "public" { database = ... }` (or another template schema) can be declared to manage its owner and
grants, including in a database the plan creates.

## grant

| Attribute | Notes |
|---|---|
| `role` | `role.<label>.id` / `user.<label>.id`, or `"PUBLIC"` (**PG**, any case, no block needed) |
| `database` | `database.<label>.name` (or `schema.<label>.database`). Must be declared |
| `database_pattern` | **My**, instead of `database`: verbatim wildcard (`%`, `_`; `\` escapes). Needs at least one wildcard; matched databases need not be declared |
| `schema` | **PG**: `schema.<label>.name`. Must be declared |
| `privileges` | List of privilege names; `"ALL"` expands to all of the object type. `[]` only for PUBLIC |
| `with_grant_option` | bool. Invalid for PUBLIC |

Semantics:

- A declared role's privileges on declared databases/schemas (and declared patterns) that no grant block
  lists are revoked.
- Grants to the object's owner have no effect (warning).
- MySQL: only database-level privileges (`ON db.*`). All grant blocks for the same account and database
  (or pattern) must use the same `with_grant_option`. `_`/`%` in `database` are escaped, never wildcards.
  `database_pattern` needs `partial_revokes` OFF.
- MySQL: for one account, only the most specific matching `mysql.db` row applies; plan warns when a pattern
  and a database grant (or two patterns) overlap.
- PG PUBLIC: managed only on objects that have at least one PUBLIC grant block; there, PUBLIC's undeclared
  privileges are revoked. `privileges = []` revokes everything PUBLIC holds and cannot be combined with
  another PUBLIC block on the same object.

Valid privileges (case-insensitive; `ALL` / `ALL PRIVILEGES` expands to the whole list; anything else is
a validation error):

- PG database: `CONNECT`, `CREATE`, `TEMPORARY` (`TEMP` accepted)
- PG schema: `CREATE`, `USAGE`
- MySQL database: `ALTER`, `ALTER ROUTINE`, `CREATE`, `CREATE ROUTINE`, `CREATE TEMPORARY TABLES`,
  `CREATE VIEW`, `DELETE`, `DROP`, `EVENT`, `EXECUTE`, `INDEX`, `INSERT`, `LOCK TABLES`, `REFERENCES`,
  `SELECT`, `SHOW VIEW`, `TRIGGER`, `UPDATE`

Table-level privileges (`SELECT` on PG tables, etc.) are out of scope: grant them from migrations.

## ignore

```hcl
ignore {
  roles     = ["datadog", "rds_.*"]
  databases = ["scratch_.*"]
  schemas   = ["staging", "analytics\\.staging"]   # PG only
}
```

- Anchored regular expressions (the whole name must match; `.` also matches a newline).
- Ignored objects are neither warned about nor pruned. Declared databases and schemas stay managed even
  when a pattern matches them.
- MySQL `roles` match the name or `name@host`: `"datadog"` (every host), `"datadog@%"` (only host `%`,
  literal), `"datadog@10\\.0\\.0\\.%"`. Empty host: `"name@"`.
- `schemas` match the schema name or `<database>.<schema>` (escape the dot).

## References

| Expression | Value |
|---|---|
| `role.<label>.name`, `user.<label>.name` | Role name |
| `role.<label>.host`, `user.<label>.host` | MySQL host |
| `role.<label>.id`, `user.<label>.id` | PG: name; My: `name@host`. Use in `member_of` and `grant.role` |
| `database.<label>.name` | Database name |
| `schema.<label>.name`, `schema.<label>.database` | Schema name, its database |

On MySQL, `role = "public"` without host is an error; write `"public@%"` or use `.id`.

## Functions

| Function | Returns |
|---|---|
| `env(name, [default])` | Environment variable; error if unset without default. **Not** a secret |
| `secretenv(name, [default])` | Like `env`, but the value is a redacted secret. Use for passwords |
| `aws_secretsmanager(secret_id, [json_key])` | Secrets Manager string, or one key of a JSON secret (string/number/bool; use `jsondecode(aws_secretsmanager(id))` for objects). Standard AWS credentials and `AWS_ENDPOINT_URL` apply |
| `gcp_secretmanager(name, [version])` | Secret Manager payload. `name` = `projects/<p>/secrets/<s>[/versions/<v>]` (no `locations/`); `version` default `latest` |
| `tfstate(url, address)` | A value from Terraform state (`s3://`, `gs://`, local path, ...; relative to the config dir), e.g. `tfstate("s3://b/k.tfstate", "aws_db_instance.main.address")`, `"output.db_host"`. Result is a secret |
| `urlencode(str)` | Percent-encoded (space → `%20`, `+` → `%2B`) |

cty stdlib subset: `abs`, `base64decode`, `base64encode`, `chomp`, `coalesce`, `concat`, `contains`,
`csvdecode`, `distinct`, `flatten`, `format`, `formatlist`, `join`, `jsondecode`, `jsonencode`, `keys`,
`length`, `lookup` (all three arguments required), `lower`, `merge`, `regex`, `replace`, `split`, `substr`,
`tolist`, `tomap`, `tonumber`, `toset`, `tostring`, `trimspace`, `upper`, `values`.

Results of `secretenv`, `aws_secretsmanager`, `gcp_secretmanager`, `tfstate` and everything computed from
them are secrets and are redacted in all output. A host or name taken from `tfstate` is redacted too; use
`env` or a literal for values that should stay visible. Each secret is fetched once per run.

## Name limits

- PostgreSQL: 63 bytes. Reserved role names: `public` (any case), `none`, `pg_*`.
- MySQL: users 32 characters, databases 64, hosts 255.
- Declared names must not contain control characters.
