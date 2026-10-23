# dbfence

Declarative management of the *outer frame* of MySQL and PostgreSQL servers —
databases, users / roles, role memberships, privileges and PostgreSQL schemas —
written in HCL. Tables are out of scope; use your schema migration tool for those.

- `plan` compares the configuration with the live server and prints the SQL it would run (dry run). Passwords are redacted.
- `apply` runs that SQL.
- dbfence keeps no state file. It always compares the HCL with the live server.

Supported engines: MySQL 8.0+ and PostgreSQL.

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
| `-f`, `--file` (`$DBFENCE_FILE`) | all | A configuration file, or a directory of `*.hcl` files (default `dbfence.hcl`) |
| `--prune` | plan, apply | Drop databases, schemas and roles that are not declared (without it they only produce warnings) |
| `--force-password` | plan, apply | Set declared passwords even when they cannot be verified |
| `--show-secrets` | plan, apply | Print passwords instead of `'<redacted>'` |
| `--detailed-exitcode` | plan | Exit with 2 when there are changes |
| `--auto-approve` | apply | Skip the confirmation prompt |

## Configuration

```hcl
connection {
  engine = "postgres"                                   # "postgres" or "mysql"
  dsn    = aws_secretsmanager("prod/db/admin", "dsn")
}

role "app_owner" {}                                    # role: NOLOGIN by default

user "app" {                                           # user: LOGIN by default
  password         = jsondecode(gcp_secretmanager("projects/p/secrets/app")).password
  member_of        = [role.readonly.id]
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

ignore {                                               # unmanaged objects to neither warn about nor prune
  roles = ["datadog", "rds_.*"]                        # anchored regular expressions
}
```

### Blocks

- **`connection`**: required, exactly one. `engine` and `dsn` (a pgx URL/DSN, or a go-sql-driver/mysql DSN).
- **`role "<label>"` / `user "<label>"`**: these two are the same thing, except that `user` defaults to `login = true`.
  - `name` overrides the label.
  - `password`, `login` and `member_of` work on both engines.
  - PostgreSQL only: `superuser`, `createdb`, `createrole`, `inherit`, `replication`, `bypassrls` and `connection_limit`.
  - MySQL only: `host` (default `"%"`) and `auth_plugin`. On MySQL a non-login role is a locked account.
  - Attributes you leave out are not managed.
  - When `member_of` is set, it must be complete: memberships that aren't listed are revoked.
- **`database "<label>"`**: `name`, `owner`, `encoding`, `lc_collate` and `lc_ctype` (PostgreSQL; the last three are create-only), or `charset` and `collation` (MySQL).
- **`schema "<label>"`**: PostgreSQL only. Takes `database`, `name` and `owner`.
- **`grant`**: takes `role`, `database`, an optional `schema` (PostgreSQL), `privileges` and `with_grant_option`.
  - `ALL` expands to every privilege of that object type.
  - A declared role's privileges on declared databases or schemas that aren't listed are revoked.
- **`ignore`**: takes `roles`, `databases` and `schemas` regexps.

References: `role.<label>` and `user.<label>` expose `name`, `host` and `id`. `id` is `name@host` on MySQL. `database.<label>.name` and `schema.<label>.name` / `.database` are also available.

Built-in objects are never reported or pruned, and neither is the connected user. Examples: `postgres`, `pg_*`, `rds_*`, `root` and `mysql.*`.

### Functions

| Function | Returns |
|---|---|
| `env(name, [default])` | An environment variable. It is an error if the variable is unset and no default is given |
| `aws_secretsmanager(secret_id, [json_key])` | An AWS Secrets Manager secret string, or one key of a JSON secret. Standard AWS credentials and `AWS_ENDPOINT_URL` apply |
| `gcp_secretmanager(name, [version])` | A GCP Secret Manager payload. `name` is `projects/<p>/secrets/<s>[/versions/<v>]`, and `version` defaults to `latest` |
| `tfstate(url, address)` | A value from a Terraform state on `s3://`, `gs://`, a local path, and so on. Examples: `aws_db_instance.main.address`, `output.db_host` |

The cty standard library is also available: `jsondecode`, `jsonencode`, `format`, `lookup`, `merge`, `split`, `join`, `base64decode` and more. Each secret is fetched once per run.

### Passwords

dbfence compares a declared password with the stored verifier without changing it:

- **PostgreSQL**: `SCRAM-SHA-256` and `md5`, read from `pg_authid`. Reading these needs superuser.
- **MySQL**: `caching_sha2_password` and `mysql_native_password`, read from `mysql.user`.

If the verifier can't be read (for example on RDS or Cloud SQL, where the admin is not a superuser), plan prints a warning and skips the comparison. `--force-password` sets the password anyway.

### Required privileges (MySQL)

dbfence works best when it can read `mysql.user`, `mysql.db` and `mysql.role_edges`.
If it can't read them, it falls back as follows:

| Can't read | Fallback |
|---|---|
| `mysql.user` | Accounts are listed from `information_schema.USER_ATTRIBUTES`. All rows are visible only with `CREATE USER` + `SYSTEM_USER`. Login state, authentication plugin and passwords of existing accounts are not compared (`--force-password` still sets the password) |
| `mysql.user`, and the account list is not visible | Declared accounts are created with `CREATE USER IF NOT EXISTS` on every run, and existing ones are not updated. Unmanaged accounts are not reported or pruned |
| `mysql.role_edges` | Declared memberships are granted on every run (`GRANT` is idempotent). Undeclared memberships are not revoked |
| `mysql.db` | Declared privileges are granted on every run. Undeclared privileges are not revoked |

Each fallback is reported as a warning in `plan`. While a fallback is in effect, `plan` keeps showing the re-asserted statements, so `--detailed-exitcode` never returns 0.

## Development

```sh
mise run test               # unit tests (-short)
mise run test:integration   # also starts MySQL 8.4 / PostgreSQL 17 containers with dockertest
mise run lint               # go tool lint ./...
mise run generate           # regenerate kessoku injectors
```
