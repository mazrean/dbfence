# Examples

Example configurations for both engines, and a Docker Compose file that
starts local servers to try them on.

| Path | What it is |
|---|---|
| [`postgres/`](postgres) | PostgreSQL 16+: owner / bundle roles, users, a database and schemas, grants, PUBLIC lock-down, membership `inherit` / `set` options |
| [`mysql/`](mysql) | MySQL 8.0+: locked roles, users with default roles, a host-restricted account, databases with charset / collation, a `database_pattern` grant |
| [`compose.yaml`](compose.yaml) | `postgres:17` on `127.0.0.1:15432` and `mysql:8.4` on `127.0.0.1:13306` |
| [`initdb/`](initdb) | SQL run when the containers are first created: an unmanaged user and database (to show warnings and `--prune`) and an ignored `monitoring` account |

Each engine's configuration is split into `connection.hcl`, `roles.hcl`,
`databases.hcl` and `grants.hcl`. dbfence reads every `*.hcl` file in the
directory given to `-C` and merges them, so the split is only for
readability.

## Try it locally

From the repository root:

```sh
docker compose -f examples/compose.yaml up -d --wait

go run . -C examples/postgres plan                # dry run: the SQL it would run
go run . -C examples/postgres apply               # type "yes" to run it
go run . -C examples/postgres plan                # -- No changes. (warnings only)
go run . -C examples/postgres plan --prune        # also drop stray_reporter and legacy_reports

go run . -C examples/mysql plan                   # the same for MySQL
go run . -C examples/mysql apply
```

Then change the HCL (add a user, remove a grant, change a password through
`APP_PASSWORD=... go run . -C examples/postgres plan`) and run `plan` again to
see the difference.

Log in as the created accounts:

```sh
docker compose -f examples/compose.yaml exec -e PGPASSWORD=app-password-change-me \
  postgres psql -h 127.0.0.1 -U app -d app
docker compose -f examples/compose.yaml exec \
  mysql mysql -h 127.0.0.1 -uapp -papp-password-change-me app
```

Start over (this deletes the data volumes, so `initdb/` runs again):

```sh
docker compose -f examples/compose.yaml down -v
```

## Environment variables

The defaults work with `compose.yaml` as is. Set the same variables for both
`docker compose` and `dbfence` to change them.

| Variable | Default | Used by |
|---|---|---|
| `DBFENCE_PG_PORT` | `15432` | compose, `postgres/connection.hcl` |
| `DBFENCE_PG_ADMIN_PASSWORD` | `dbfence-admin` | compose (only when the volume is created), `postgres/connection.hcl` |
| `DBFENCE_MYSQL_PORT` | `13306` | compose, `mysql/connection.hcl` |
| `DBFENCE_MYSQL_ROOT_PASSWORD` | `dbfence-root` | compose (only when the volume is created), `mysql/connection.hcl` |
| `APP_PASSWORD`, `MIGRATOR_PASSWORD`, `ANALYST_PASSWORD`, `TENANT_ADMIN_PASSWORD` | `*-change-me` | the user blocks |

The passwords are read with `secretenv`, so they are printed as
`<redacted>`. In real configurations take them from a secret store
(`aws_secretsmanager`, `gcp_secretmanager`, `tfstate`) instead of defaults.
