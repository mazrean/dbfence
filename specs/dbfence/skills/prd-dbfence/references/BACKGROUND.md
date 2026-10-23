# dbfence - Background & Research

## Background

Schema-migration tools (sqldef, Atlas, golang-migrate, ...) manage tables, but the objects *around*
them — databases, login roles/users, role memberships, grants and PostgreSQL schemas — are usually
created by hand, by ad-hoc bootstrap scripts, or by a Terraform provider that requires a state file and
network access from the Terraform runner. dbfence covers that "outer frame" declaratively: HCL in,
diff against the live server, SQL out. Because there is no state file, drift introduced by humans is
always visible, and secrets come from secret managers or Terraform state at run time.

## Research

- Terraform providers (`cyrilgdn/postgresql`, `petoju/mysql`) solve the same problem but need state
  and terraform runs; operators asked for a dry-run that shows raw SQL.
- Managed databases (RDS, Aurora, Cloud SQL) hide password hashes from non-superusers and ship many
  built-in roles, so password comparison must degrade and built-ins must be excluded.

## Built-in Exclusions (never warned, never pruned)

| Engine | Users / roles | Databases |
|--------|---------------|-----------|
| MySQL | `root` (any host), `mysql.sys`, `mysql.session`, `mysql.infoschema`, `mariadb.sys`, `rdsadmin`, `rdsrepladmin`, `debian-sys-maint`, `cloudsql*`, `azure_*`, connecting user | `mysql`, `sys`, `information_schema`, `performance_schema`, `ndbinfo` (case-insensitive) |
| PostgreSQL | `postgres`, `rdsadmin`, `rdsrepladmin`, `pg_*`, `rds_*`, `cloudsql*`, `azure_*`, `alloydb*`, connecting user | `postgres`, `template0`, `template1`, `rdsadmin`, `cloudsqladmin`, `azure_maintenance`, `azure_sys`, `alloydbadmin` (templates and non-connectable databases are not inspected) |

PostgreSQL schemas `pg_*`, `information_schema` and `public` are not warned about. Lists live in each
driver's `Dialect.IsSystem*` methods.

## Edge Cases

| Case | Expected Behavior | Requirement |
|------|-------------------|-------------|
| Secret is JSON but `json_key` absent from it | Error naming the key (not the value) | FR-6, NFR-2 |
| `json_key` value is not a string | JSON-encoded string returned | FR-6 |
| Same secret referenced from 3 blocks | Fetched once | FR-10 |
| Password sourced via `jsondecode(secret).password` | Still redacted (all `password` values are `plan.Secret`) | FR-11 |
| Role declared without `password` | Password never diffed | FR-15 |
| Live password hash is `md5` but desired would be SCRAM | Compare via md5; equal → no change | FR-15 |
| MySQL account uses an unsupported plugin (e.g. `auth_socket`) | Warn, skip password diff | FR-16 |
| MySQL `auth_plugin` declared and differs from the live one | `ALTER USER ... IDENTIFIED WITH <plugin> BY` (needs a declared password, else warning) | FR-15 |
| Non-superuser PostgreSQL | One warning per role with a declared password; no password changes | FR-16 |
| Missing `SELECT` on `mysql.user` / `mysql.db` / `mysql.role_edges` | Degraded mode (`model.Current.Unreadable`). Accounts are listed via `information_schema.USER_ATTRIBUTES`; full visibility is detected by seeing any account other than the current one. If they can't be listed, `CREATE USER IF NOT EXISTS` is used and prune is skipped. Credentials and lock state are not compared (`--force-password` still sets the password). Memberships and privileges that can't be read are re-granted idempotently and never revoked. One warning per facet | FR-16 |
| Unmanaged role owns objects (PG) with `--prune` | `REASSIGN OWNED BY x TO CURRENT_USER; DROP OWNED BY x` in every surviving connectable database, then DROP | FR-13, FR-18 |
| Declared encoding / lc_collate / lc_ctype differs on an existing PG database | Warning; no change (create-only) | FR-12 |
| `member_of` omitted | Memberships unmanaged; when set, undeclared memberships are revoked | FR-13a |
| `ignore` pattern `legacy_.*` | Treated as anchored `^legacy_.*$` | FR-14 |
| Name with `"` or `` ` `` | Quoted correctly | NFR-4 |
| Grant privileges given in lower case / with duplicates | Normalized (upper-case, set) before diff | FR-12 |
| `ALL PRIVILEGES` declared | Expanded to the engine's privilege set for comparison | FR-12 |
| No changes, only warnings | `--detailed-exitcode` exits 0 | FR-19 |
| Apply fails midway | Stop, report the failed change and how many statements were applied; re-plan shows remaining diff | FR-20 |
