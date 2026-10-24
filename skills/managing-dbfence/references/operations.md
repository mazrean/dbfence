# Operating dbfence

## Contents

- [Commands and flags](#commands-and-flags)
- [Reading plan output](#reading-plan-output)
- [Exit codes and errors](#exit-codes-and-errors)
- [Common warnings](#common-warnings)
- [Required server privileges](#required-server-privileges)
- [What dbfence protects](#what-dbfence-protects)

## Commands and flags

```sh
dbfence validate              # load and evaluate every *.hcl in the working directory (no DB connection)
dbfence plan                  # dry run: print the SQL
dbfence apply                 # print the SQL, ask for "yes", then execute
dbfence -C infra/db plan      # use the *.hcl files in infra/db
```

| Flag | Commands | Meaning |
|---|---|---|
| `-C`, `--chdir` (`$DBFENCE_CHDIR`) | all | Configuration directory (default `.`) |
| `--prune` | plan, apply | Drop undeclared databases, schemas, roles (otherwise only warnings) |
| `--force-password` | plan, apply | Set declared passwords even if they cannot be verified or already match |
| `--show-secrets` | plan, apply | Disable all redaction. **Agents must not use it** |
| `--target ADDRESS` | plan, apply | Only that block's changes (repeatable). Not with `--prune` |
| `--detailed-exitcode` | plan | Exit 2 when there are changes |
| `--auto-approve` | apply | Skip the confirmation prompt |
| `--version` | — | Print the version |

`--target` addresses: `role.<label>`, `user.<label>` (both find either), `database.<label>`, `schema.<label>`.
`grant` and `ignore` have no address; a grant belongs to its role and its database/schema. An unknown
address is an error. Every targeted plan starts with `--target is in effect: ...`.

### Safe apply procedure for agents

1. `dbfence -C DIR plan` and show the output to the user.
2. If it contains `-- [drop]`, `-- DESTRUCTIVE:`, `-- [revoke]` or password statements, ask before applying.
3. `dbfence -C DIR apply --auto-approve` only if the HCL and the server state are unchanged since that plan
   (apply recomputes the plan; if in doubt, run interactive `apply` or plan again).
4. `dbfence -C DIR plan` again; expect `-- No changes.`.

## Reading plan output

```sql
-- warning: unmanaged user "stray" (use --prune to drop it)

-- [create] user "app"
CREATE ROLE "app" WITH LOGIN CONNECTION LIMIT 20 PASSWORD '<redacted>';

-- [create] schema "api" in database "app"
-- (on database "app")
CREATE SCHEMA "api" AUTHORIZATION "app_owner";

-- [revoke] CONNECT, TEMPORARY on database "app" from PUBLIC
REVOKE CONNECT, TEMPORARY ON DATABASE "app" FROM PUBLIC;

-- Plan: 5 to create, 0 to change, 4 to grant, 1 to revoke, 0 to drop (10 statements).
```

- Each change starts with `-- [create|update|grant|revoke|drop] <resource>`.
- `-- (on database "x")`: the statement runs in another database. `-- (as role "g")`: a PostgreSQL revoke
  of another grantor's grant, run under `SET LOCAL ROLE` in its own transaction.
- `-- CASCADE: ...`: explains a PostgreSQL revoke that cascades; declared privileges are granted again.
- `-- DESTRUCTIVE: this plan drops N objects: ...` follows the summary when something is dropped.
- Empty plan: `-- No changes. The server matches the configuration.` or
  `-- No changes to apply. See the N warnings above ...`.
- Warnings also go to stderr as `warning: ...`.
- Passwords print as `'<redacted>'`; any known secret anywhere in output is `<redacted>`.

`apply` prints the same plan, then `[k/N] <statement>` per statement. No transaction; stops at the first
error and says how many statements ran. Re-run `plan` to see what is left.

## Exit codes and errors

| Exit | Meaning |
|---|---|
| 0 | Success (plan with no changes, or any successful command) |
| 1 | Error: `dbfence: error: ...` on stderr; apply cancelled (no `yes`, closed stdin); safety check failure |
| 2 | `plan --detailed-exitcode` only: the plan has changes (warnings alone exit 0) |

- Configuration diagnostics follow `dbfence: error:` and quote the HCL source with `password` values masked as `*`.
- `dbfence: error: internal safety check failed: ... (this is a bug in dbfence; please report it)`:
  an independent check rejected the plan; nothing is executed. Report it; do not work around it.
- `dbfence: error: the plan selected by --target fails the safety check: ...`: select more objects or run
  without `--target`.
- When a function fails on a secret, its message is `the error is not shown because the arguments include a secret value`.
  Check the env var / secret id / permissions without printing the secret.

## Common warnings

| Warning (abridged) | Meaning / fix |
|---|---|
| `unmanaged user "x"` / `unmanaged role "x"` (`use --prune to drop it`) | Exists on the server, not declared. Declare it, add it to `ignore`, or drop with `--prune` (with consent) |
| `cannot compare the password` / roles whose passwords are not compared | Verifier unreadable (not superuser, e.g. RDS / Cloud SQL) or unsupported plugin. `--force-password` sets it anyway |
| Grant to the object's owner has no effect | Remove the grant block; owners already hold all privileges |
| Role keeps a privilege through PUBLIC | Add a PUBLIC grant block on that object (e.g. `privileges = []`) |
| MySQL pattern privileges don't apply to a database | A `database` grant or a more specific pattern wins for that account; list the privileges in the specific grant |
| A change was skipped because the connected user would lose access | Intentional protection; make the change by hand or connect as another admin |
| A change needs `GRANT <owner> TO <user> ...` | PostgreSQL non-superuser lacks the owner's privileges; run the `GRANT` the warning names, then plan again |
| `role "x\n": its name contains control characters, so dbfence does not manage it` | Server object with an unsafe name; handle it manually |
| MySQL fallback warnings (`mysql.user`, `mysql.db`, `mysql.role_edges`, `mysql.default_roles` unreadable) | Grant read access to those tables; until then some statements are re-asserted on every run and `--detailed-exitcode` keeps returning 2 |

## Required server privileges

PostgreSQL:

- Superuser is simplest. Reading password verifiers (`pg_authid`) needs superuser.
- Otherwise changes the user may not make are not planned and produce warnings: altering a role needs
  ADMIN OPTION on it; membership changes need ADMIN OPTION (16+); creating schemas or granting on objects
  owned by another role needs that owner's privileges; pruning a role needs that role's privileges.

MySQL: dbfence works best when it can read `mysql.user`, `mysql.db`, `mysql.role_edges` and
`mysql.default_roles`. Without them it falls back (accounts from `information_schema.USER_ATTRIBUTES`,
memberships / default roles / grants re-asserted on every run, undeclared ones not revoked), with a warning each.

## What dbfence protects

These are never dropped or broken, even with `--prune`; the plan prints a warning instead:

- Built-in objects: PG roles `postgres`, `pg_*`, `rdsadmin`, `rdsrepladmin`, `rdstopmgr`, `rds_*`, `cloudsql*`, `azure*`, `alloydb*`; PG databases
  `postgres`, `template0`, `template1` and provider databases; schemas `public`, `information_schema`, `pg_*`;
  MySQL accounts `root`, `mysql.*`, `mariadb.sys`, `debian-sys-maint`, `rds*`, `aws_*`, `cloudsql*`, `azure_*`;
  databases `mysql`, `sys`, `information_schema`, `performance_schema`, `ndbinfo`.
- The connected user and database, roles referenced but not declared, roles granted to the connected user,
  owners of ignored objects.
- Changes that would lock the connected user out (disable login, remove superuser, revoke its memberships
  or `CONNECT` on the connected database, ...).

Do not try to force these through dbfence; ask the user to do them manually if really needed.
