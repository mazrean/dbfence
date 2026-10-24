# CLI

```sh
dbfence validate          # load and evaluate the configuration
dbfence plan              # dry run: print the SQL
dbfence apply             # print the SQL, ask for "yes", then execute
dbfence -C infra/db plan  # use the *.hcl files in infra/db
```

Like Terraform, dbfence reads every `*.hcl` file directly in the directory
(not in subdirectories) and merges them into one configuration, so other
HCL files (Packer, Nomad, ...) must not share the directory.

## Flags

| Flag | Commands | Meaning |
|---|---|---|
| `-C`, `--chdir` (`$DBFENCE_CHDIR`) | all | The directory whose `*.hcl` files are the configuration (default `.`; an empty value also means the default) |
| `--prune` | plan, apply | Drop databases, schemas and roles that are not declared (without it they only produce warnings). See [Safety](safety.md) for what is never dropped |
| `--force-password` | plan, apply | Set every declared password, even if it cannot be verified or already matches |
| `--show-secrets` | plan, apply | Turn off all redaction (see [Secrets](secrets.md)) |
| `--target ADDRESS` | plan, apply | Plan only the changes of some declared blocks (repeatable; see [Targeting](#targeting)). Cannot be combined with `--prune` |
| `--detailed-exitcode` | plan | Exit with 2 when there are changes. Warnings alone exit with 0 |
| `--auto-approve` | apply | Skip the confirmation prompt |
| `--version` | — | Print the version |

## Targeting

Like Terraform's `-target`, `--target` limits `plan` and `apply` to some declared blocks, for example to create a new user before the rest of a change is ready:

```sh
dbfence plan --target user.app --target database.analytics
```

- An address is `role.<label>` or `user.<label>` (role and user blocks share their labels, so either form finds both), `database.<label>` or `schema.<label>`. An address that names no declared block is an error. `grant` and `ignore` blocks have no address: a grant belongs to its role and to its database or schema.
- A role or user selects its own create or alter, its default roles (MySQL), its `member_of` memberships (as the member, not the memberships others have in it) and the privileges granted to or revoked from it. A database or schema selects its own create or alter and the privileges on it, PUBLIC's included.
- The plan always compares the whole configuration with the server and then keeps only the selected changes. Statements planned together with a selected one stay with it, even when they act on other roles, such as a revoke with `CASCADE` and the grants that restore the declared privileges it took away; no other unselected change is planned.
- When a selected change names a role, database or schema that the plan creates (a grantee, an owner, a member's role, a schema's database), that create is selected too. Nothing else is.
- `--prune` cannot be combined with `--target`: undeclared objects have no address, so nothing would be dropped.
- Every targeted plan starts with the warning `--target is in effect: ...`. Run `plan` without `--target` afterwards to see what is left.
- The [safety check](safety.md#independent-safety-check) runs on the selected plan as well. When the whole plan passes it but the selection does not (a left-out change made a selected one safe), the command fails with `dbfence: error: the plan selected by --target fails the safety check: ...; select more objects or run without --target`.

## plan output

`plan` writes annotated SQL to stdout:

- Each change starts with `-- [create|update|grant|revoke|drop] <resource>`.
- Statements that must run in another database are preceded by `-- (on database "x")`.
- A PostgreSQL revoke of another grantor's grant runs as that grantor and is preceded by `-- (as role "g")` (or `-- (on database "x", as role "g")`); `apply` runs it in a transaction of its own under `SET LOCAL ROLE`, so a failure leaves the session's role unchanged.
- A PostgreSQL revoke that cascades is preceded by `-- CASCADE: privileges on <object> that "<grantor>" granted to ... are revoked too; declared ones are granted again` (or `memberships in "<role>" that ...`).
- The plan ends with a summary such as `-- Plan: 5 to create, 0 to change, 4 to grant, 1 to revoke, 0 to drop (10 statements).` When something is dropped, it is followed by `-- DESTRUCTIVE: this plan drops N objects: ...`.
- An empty plan prints `-- No changes. The server matches the configuration.`, or, when there are warnings, `-- No changes to apply. See the N warnings above ...`.

Comment lines are only printed; they are not part of the SQL sent to the server.

Warnings are printed in the plan and also to stderr as `warning: ...`, so they stay visible when stdout is redirected. Unmanaged roles are reported as `unmanaged user "x"` when they can log in, and `unmanaged role "x"` otherwise.

## apply

`apply` prints the same plan, asks for `yes` (anything else, or a closed stdin, cancels with exit 1), and prints `[k/N] <statement>` for each statement (its comment lines first).

- Statements run one by one, without a transaction, and apply stops at the first error. The error says how many statements were applied; run `plan` again to see what is left.
- An interrupted apply stops before the next statement, and the error ends with the cause, such as `interrupt signal received`.
- Every SQL statement is sent on its own, so the server rejects a query that holds a second statement: PostgreSQL statements use the extended query protocol, and MySQL connections do not allow multiple statements.

## validate

`validate` prints a summary such as `The configuration is valid (postgres: 1 database, 3 roles, 1 schema, 3 privileges).`

## Errors and exit codes

Errors are printed to stderr as `dbfence: error: ...` (configuration diagnostics follow unindented) and exit with 1. `plan --detailed-exitcode` exits with 2 when the plan has changes; everything else that succeeds exits with 0.

## Control characters and library logs

Control characters (other than line breaks and tabs that separate lines and columns of output) are printed as Go escapes (`\x1b`, `\r`) everywhere on stdout and stderr; control characters inside names read from the server, line breaks included, are escaped in the plan, warnings, `apply` progress and errors. The SQL sent to the server is unchanged.

Messages that the MySQL client library logs itself (prefixed `[mysql]`, for example an authentication plugin the server asked for that is not supported) go to stderr the same way, and so do the warnings and errors that the AWS and GCP SDKs and the HCP Terraform client log. The SDKs' debug logs, which quote whole responses (secret payloads and state files included), are not printed: `GOOGLE_SDK_GO_LOGGING_LEVEL` and `AZURE_SDK_GO_LOGGING` are ignored.
