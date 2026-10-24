# Required privileges

## PostgreSQL

Without superuser, changes the connected user may not make are not planned and produce a warning instead:

- Altering a role needs ADMIN OPTION on it (superuser for superuser roles).
- Changing a privilege grant made by another grantor needs superuser, or, for revokes, `SET` on that grantor.
- Granting or revoking a membership needs ADMIN OPTION on the role on PostgreSQL 16+ (revoking another grantor's membership grant needs superuser); before 16, ADMIN OPTION or CREATEROLE for a role that is not a superuser. Membership re-grants after a `CASCADE` follow the same rules.
- Creating schemas in, or granting on, objects owned by another role needs that owner's privileges. The warning names the `GRANT` to run: on PostgreSQL 16+ `GRANT <owner> TO <user> WITH INHERIT TRUE, SET TRUE` (`WITH SET TRUE, INHERIT FALSE` when only an owner change needs it, `WITH INHERIT TRUE` when only its privileges are needed); before 16 a plain `GRANT <owner> TO <user>`.
- Pruning a role needs the connected user to have that role's privileges; a warning names the `GRANT` to run.

Privileges and memberships are revoked per grantor.

Comparing passwords needs superuser (see [Passwords](passwords.md)).

## MySQL

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
