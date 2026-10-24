# Safety

Without `--prune`, nothing is dropped: undeclared roles, databases and schemas only produce warnings. This page lists what dbfence never drops or changes even with `--prune`, and how every plan is checked before it runs.

## Built-in objects

Built-in objects are never reported or pruned:

- PostgreSQL roles `postgres`, `pg_*`, `rdsadmin`, `rdsrepladmin`, `rdstopmgr`, `rds_*`, `cloudsql*`, `azure*` and `alloydb*`; databases `postgres`, `template0`, `template1`, `rdsadmin`, `cloudsqladmin`, `azure_maintenance`, `azure_sys` and `alloydbadmin`; schemas `public`, `information_schema` and `pg_*`.
- MySQL accounts `root`, `mariadb.sys`, `debian-sys-maint`, `mysql.*`, `rds*`, `aws_*`, `cloudsql*` and `azure_*`; databases `mysql`, `sys`, `information_schema`, `performance_schema` and `ndbinfo`.

Objects matched by an [`ignore`](configuration.md#ignore) block are not reported or pruned either.

## Kept under `--prune`

These are kept, with a warning, on both engines:

- The connected user and the database it is connected to (on MySQL, the `database` of the `connection` block, read through `DATABASE()`).
- Roles the configuration references without declaring them.
- Roles granted to the connected user.
- Owners of ignored databases or schemas. PostgreSQL also reads the schema owners and schema privileges of every other connectable, undeclared and not ignored database.

## The connected user

dbfence does not lock itself out. Each of these changes is skipped with a warning:

- Changes to the connected user that disable its login, lock it, remove its superuser status or set connection limit 0 on a non-superuser, and `inherit = false` on it (`NOINHERIT` would take away the privileges of its roles).
- Revoking its memberships or their ADMIN OPTION.
- `inherit = false` and `set = false` on a membership of it that has, or may have, `INHERIT` or `SET`. They apply to its new memberships.
- Revoking a membership of another role through which the connected user is a member of a role (`admin` → `ops` → `dba`: the membership of `ops` in `dba`) while it has no other path to that role. On MySQL their ADMIN OPTION is then not removed either, since that revokes the role and grants it again.
- `NOINHERIT` on a role granted to the connected user (`ops` above) while it has a membership with INHERIT, and `inherit = false` or `set = false` on that role's existing memberships that have the option; new memberships may still declare them. PostgreSQL 16 needs both options on every membership along the chain, and before 16 the `INHERIT` attribute of `ops` decides whether `admin` gets the privileges of `dba`.
- MySQL: narrowing its default roles. They also keep the memberships it keeps and its current default roles; when those cannot be read, its default roles are left unchanged.
- MySQL: discarding its secondary password (see [Passwords](passwords.md#secondary-passwords-mysql)).

On PostgreSQL, when the connected user is not a superuser:

- `CONNECT` on the database dbfence is connected to is not revoked from PUBLIC, the connected user or a role it inherits privileges from, when the connected user would hold `CONNECT` there through none of them afterwards: it could not connect again. The other privileges of the revoke are still revoked.
- For the same reason the database's owner is not changed (`ALTER DATABASE ... OWNER TO` moves the old owner's privileges to the new one) when the connected user holds `CONNECT` there only as, or through, the old owner.
- A revoke of `CONNECT` on that database, or of its grant option, is skipped when the grants its `CASCADE` removes include one to PUBLIC, the connected user or a role it inherits privileges from.

On PostgreSQL 16+, a revoke of a membership or its ADMIN OPTION is skipped when the memberships its `CASCADE` removes include one of the connected user or of a role it is a member of, directly or transitively (it may have that membership, or its `INHERIT` and `SET`, only through the removed grant).

## Pruning roles on PostgreSQL

`--prune` of a role runs `REASSIGN OWNED BY ... TO CURRENT_USER` and `DROP OWNED` in every connectable database, then `DROP ROLE`.

- `DROP OWNED` revokes the privileges and memberships the pruned role granted to others, except grants it made while holding an owner's privileges through a membership with INHERIT. dbfence therefore revokes those memberships first (with `CASCADE` on PostgreSQL 16+ for memberships it granted from them).
- Afterwards it grants the declared ones again (memberships only on PostgreSQL 16+), unless the grantee still holds the privilege from another grantor such as the owner. This needs the connected user to be allowed to grant them, and a warning is printed when owner memberships or re-grants cannot be handled.

A role is kept instead, with a warning, when:

- Its `DROP OWNED` would revoke with `CASCADE` a grant it made, directly or through other roles, that the connected user may rely on: `CONNECT` on the database dbfence is connected to, granted to PUBLIC or to the connected user or a role it is a member of (when the connected user is not a superuser), or (16+) a membership of the connected user or of a role it is a member of, including the grants that carry its `INHERIT` and `SET`.
- It owns objects or holds or granted privileges (`pg_shdepend`) in a database where `DROP OWNED` runs, and a role with a [name dbfence does not manage](#names-dbfence-does-not-manage) owns objects or holds privileges there too. Privileges on tables, functions and types are not inspected, so its `DROP OWNED` could revoke one it granted to that role. The warning names the role and the database.

Roles that own objects or hold privileges in databases dbfence cannot connect to (no `CONNECT`, `ALLOW_CONNECTIONS false`, templates, provider databases) or that are ignored are named in a warning, even without `--prune`: `DROP ROLE` fails for them until those objects are reassigned or dropped in that database.

## Names dbfence does not manage

Names read from the server are treated as untrusted input. Roles (MySQL accounts, by name or host), databases and schemas whose names contain control characters (C0, DEL, C1), are not valid UTF-8, or are longer than the engine allows (PostgreSQL: 63 bytes; MySQL: 32 characters for user names, 255 for hosts, 64 for databases) are left out of the inspected state, with one warning per object:

```text
role "x\n": its name contains control characters, so dbfence does not manage it (...); handle it manually
```

- Nothing is created, altered, granted, revoked or dropped for them, `--prune` never drops them, and memberships, default roles and privileges that name them are left alone.
- A connected user with such a name is an error. Declared names (and `owner`, `member_of`, grant `role`/`database`/`schema`/`database_pattern`) must not contain control characters either.
- PostgreSQL: when such a role is the grantor of a grant that differs from the configuration, that change is skipped with a warning instead of naming the grantor in `GRANTED BY` or `SET ROLE`. A revoke whose `CASCADE` would also take privileges or memberships from such a role (because they were granted, directly or transitively, by the role losing them) is skipped with a warning to handle it manually.

`--prune` keeps, with a warning, every role whose drop would change one of these objects:

- PostgreSQL: a role that is a member of such a role, has one as a member or as the grantor of one of its memberships, owns such a database or schema (`REASSIGN OWNED` would change its owner), holds or granted a privilege on one, holds a privilege such a role granted, or whose `DROP OWNED` would revoke a privilege or (16+) membership it granted, directly or through other roles, to such a role or in such a role, on an object it does not own. The schemas checked are those of declared databases and of the other connectable databases where `REASSIGN OWNED` and `DROP OWNED` run; grants on tables, functions and other objects inside schemas are not inspected.
- PostgreSQL, whatever its name: because both statements also change shared objects from any database, a role that owns or has privileges on a tablespace, a parameter (`GRANT SET ON PARAMETER`), or a database dbfence does not read (templates and databases with `ALLOW_CONNECTIONS false` that are not declared). The warning names them.
- MySQL: an account granted to such an account or one of its default roles, one that has such an account as a granted or default role, or one that holds privileges on such a database, or on tables, columns or routines in one (`mysql.tables_priv`, `columns_priv`, `procs_priv`), or a `PROXY` privilege for such an account (`mysql.proxies_priv`). `DROP USER` removes all of them; when those tables cannot be read, a warning says that their rows are not checked. The default roles of an account that has such a role as a default role are not set either.

`--prune` also keeps, with a warning to handle it manually, an undeclared PostgreSQL database or schema whose drop would drop such objects:

- A database or schema owned by such a role or granting a privilege to one.
- A database holding a schema with such a name or owned by or granting to such a role, and a database in which such a role owns objects or holds privileges (`pg_shdepend`, also for databases dbfence cannot connect to).
- A schema containing tables, functions or types in a declared database where such a role owns objects or holds privileges, or that also contains a schema with such a name or owned by such a role, whose objects may depend on it. Which schema those objects are in, and what depends on what, is not read; a schema without them is dropped without `CASCADE`, which fails if anything still depends on it.
- Every undeclared database dbfence cannot connect to (no `CONNECT`, or the connection fails), since what it contains is not known.

## Independent safety check

Before `plan` prints its result and before `apply` asks for confirmation, dbfence checks the finished plan (and with `--target`, also the selected plan that is printed and executed) again, by code separate from the code that computed it. It verifies every protection on this page, and also that:

- nothing is dropped without `--prune`;
- `DROP OWNED` of a role runs in a database only after `REASSIGN OWNED` of the same role ran there;
- no statement names (as target, grantee, `GRANTED BY` grantor, owner or default role), or runs as, a role, database or schema dbfence does not manage, or drops a database or schema whose contents it could not read.

It fails safe:

- Revokes are checked statement by statement, so a revoke that is granted again later still counts.
- When memberships are unreadable, `INHERIT FALSE` or `SET FALSE` on any membership of the connected user that may have that option is rejected.
- When privileges are unreadable, any revoke of `CONNECT` on the connected database from PUBLIC, the connected user or a role it inherits privileges from is rejected, and so is any owner change of that database to a role it does not inherit privileges from.
- Roles whose grants a revoke's `CASCADE` removes count as losing `CONNECT`, also for a revoke of only the grant option.
- MySQL: a `SET DEFAULT ROLE` that removes one of the connected account's current default roles is rejected; when the default roles cannot be read, one that removes any of its granted roles.

A plan that breaks one of them is still printed, but the command fails with exit 1 and `dbfence: error: internal safety check failed: ... (this is a bug in dbfence; please report it)`, and `apply` executes nothing.

## Known limits

- The protections fail safe rather than exact. Under `--prune` a role is kept when it granted the connected user `CONNECT` on the connected database or a membership on its chain, even if the connected user also holds them another way (for example through PUBLIC); drop such a role by hand.
- A schema matched by `ignore.schemas` in a declared database is not checked for views or functions that depend on a schema `--prune` drops with `CASCADE`.
- The `sqlfragment` lint rule (see [Development](development.md)) catches mistakes, not deliberately obfuscated code.
