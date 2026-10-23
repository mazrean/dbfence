---
name: tech-pgx
description: jackc/pgx v5 + PostgreSQL catalog research digest (stdlib driver, per-database connections, identifier quoting, pg_roles/pg_authid/aclexplode, role/grant DDL). Use when implementing internal/driver/postgres in dbfence.
---

# pgx v5 / PostgreSQL — Research Digest

## TL;DR

Use `database/sql` with `github.com/jackc/pgx/v5/stdlib` (driver name `"pgx"`). PostgreSQL cannot
switch databases on a connection, so open one `*sql.DB` per database by rewriting the DSN's dbname
(`pgx.ParseConfig` → `cfg.Copy()`, set `Database` → `stdlib.OpenDB(*cfg)`). As built, identifiers are quoted
by `postgres.Ident` (`"` doubled, equivalent to `pgx.Identifier.Sanitize`) and literals by `postgres.Literal`
(`'` doubled; assumes `standard_conforming_strings=on`).

## Identity

- **Version**: pgx v5.x (pin latest v5 via `go get`); target PostgreSQL 13–17, tested on 17.
- **Docs**: https://pkg.go.dev/github.com/jackc/pgx/v5 , https://www.postgresql.org/docs/17/catalogs.html — License MIT

## API We Use

```go
cfg, err := pgx.ParseConfig(dsn)   // accepts URL and key=value DSNs
cfg.Database = "app"; db := stdlib.OpenDB(*cfg)
pgx.Identifier{"app"}.Sanitize() // => "app" with " doubled
```

```sql
SELECT current_user;
SELECT datname, pg_get_userbyid(datdba), pg_encoding_to_char(encoding), datcollate, datctype
  FROM pg_database WHERE NOT datistemplate AND datallowconn;
SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolinherit, rolreplication, rolbypassrls, rolconnlimit FROM pg_roles;
SELECT rolname, rolpassword FROM pg_authid;            -- superuser only; 42501 otherwise
SELECT g.rolname AS role, m.rolname AS member FROM pg_auth_members am
  JOIN pg_roles g ON g.oid = am.roleid JOIN pg_roles m ON m.oid = am.member;
SELECT d.datname, r.rolname, a.privilege_type, a.is_grantable
  FROM pg_database d CROSS JOIN LATERAL aclexplode(d.datacl) a JOIN pg_roles r ON r.oid = a.grantee; -- drops PUBLIC
SELECT nspname, pg_get_userbyid(nspowner) FROM pg_namespace
  WHERE nspname NOT LIKE 'pg\_%' AND nspname <> 'information_schema';   -- per declared database
-- + aclexplode(nspacl) joined to pg_roles, same filter
```

DDL: `CREATE DATABASE x OWNER o ENCODING 'UTF8' LC_COLLATE '..' LC_CTYPE '..' TEMPLATE template0`,
`CREATE ROLE x WITH LOGIN ... PASSWORD '...'`, `ALTER ROLE x WITH ... PASSWORD '...'`, `GRANT r TO x`,
`CREATE SCHEMA s AUTHORIZATION o`, `GRANT CONNECT, CREATE ON DATABASE d TO x`, `GRANT USAGE ON SCHEMA s TO x`,
`REASSIGN OWNED BY x TO CURRENT_USER; DROP OWNED BY x` (per surviving database), `DROP ROLE x`, `DROP DATABASE x`.

## Pitfalls

- **CREATE/DROP DATABASE cannot run in a transaction** → apply runs every statement on its own, no transaction.
- **`pg_roles.rolpassword` is always `********`** → only `pg_authid` gives hashes; any error ⇒ unreadable
  (as built: one warning per role with a declared password).
- **NULL datacl/nspacl** means default privileges (owner all, PUBLIC CONNECT/TEMP on DB) → treat as owner-only; ignore PUBLIC.
- **Plaintext PASSWORD in DDL is hashed server-side** using `password_encryption` (scram-sha-256 default since 14).
  Statements may appear in server logs — document; optionally pre-hash SCRAM client-side later.
- **Encoding/collation of existing DBs is immutable** → diff emits a warning, not ALTER.
- **Placeholders don't work in utility statements** (CREATE ROLE ... PASSWORD $1) → literal escaping required.
- **pgx stdlib default `QueryExecModeCacheStatement`** is fine for catalog queries.

## Confidence

- **High**: catalog columns, DDL rules. **Medium**: Cloud SQL/RDS role names beyond the exclusion list.
