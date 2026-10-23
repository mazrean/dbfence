---
name: tech-go-sql-driver-mysql
description: go-sql-driver/mysql + MySQL 8.x account/privilege catalog research digest (DSN, mysql.user, role_edges, SCHEMA_PRIVILEGES, CREATE USER/ROLE/GRANT DDL, quoting). Use when implementing internal/driver/mysql in dbfence.
---

# go-sql-driver/mysql / MySQL 8 — Research Digest

## TL;DR

`sql.Open("mysql", dsn)` with go-sql-driver DSN (`user:pass@tcp(host:3306)/`). As built, a single
connection (`SetMaxOpenConns(1)`) runs everything. Accounts are `'user'@'host'`; roles are locked accounts
(dbfence creates them with `CREATE USER ... ACCOUNT LOCK`, never `CREATE ROLE`). Quote identifiers with backticks (double inner backticks);
string literals with `'` doubling and backslash escaping (unless `NO_BACKSLASH_ESCAPES`).

## Identity

- **Version**: go-sql-driver/mysql v1.9.x (pin via `go get`); MySQL 8.0+/8.4 LTS, tested on 8.4.
- **Docs**: https://pkg.go.dev/github.com/go-sql-driver/mysql , https://dev.mysql.com/doc/refman/8.4/en/account-management-statements.html — License MPL-2.0

## API We Use

```go
cfg, err := mysql.ParseDSN(dsn); cfg.User // connecting user
db, err := sql.Open("mysql", cfg.FormatDSN())
var me *mysql.MySQLError; errors.As(err, &me); me.Number // 1142/1227 = access denied
```

```sql
SELECT CURRENT_USER();
SELECT SCHEMA_NAME, DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA;
SELECT User, Host, plugin, HEX(authentication_string), account_locked FROM mysql.user;
SELECT FROM_USER, FROM_HOST, TO_USER, TO_HOST FROM mysql.role_edges;
SELECT User, Host, Db, Grant_priv, Select_priv, ... , Trigger_priv FROM mysql.db; -- as built (instead of SCHEMA_PRIVILEGES)
SELECT @@SESSION.sql_mode;                                                         -- NO_BACKSLASH_ESCAPES detection
```

DDL: `CREATE DATABASE `x` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci`, `CREATE USER 'u'@'%' IDENTIFIED BY '...'`,
`CREATE USER 'r'@'%' ACCOUNT LOCK`, `ALTER USER 'u'@'%' IDENTIFIED WITH <plugin> BY '...'` (plugin always explicit),
`ALTER USER ... ACCOUNT LOCK|UNLOCK`, `GRANT 'r'@'%' TO 'u'@'%'` + `SET DEFAULT ROLE ALL TO 'u'@'%'`,
`GRANT SELECT, INSERT ON `db`.* TO 'u'@'%' [WITH GRANT OPTION]`, `REVOKE ...`, `REVOKE GRANT OPTION ON `db`.* FROM ...`,
`DROP USER`, `DROP DATABASE`.

## Pitfalls

- **DSN defaults**: `multiStatements=false`, `interpolateParams=false` → execute one statement per `Exec`; keep it.
- **`authentication_string` for caching_sha2 contains raw salt bytes** (may be non-printable) → always `SELECT HEX(...)` and decode.
- **`SELECT` on `mysql.user` / `mysql.db` needs privilege** (denied on some managed setups) → as built: errors 1044/1142/1143/1227 trigger degraded mode (see BACKGROUND.md). `information_schema.USER_ATTRIBUTES` (8.0.21+, all rows with `CREATE USER` + `SYSTEM_USER`) lists accounts without credentials, and `CREATE USER IF NOT EXISTS` is used when even that is unavailable. Unreadable memberships and privileges are re-granted, never revoked.
- **DCL is implicitly committed** → no transactional grouping; apply stops at first error.
- **Grant option is per level** (`mysql.db.Grant_priv`) → revoked with `REVOKE GRANT OPTION ON db.*`.
- **Role granted ≠ role active** → also emit `SET DEFAULT ROLE ALL TO` when memberships change.
- **Placeholders unsupported for `IDENTIFIED BY`** → literal escaping; never use `interpolateParams` as a quoting tool.
- **`ALL PRIVILEGES` on db.*** expands to the 18 db-level privileges → `config.ExpandPrivileges` normalizes before diff.

## Confidence

- **High**: catalog tables and DDL (refman 8.4). **Medium**: managed-MySQL (RDS/Cloud SQL) privilege denials — verify on staging.
