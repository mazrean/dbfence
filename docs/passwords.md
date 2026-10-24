# Passwords

## Comparison

dbfence compares a declared password with the stored verifier without changing it, and sets it only when they differ:

- **PostgreSQL**: `SCRAM-SHA-256` and `md5`, read from `pg_authid`. Reading them needs superuser. Under `password_encryption = scram-sha-256` an `md5` verifier counts as a mismatch, so setting the password again upgrades it to SCRAM. A password that looks like a verifier (`md5` + 32 characters, or `SCRAM-SHA-256$...`) is an error, because PostgreSQL would store it as is.
- **MySQL**: `caching_sha2_password`, `mysql_native_password` and `sha256_password`, read from `mysql.user`. Other plugins cannot be compared and always produce a warning.

When a password cannot be compared, `--force-password` sets it anyway; with that flag the plan contains a password statement for every role that declares one.

- If the verifiers can't be read (for example on RDS or Cloud SQL, where the admin is not a superuser), plan prints one warning listing the roles whose passwords are not compared.
- Verifiers come from the server and are checked before use: a verifier or authentication string longer than 1024 bytes, or a SCRAM iteration count below 1 or above 1,000,000, is not compared, with the same `cannot compare the password` warning.

## Secondary passwords (MySQL)

When a password is declared and the account still has a secondary password kept by `RETAIN CURRENT PASSWORD` (MySQL 8.0.14+), plan adds `ALTER USER ... DISCARD OLD PASSWORD`, so that only the declared password logs in. The connected account keeps its secondary password (with a warning), because dbfence may be logged in with it.

## Sending passwords

Passwords are sent in plaintext (`PASSWORD '...'`, `IDENTIFIED BY '...'`), so that the server hashes them with its own settings (`password_encryption`, `scram_iterations`) and password policies apply (`passwordcheck` / `credcheck`, MySQL `validate_password`).

As a consequence, PostgreSQL statement logging (`log_statement = ddl` or `all`, and `log_min_error_statement` for failed statements) records the password; MySQL rewrites passwords in its logs. Disable such logging for the dbfence session or role if that matters.

## Errors

When a statement with a password fails, the server's message is shown up to its first quote, and nothing after it (later lines included), because servers quote parts of the statement in their messages. Policy rejections such as `Your password does not satisfy the current policy requirements` contain no quotes and are shown in full. `--show-secrets` shows the whole message.
