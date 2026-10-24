# Configuration

A configuration is every `*.hcl` file in one directory (see [CLI](cli.md)).
Complete examples for both engines are in [`examples/`](../examples).

```hcl
connection "postgres" {                                # "postgres" or "mysql"
  host     = "db.internal"
  user     = "admin"
  password = secretenv("PGPASSWORD")
  tls      = "verify-full"
}

role "app_owner" {}                                    # role: NOLOGIN

user "app" {                                           # user: LOGIN
  password         = jsondecode(gcp_secretmanager("projects/p/secrets/app")).password
  member_of        = [role.readonly.id, { role = role.app_owner.id, inherit = false }]
  connection_limit = 20                                # PostgreSQL only
}

user "batch" {
  aws_iam {}                                           # logs in with an RDS IAM token
  member_of = [role.readonly.id]
}

role "readonly" {}

database "app" {
  owner    = role.app_owner.name                       # PostgreSQL only
  encoding = "UTF8"
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

grant {                                                # PostgreSQL only: undeclared roles may not connect
  role       = "PUBLIC"
  database   = database.app.name
  privileges = []
}

ignore {                                               # unmanaged objects to neither warn about nor prune
  roles = ["datadog", "rds_.*"]
}
```

## References

- `role.<label>` and `user.<label>` expose `name`, `host` and `id`. `id` is `name@host` on MySQL; use it in `member_of` and `grant.role`, because a bare name means `name@%`.
- `database.<label>.name`, `schema.<label>.name` and `schema.<label>.database`.
- On MySQL, `role = "public"` without a host is an error; write `"public@%"` or use `.id`.

Values can also come from [functions](functions.md).

## `connection "<engine>"`

Required, exactly one; the label is `"postgres"` or `"mysql"`.

| Attribute | Meaning |
|---|---|
| `host` | Required, not empty. On PostgreSQL a `host` starting with `/` is the directory of a Unix-domain socket |
| `socket` | MySQL only: the path of a Unix-domain socket, instead of `host` and `port` |
| `user` | Required, not empty |
| `port` | Default 5432 (PostgreSQL) or 3306 (MySQL) |
| `database` | The database to connect to; default `"postgres"` on PostgreSQL, none on MySQL |
| `tls` | See below |
| `tls_ca_file` | A PEM file of the certificates that verify the server, such as the RDS or Cloud SQL CA bundle; only with `"verify-ca"` or `"verify-full"`. A relative path is in the configuration directory |
| `connect_timeout` | Seconds, default 10. On MySQL it covers the handshake and session setup as well as the dial (`connect to mysql: timed out after 10s`). PostgreSQL reports a host's timeout once, even with `tls = "prefer"` |

These attributes, and the password, are always taken from the configuration: on PostgreSQL the matching `PG*` environment variables and `~/.pgpass` are not read. TLS certificate settings (`PGSSLROOTCERT`, `PGSSLCERT`, `PGSSLKEY`, `~/.postgresql/`), `PGOPTIONS` and `PGSERVICE` still apply as in libpq.

`tls` is one of:

- `"disable"`
- `"prefer"`: TLS when the server supports it.
- `"require"`: always TLS; the certificate is not verified.
- `"verify-full"`: always TLS; the certificate and host name are verified, on PostgreSQL against `tls_ca_file`, `PGSSLROOTCERT` or `~/.postgresql/root.crt`, otherwise the system roots; on MySQL against `tls_ca_file` or the system roots. Cannot be used with `socket`.
- PostgreSQL only: `"allow"` (TLS only when the server requires it) and `"verify-ca"` (the certificate is verified, the host name is not).

The default is `"prefer"`, `"require"` with IAM authentication, and `"disable"` with `socket`.

Authentication is one of:

- `password`: optional; without it (and without the blocks below) dbfence connects without a password.
- `aws_iam { region = "..." }`: an [Amazon RDS IAM authentication token](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html) for `host`, `port` and `user`, signed with the standard AWS credentials. `region` defaults to that of the AWS configuration (`AWS_REGION`). Needs `host`, not `socket`.
- `gcp_iam {}`: a Google Cloud access token of the [application default credentials](https://cloud.google.com/docs/authentication/application-default-credentials) for a Cloud SQL IAM database user; `user` is the database user name of the IAM principal, which Cloud SQL derives from its email address as described in the [Cloud SQL IAM documentation](https://cloud.google.com/sql/docs/postgres/iam-logins).

Setups are shown in [Amazon RDS](aws-rds.md) and [Google Cloud SQL](gcp-cloud-sql.md). IAM tokens expire, so a new one is taken for every connection dbfence opens. They are sent as a cleartext password (MySQL: the `mysql_clear_password` plugin), so `tls` must be `"require"` or a verifying mode, except over a MySQL `socket`.

## `role "<label>"` / `user "<label>"`

The two are the same, except for the login default: `login` defaults to `false` for `role` (NOLOGIN / ACCOUNT LOCK) and `true` for `user`. Declaring an existing login account as a `role` without `login = true` disables its login.

| Attribute | Engines | Meaning |
|---|---|---|
| `name` | both | Overrides the label. Use it, with an identifier-safe label, for names with upper case, spaces or quotes, because only such labels can be referenced (`user.<label>.name`) |
| `password` | both | See [Passwords](passwords.md). `password = ""` is an error on PostgreSQL |
| `login` | both | Always managed (see above) |
| `member_of` | both | See [`member_of`](#member_of) |
| `superuser`, `createdb`, `createrole`, `inherit`, `replication`, `bypassrls` | PostgreSQL | Role attributes |
| `connection_limit` | PostgreSQL | -1 or more |
| `host` | MySQL | Default `"%"`, lower-cased, must not be empty or contain `@` |
| `auth_plugin` | MySQL | Letters, digits and `_`. `AWSAuthenticationPlugin` is set with its authentication string `AS 'RDS'`. Works without a password for passwordless plugins; a login account with neither gets a warning |

- Attributes you leave out are not managed, except `login`.
- `name` and `host` accept only literals and functions, not references to other blocks.
- Names are checked against the engine limits: 63 bytes on PostgreSQL; 32 characters for MySQL users, 64 for databases and 255 for hosts. PostgreSQL role names `public` (in any case), `none` and `pg_*` are reserved.
- On MySQL a non-login role is a locked account.

### `aws_iam {}`

The role logs in with an Amazon RDS IAM authentication token instead of a password. What this sets on the server is described in [Amazon RDS](aws-rds.md#users-that-log-in-with-iam).

- Cannot be combined with `password` or `auth_plugin`, and needs login (`user`, or `login = true`).
- Without `aws_iam`, IAM authentication is left unmanaged: an existing `rds_iam` membership is revoked only by a `member_of` that omits it.

### `gcp_iam {}`

The role is an existing Cloud SQL IAM user, service account or group. How these are created and handled is described in [Google Cloud SQL](gcp-cloud-sql.md#iam-users-service-accounts-and-groups).

- Set `name` to the database user name Cloud SQL gives it (PostgreSQL: the email address, without `.gserviceaccount.com` for a service account; MySQL: the part before `@`).
- Cannot be combined with `password`, `auth_plugin` or `aws_iam`. A group is not a login: declare it as a `role`.

## `member_of`

A list of role ids, or objects `{ role = <id>, admin = bool, inherit = bool, set = bool }`; both forms can be mixed.

- When `member_of` is set, it must be complete: memberships that aren't listed are revoked. Cycles, duplicates and self-membership are errors.
- Options written in an object are managed; omitted ones (and the string form) are left alone.
- `admin` (`WITH ADMIN OPTION`) works on both engines. On PostgreSQL, revoking it cascades to the memberships the member granted with it, and declared ones are granted again. On MySQL, removing it revokes the role and grants it again.
- `inherit` and `set` are PostgreSQL 16+ only (a validation error on MySQL; plan fails on older PostgreSQL). On PostgreSQL 16+ the role's `inherit` attribute is only the default for new grants, so dbfence also sets `inherit` on the role's existing memberships to match, except those that declare their own `inherit`. A warning is printed while the two disagree.
- On PostgreSQL 16+ each grantor's grant is changed with `GRANTED BY`; an option counts as held when any grant has it.
- On MySQL the declared `member_of` becomes exactly the account's default roles (`SET DEFAULT ROLE`), so the roles are active without `SET ROLE`.
- Memberships of the connected user are protected: see [Safety](safety.md#the-connected-user).

## `database "<label>"`

- PostgreSQL: `name`, `owner`, `encoding`, `lc_collate` and `lc_ctype`. The last three are create-only, and none may be empty.
- MySQL: `name`, `charset` and `collation` (letters, digits and `_`).

## `schema "<label>"`

PostgreSQL only. Takes `database`, `name` and `owner`.

`schema "public"` (or another template schema) can also be declared in a database the plan creates; only its owner and grants are planned.

## `grant`

Takes `role`, `database` (or `database_pattern` on MySQL), an optional `schema` (PostgreSQL), `privileges` and `with_grant_option`.

- `ALL` expands to every privilege of that object type. `GRANT OPTION` is not a privilege; use `with_grant_option = true`.
- The database (and schema) must be declared.
- A declared role's privileges on declared databases or schemas that aren't listed are revoked.
- Grants to an object's owner have no effect (a warning is printed).
- MySQL:
  - Only database-level privileges (`ON db.*`) are managed.
  - Every grant block for the same account and database (or pattern) must use the same `with_grant_option`, because MySQL keeps one grant option per database.
  - `_` and `%` in `database` names are escaped (`my\_app`), so a `database` grant never acts as a wildcard. With `partial_revokes` ON, MySQL reads names literally, so escaped rows of declared databases are revoked and granted again on the literal name.

### `database_pattern` (MySQL only)

A wildcard grant such as `ON tenant\_%.*`:

```hcl
grant {
  role             = user.app.id
  database_pattern = "tenant\\_%"          # tenant_a, tenant_b, ... (not tenantX)
  privileges       = ["SELECT", "INSERT"]
}
```

- The pattern is used verbatim: `%` and `_` are wildcards and `\` escapes them (write `"tenant\\_%"` in HCL for `tenant\_%`). It needs at least one wildcard, and the databases it matches need not be declared.
- A declared role's privileges on a declared pattern that aren't listed are revoked. Patterns that no grant block declares are not managed; a warning is printed when one held by a declared account matches a declared database.
- MySQL does not add up database-level grants: for an account it uses only the most specific `mysql.db` row that matches a database. When an account has both a `database` grant and a matching pattern, or two matching patterns, plan warns that the pattern's privileges don't apply to that database.
- Needs `partial_revokes` OFF (plan fails otherwise, because MySQL then reads `%` and `_` literally). Wildcards in database-level grants are deprecated since MySQL 8.2 and are to become literals in a future release.

### Grants to `PUBLIC` (PostgreSQL only)

`role = "PUBLIC"` (any case, no role block needed).

- PUBLIC is managed only on databases and schemas that have at least one PUBLIC grant block. There, PUBLIC's undeclared privileges are revoked; elsewhere they are left alone.
- `privileges = []` (allowed only for PUBLIC) revokes everything PUBLIC holds on that object. It cannot be combined with another PUBLIC grant block on the same object.
- `with_grant_option = true` is invalid for PUBLIC.
- PostgreSQL's defaults are visible: `CONNECT` and `TEMPORARY` on every database, and `USAGE` on schema `public` (`CREATE` and `USAGE` before PostgreSQL 15). To manage the `public` schema's PUBLIC grants, declare `schema "public" { database = ... }`.
- When a role loses a privilege that PUBLIC still holds on an unmanaged object, the plan warns that the role keeps it through PUBLIC. Add a PUBLIC grant block (for example `privileges = []`) to take it away.

## `ignore`

Takes `roles`, `databases` and `schemas` (PostgreSQL) regexps. Matching objects are neither reported nor pruned.

- Each pattern must be a valid regexp on its own and is anchored to the whole string; `.` also matches a newline.
- On MySQL, `roles` patterns match the name or `name@host`: `"datadog"` ignores every host, `"datadog@%"` only the host `%` (`%` is a literal here), and `"datadog@10\\.0\\.0\\.%"` one host. An account with an empty host (shown as `"name"@""`) matches `"name@"`.
- `schemas` patterns match the schema name or `<database>.<schema>`: `"staging"` ignores it in every database, `"analytics\\.staging"` only in `analytics` (escape the dot; an unescaped `.` matches any character).
- Declared databases and schemas stay managed even when a pattern matches them.
