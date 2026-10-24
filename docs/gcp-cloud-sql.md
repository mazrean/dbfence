# Google Cloud SQL

dbfence runs against Cloud SQL for PostgreSQL and Cloud SQL for MySQL. On PostgreSQL the admin user is not a superuser, which limits what dbfence can do; see [What to expect on Cloud SQL](#what-to-expect-on-cloud-sql). This page shows the typical setups. For every attribute, see [Configuration](configuration.md).

## Connect with a password

Take the address from Terraform state and the password from Secret Manager:

```hcl
connection "postgres" {
  host        = tfstate("gs://tfstate/db/default.tfstate", "google_sql_database_instance.main.private_ip_address")
  user        = "postgres"
  password    = gcp_secretmanager("projects/my-project/secrets/db-postgres-password")
  tls         = "verify-ca"
  tls_ca_file = "server-ca.pem"   # the instance's server CA, next to the *.hcl files
}
```

- `gcp_secretmanager` and `tfstate` use the application default credentials, and their results are [secrets](secrets.md): the address taken from `tfstate` is redacted in output too. Use `env` or a literal for the host if it should stay visible.
- `verify-ca` checks the certificate but not the host name. Use `verify-full` when the server certificate names the host you connect to; MySQL has no `verify-ca`.

## Connect with IAM authentication

dbfence can log in as a [Cloud SQL IAM database user](https://cloud.google.com/sql/docs/postgres/iam-logins) with an access token of the [application default credentials](https://cloud.google.com/docs/authentication/application-default-credentials), for example a service account in CI:

```hcl
connection "postgres" {
  host        = "10.0.0.3"
  user        = "dbfence@my-project.iam"   # the IAM database user name
  tls         = "verify-ca"
  tls_ca_file = "server-ca.pem"

  gcp_iam {}
}
```

`user` follows the same naming rule as [`gcp_iam` roles](configuration.md#gcp_iam-). For the token and TLS rules, see [`connection`](configuration.md#connection-engine).

### Through the Cloud SQL Auth Proxy

- MySQL: point `socket` at the proxy's Unix socket and keep `gcp_iam {}`; `tls` then defaults to `"disable"`.
- PostgreSQL: dbfence does not send a token without TLS, and the proxy's local listener has none. Start the proxy with `--auto-iam-authn`, so that it logs in with IAM itself, and leave `password` and `gcp_iam` out of the `connection` block.

## IAM users, service accounts and groups

Only the Cloud SQL Admin API creates IAM users, so create them first, with `gcloud` (`--type=cloud_iam_user`, `cloud_iam_service_account` or `cloud_iam_group`) or Terraform:

```sh
gcloud sql users create app@my-project.iam --instance=main --type=cloud_iam_service_account
gcloud sql users create data-team@example.com --instance=main --type=cloud_iam_group
```

Then declare them with `gcp_iam {}` and manage their memberships and grants as usual:

```hcl
user "app" {
  name = "app@my-project.iam"
  gcp_iam {}
  member_of = [role.readonly.id]
}

role "data_team" {                 # a group is not a login: declare it as a role
  name = "data-team@example.com"
  gcp_iam {}
}

grant {
  role       = role.data_team.id
  database   = database.analytics.name
  privileges = ["CONNECT"]
}
```

- dbfence never creates a `gcp_iam` role and never changes its authentication; its other attributes, memberships and grants are managed as declared, except that on PostgreSQL a membership cannot be revoked or changed once granted (see [What to expect on Cloud SQL](#what-to-expect-on-cloud-sql)). Plan fails when it does not exist; when the roles cannot be listed it is not created, with a warning.
- On PostgreSQL, the memberships Cloud SQL gives these roles (`cloudsqliamuser`, `cloudsqliamserviceaccount`, `cloudsqliamgroup`) are kept: `member_of` neither grants nor revokes them.

To let dbfence itself connect with IAM on PostgreSQL, declare its user while connected as `postgres`, apply, then switch the connection to `gcp_iam`:

```hcl
user "dbfence" {
  name       = "dbfence@my-project.iam"
  gcp_iam {}
  member_of  = ["cloudsqlsuperuser"]   # the privileges of the admin users' group
  createrole = true                    # role attributes are not inherited through
  createdb   = true                    # cloudsqlsuperuser, so give them directly
}
```

## What to expect on Cloud SQL

Checked on Cloud SQL for PostgreSQL and MySQL by the [end-to-end test](e2e.md).

- The `postgres` user (and any built-in user, a member of `cloudsqlsuperuser`) is not a superuser, so dbfence cannot read password verifiers on PostgreSQL: plan prints one warning listing the roles whose passwords are not compared, and declared passwords are not set again. Run with `--force-password` to set (rotate) them. See [Passwords](passwords.md).
- On PostgreSQL the admin user does not become a member of the roles it creates, unlike on plain PostgreSQL 16+, and `createrole_self_grant` has no effect. It may still alter, grant, revoke and drop them, but it lacks their privileges, which these changes need ([Required privileges](privileges.md)). dbfence plans them anyway, so `apply` fails:
  - A database or schema whose `owner` is another role: `CREATE DATABASE ... OWNER` and `ALTER ... OWNER TO` fail with `must be able to SET ROLE`.
  - `--prune` of a role that owns objects or holds privileges in a database: `REASSIGN OWNED` fails with `permission denied to reassign objects`. A role that holds nothing is dropped, despite the warning that `REASSIGN OWNED` will fail.

  For both, run the `GRANT` that the warning names (`GRANT <role> TO <admin> WITH SET TRUE, INHERIT TRUE`) first, or leave such owners out and let the admin own databases and schemas.
- On PostgreSQL, Cloud SQL records the memberships the admin grants with the grantor `cloudsqladmin`. dbfence revokes or changes a membership only as a superuser or as its grantor, so afterwards it does not revoke such a membership or change its `admin`, `inherit` or `set` options: a `member_of` that drops it, or changes them, is not applied, with a warning (`it needs superuser, since another role granted it`). Dropping the role (`--prune`) still removes its memberships. Revoke a membership by hand when it has to go.
- Other changes the connected user may not make are skipped with a warning; see [Required privileges](privileges.md).
- Cloud SQL's own roles and databases (`cloudsql*`, `cloudsqladmin`) are never reported or pruned. See [Safety](safety.md#built-in-objects).
