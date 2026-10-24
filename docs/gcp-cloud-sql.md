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

- dbfence never creates a `gcp_iam` role and never changes its authentication; its other attributes, memberships and grants are managed as declared. Plan fails when it does not exist; when the roles cannot be listed it is not created, with a warning.
- On PostgreSQL, the memberships Cloud SQL gives these roles (`cloudsqliamuser`, `cloudsqliamserviceaccount`, `cloudsqliamgroup`) are kept: `member_of` neither grants nor revokes them.

To let dbfence itself connect with IAM on PostgreSQL, declare its user while connected as `postgres`, apply, then switch the connection to `gcp_iam`:

```hcl
user "dbfence" {
  name       = "dbfence@my-project.iam"
  gcp_iam {}
  member_of  = ["cloudsqlsuperuser"]
  createrole = true   # role attributes are not inherited from cloudsqlsuperuser
  createdb   = true
}
```

## What to expect on Cloud SQL

- The `postgres` user is not a superuser, so dbfence cannot read password verifiers on PostgreSQL: plan prints one warning listing the roles whose passwords are not compared, and declared passwords are not set again. Run with `--force-password` to set (rotate) them. See [Passwords](passwords.md).
- On PostgreSQL the admin user is not a member of the roles it creates: it may alter, grant and drop them, but not act as them. Plan warns about the changes that need that, and they fail at `apply` unless you first run the `GRANT` the warning names (`GRANT <role> TO <admin user> WITH SET TRUE, INHERIT TRUE`):
  - an `owner` other than the admin user (`must be able to SET ROLE`); or leave `owner` out, so that the admin user owns databases and schemas;
  - `--prune` of a role that still owns objects or holds privileges (`permission denied to reassign objects`). A role that holds nothing is dropped despite the warning.
- Other changes the connected user may not make are skipped with a warning; see [Required privileges](privileges.md).
- Cloud SQL's own roles and databases (`cloudsql*`, `cloudsqladmin`) are never reported or pruned. See [Safety](safety.md#built-in-objects).
