# Amazon RDS

dbfence runs against RDS for PostgreSQL and MySQL and Aurora PostgreSQL and MySQL. On PostgreSQL the master user is not a superuser, which limits what dbfence can do; see [What to expect on RDS](#what-to-expect-on-rds). This page shows the typical setups. For every attribute, see [Configuration](configuration.md).

## Connect with the master password

Take the endpoint from Terraform state and the password from the secret RDS manages in Secrets Manager:

```hcl
connection "postgres" {
  host        = tfstate("s3://tfstate/db.tfstate", "aws_db_instance.main.address")
  user        = "postgres"
  password    = aws_secretsmanager(tfstate("s3://tfstate/db.tfstate", "aws_db_instance.main.master_user_secret[0].secret_arn"), "password")
  tls         = "verify-full"
  tls_ca_file = "global-bundle.pem"   # the RDS CA bundle, next to the *.hcl files
}
```

For Aurora, take the cluster's writer endpoint and secret instead (`aws_rds_cluster.main.endpoint`, `aws_rds_cluster.main.master_user_secret[0].secret_arn`).

`aws_secretsmanager` and `tfstate` use the standard AWS credentials, and their results are [secrets](secrets.md): the endpoint taken from `tfstate` is redacted in output too. Use `env` or a literal for the host if it should stay visible.

## Connect with IAM authentication

With [IAM database authentication](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html) enabled on the instance, dbfence can log in with a token instead of a password, for example from CI with an IAM role:

```hcl
connection "postgres" {
  host        = "mydb.xxxxxxxx.ap-northeast-1.rds.amazonaws.com"
  user        = "dbfence"
  tls_ca_file = "global-bundle.pem"
  tls         = "verify-full"

  aws_iam {
    region = "ap-northeast-1"   # default: the AWS configuration (AWS_REGION)
  }
}
```

The AWS credentials need `rds-db:connect` on that database user (`arn:aws:rds-db:<region>:<account>:dbuser:<resource id>/<user>`, with the instance's `resource_id` or the Aurora cluster's `cluster_resource_id`). For the token and TLS rules, see [`connection`](configuration.md#connection-engine).

The database user itself must log in with IAM. dbfence can create it (see [Users that log in with IAM](#users-that-log-in-with-iam)): apply this once while connected with the master password, then switch the connection to `aws_iam`. On PostgreSQL:

```hcl
user "dbfence" {
  aws_iam {}
  member_of  = ["rds_superuser"]
  createrole = true   # role attributes are not inherited from rds_superuser
  createdb   = true
}
```

On MySQL, dbfence manages only database-level privileges, so grant this account its global privileges (`CREATE USER` and the privileges it grants to others) by hand.

After the switch the master user is no longer the connected user. Unless it is a [built-in name](safety.md#built-in-objects) such as `postgres` on PostgreSQL, it is an ordinary role: declare it or add it to `ignore`, so that `--prune` does not drop it. The default MySQL master user `admin` is such a case.

```hcl
ignore {
  roles = ["admin"]
}
```

## Users that log in with IAM

```hcl
user "app" {
  aws_iam {}
  member_of = [role.readonly.id]
}
```

- PostgreSQL: the user is made a member of `rds_iam`, which turns password authentication off for it. `member_of` need not list `rds_iam` and never revokes it. Plan fails when the server has no `rds_iam` role.
- MySQL: the account is `IDENTIFIED WITH AWSAuthenticationPlugin AS 'RDS'`. Plan warns when the plugin is not active, that is, when IAM database authentication is not enabled on the instance.

## What to expect on RDS

- The master user is not a superuser, so dbfence cannot read password verifiers on PostgreSQL: plan prints one warning listing the roles whose passwords are not compared, and declared passwords are not set again. Run with `--force-password` to set (rotate) them. See [Passwords](passwords.md).
- On PostgreSQL the master user is not a member of the roles it creates: it may alter, grant and drop them, but not act as them. Plan warns about the changes that need that, and they fail at `apply` unless you first run the `GRANT` the warning names (`GRANT <role> TO <master user> WITH SET TRUE, INHERIT TRUE`):
  - an `owner` other than the master user (`must be able to SET ROLE`); or leave `owner` out, so that the master user owns databases and schemas;
  - `--prune` of a role that still owns objects or holds privileges (`permission denied to reassign objects`). A role that holds nothing is dropped despite the warning.
- Other changes the master user may not make are skipped with a warning; see [Required privileges](privileges.md).
- RDS's own roles and databases (`rdsadmin`, `rds_*`, ...) are never reported or pruned. See [Safety](safety.md#built-in-objects).
