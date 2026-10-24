# dbfence recipes

Patterns taken from the repository's `examples/postgres` and `examples/mysql`. Copy and adapt; run
`validate` and `plan` after every change.

## Contents

- [PostgreSQL: owner, bundle roles, app user](#postgresql-owner-bundle-roles-app-user)
- [PostgreSQL: migrator that can SET ROLE to the owner](#postgresql-migrator-that-can-set-role-to-the-owner)
- [PostgreSQL: lock down PUBLIC](#postgresql-lock-down-public)
- [MySQL: roles, default roles, host-restricted account](#mysql-roles-default-roles-host-restricted-account)
- [MySQL: per-tenant wildcard grant](#mysql-per-tenant-wildcard-grant)
- [Names that are not valid labels](#names-that-are-not-valid-labels)
- [IAM users (RDS / Cloud SQL)](#iam-users-rds--cloud-sql)
- [Passwords from secret stores](#passwords-from-secret-stores)
- [Connection from Terraform state](#connection-from-terraform-state)
- [Objects managed elsewhere](#objects-managed-elsewhere)

## PostgreSQL: owner, bundle roles, app user

```hcl
role "app_owner" {}                       # owns the database and schemas; nobody logs in

role "app_readonly" {}                    # privilege bundles
role "app_readwrite" {
  member_of = [role.app_readonly.id]
}

user "app" {
  password         = secretenv("APP_PASSWORD")
  member_of        = [role.app_readwrite.id]
  connection_limit = 20
}

database "app" {
  owner    = role.app_owner.name
  encoding = "UTF8"                       # create-only
}

schema "api" {
  database = database.app.name
  owner    = role.app_owner.name
}

grant {
  role       = role.app_readonly.id
  database   = database.app.name
  privileges = ["CONNECT"]
}

grant {
  role       = role.app_readonly.id
  database   = schema.api.database
  schema     = schema.api.name
  privileges = ["USAGE"]
}

grant {
  role       = role.app_readwrite.id
  database   = database.app.name
  privileges = ["TEMPORARY"]
}
```

Table privileges (`SELECT ON ALL TABLES`, default privileges) are not dbfence's job: grant them to the bundle
roles from migrations.

## PostgreSQL: migrator that can SET ROLE to the owner

Needs PostgreSQL 16+. The migrator does not inherit the owner's privileges but may `SET ROLE app_owner`
to run DDL as the owner.

```hcl
user "migrator" {
  password = secretenv("MIGRATOR_PASSWORD")
  member_of = [
    { role = role.app_owner.id, inherit = false, set = true },
  ]
}

grant {
  role       = user.migrator.id
  database   = database.app.name
  privileges = ["CONNECT"]
}
```

## PostgreSQL: lock down PUBLIC

PostgreSQL grants `CONNECT`, `TEMPORARY` on every database and `USAGE` on schema `public` to PUBLIC by
default. Revoke them so only roles granted above can connect:

```hcl
grant {
  role       = "PUBLIC"
  database   = database.app.name
  privileges = []
}

schema "public" {                         # declared only to manage PUBLIC's grants on it
  database = database.app.name
}

grant {
  role       = "PUBLIC"
  database   = schema.public.database
  schema     = schema.public.name
  privileges = []
}
```

## MySQL: roles, default roles, host-restricted account

On MySQL a `role` is a locked account and `member_of` becomes the account's default roles, so no
`SET ROLE` is needed. Always reference accounts by `.id` (`name@host`).

```hcl
role "app_readonly" {}
role "app_readwrite" {
  member_of = [role.app_readonly.id]
}

user "app" {
  password  = secretenv("APP_PASSWORD")
  member_of = [role.app_readwrite.id]
}

user "analyst" {
  host      = "172.%"                     # default "%"
  password  = secretenv("ANALYST_PASSWORD")
  member_of = [role.app_readonly.id]
}

database "app" {
  charset   = "utf8mb4"
  collation = "utf8mb4_0900_ai_ci"
}

grant {
  role       = role.app_readonly.id
  database   = database.app.name
  privileges = ["SELECT"]
}

# MySQL uses only the most specific mysql.db row per account and database,
# so list SELECT again instead of relying on app_readonly.
grant {
  role       = role.app_readwrite.id
  database   = database.app.name
  privileges = ["SELECT", "INSERT", "UPDATE", "DELETE"]
}
```

## MySQL: per-tenant wildcard grant

```hcl
user "tenant_admin" {
  password = secretenv("TENANT_ADMIN_PASSWORD")
}

grant {
  role             = user.tenant_admin.id
  database_pattern = "tenant\\_%"         # tenant_a, tenant_b, ... (not tenantX)
  privileges       = ["ALL"]
}
```

Needs `partial_revokes` OFF. The matched databases need not be declared.

## Names that are not valid labels

```hcl
user "analyst" {
  name     = "analyst.alice"
  password = secretenv("ANALYST_PASSWORD")
}
# reference it as user.analyst.id / user.analyst.name
```

## IAM users (RDS / Cloud SQL)

```hcl
user "batch" {
  aws_iam {}                              # RDS IAM token login; PG: rds_iam membership is managed
  member_of = [role.readonly.id]
}

user "ci" {
  name      = "ci@my-project.iam"         # Cloud SQL DB user name (PG: email without .gserviceaccount.com)
  gcp_iam {}                              # must already exist: gcloud sql users create ... --type=cloud_iam_service_account
  member_of = [role.readonly.id]
}
```

Connecting dbfence itself with IAM:

```hcl
connection "postgres" {
  host = "mydb.xxxx.ap-northeast-1.rds.amazonaws.com"
  user = "dbfence"
  tls  = "verify-full"
  tls_ca_file = "rds-global-bundle.pem"
  aws_iam { region = "ap-northeast-1" }
}
```

## Passwords from secret stores

```hcl
password = secretenv("APP_PASSWORD")
password = aws_secretsmanager("prod/db/app", "password")
password = jsondecode(gcp_secretmanager("projects/p/secrets/app")).password
```

All are redacted as `'<redacted>'` in plan output and in every message.

## Connection from Terraform state

```hcl
connection "postgres" {
  host     = tfstate("s3://tfstate-bucket/db.tfstate", "aws_db_instance.main.address")
  user     = "admin"
  password = secretenv("PGADMIN_PASSWORD")
  tls      = "verify-full"
}
```

`tfstate` results are secrets, so the host is redacted in output; use `env` or a literal if it must stay visible.

## Objects managed elsewhere

```hcl
ignore {
  roles     = ["datadog", "monitoring", "rds_.*"]   # anchored regexps
  databases = ["scratch_.*"]
}
```

Ignored objects are neither reported as unmanaged nor dropped by `--prune`.
