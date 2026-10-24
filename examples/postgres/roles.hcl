# role = NOLOGIN by default, user = LOGIN by default. Otherwise they are the
# same block.

# Owns the database and its schemas. Nobody logs in as it directly.
role "app_owner" {}

# Privilege bundles. Applications get them through member_of.
role "app_readonly" {}

role "app_readwrite" {
  member_of = [role.app_readonly.id]
}

# The application. Its password comes from the environment and is printed
# in the plan as '<redacted>'.
user "app" {
  password         = secretenv("APP_PASSWORD", "app-password-change-me")
  member_of        = [role.app_readwrite.id]
  connection_limit = 20
}

# Runs schema migrations: it does not inherit the owner's privileges, but may
# `SET ROLE app_owner` to run DDL as the owner (PostgreSQL 16+ options).
user "migrator" {
  password = secretenv("MIGRATOR_PASSWORD", "migrator-password-change-me")
  member_of = [
    { role = role.app_owner.id, inherit = false, set = true },
  ]
}

# Read-only access for people. The name is not a valid HCL label, so `name`
# overrides it.
user "analyst" {
  name      = "analyst.alice"
  password  = secretenv("ANALYST_PASSWORD", "analyst-password-change-me")
  member_of = [role.app_readonly.id]
}

# In real configurations, fetch passwords from a secret store instead:
#
#   password = aws_secretsmanager("prod/db/app", "password")
#   password = jsondecode(gcp_secretmanager("projects/p/secrets/app")).password
