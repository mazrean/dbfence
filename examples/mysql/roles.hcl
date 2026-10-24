# On MySQL a role is a locked account (ACCOUNT LOCK) and a user can log in.
# host defaults to "%". Reference accounts by .id ("name@host"), not by name.

# Privilege bundles. Applications get them through member_of, which also
# becomes the account's default roles, so no SET ROLE is needed.
role "app_readonly" {}

role "app_readwrite" {
  member_of = [role.app_readonly.id]
}

# The application. Its password comes from the environment and is printed
# in the plan as '<redacted>'.
user "app" {
  password  = secretenv("APP_PASSWORD", "app-password-change-me")
  member_of = [role.app_readwrite.id]
}

# Read-only access for people, from the Docker network only.
user "analyst" {
  host      = "172.%"
  password  = secretenv("ANALYST_PASSWORD", "analyst-password-change-me")
  member_of = [role.app_readonly.id]
}

# Provisions per-tenant databases (see the database_pattern grant).
user "tenant_admin" {
  password = secretenv("TENANT_ADMIN_PASSWORD", "tenant-admin-password-change-me")
}
