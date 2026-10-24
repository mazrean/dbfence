# Only database-level privileges (ON db.*) are managed. Privileges on
# declared databases that are not listed here are revoked from declared
# accounts.

grant {
  role       = role.app_readonly.id
  database   = database.app.name
  privileges = ["SELECT"]
}

grant {
  role       = role.app_readonly.id
  database   = database.analytics.name
  privileges = ["SELECT"]
}

# MySQL uses only the most specific mysql.db row per account and database,
# so app_readwrite lists SELECT again instead of relying on app_readonly.
grant {
  role       = role.app_readwrite.id
  database   = database.app.name
  privileges = ["SELECT", "INSERT", "UPDATE", "DELETE"]
}

# A wildcard grant (ON `tenant\_%`.*): tenant_a, tenant_b, ... The databases
# need not be declared. "\\_" in HCL is the escaped "_", so tenantX does not
# match.
grant {
  role             = user.tenant_admin.id
  database_pattern = "tenant\\_%"
  privileges       = ["ALL"]
}
