# Stage 1: create everything from scratch. run.sh composes this file with
# ignore.hcl, the target's admin connection and its IAM user declaration.

role "e2e_readonly" {}

role "e2e_readwrite" {
  member_of = [role.e2e_readonly.id]
}

user "e2e_app" {
  password  = secretenv("DBFENCE_E2E_APP_PASSWORD")
  member_of = [role.e2e_readwrite.id]
}

user "e2e_migrator" {
  password = secretenv("DBFENCE_E2E_MIGRATOR_PASSWORD")
}

database "e2e_app" {
  charset   = "utf8mb4"
  collation = "utf8mb4_0900_ai_ci"
}

grant {
  role       = role.e2e_readonly.id
  database   = database.e2e_app.name
  privileges = ["SELECT"]
}

grant {
  role       = role.e2e_readwrite.id
  database   = database.e2e_app.name
  privileges = ["INSERT", "UPDATE", "DELETE"]
}

grant {
  role       = user.e2e_migrator.id
  database   = database.e2e_app.name
  privileges = ["SELECT", "CREATE", "ALTER", "DROP", "INDEX"]
}
