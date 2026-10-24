# Stage 2: change what stage 1 created. run.sh applies it with --prune and
# --force-password, so e2e_migrator is dropped and e2e_app gets a new
# password.

role "e2e_readonly" {}

role "e2e_readwrite" {
  member_of = [role.e2e_readonly.id]
}

user "e2e_app" {
  password  = secretenv("DBFENCE_E2E_APP_PASSWORD_NEXT")
  member_of = [role.e2e_readwrite.id]
}

database "e2e_app" {
  charset   = "utf8mb4"
  collation = "utf8mb4_0900_ai_ci"
}

grant {
  role       = role.e2e_readonly.id
  database   = database.e2e_app.name
  privileges = ["SELECT", "SHOW VIEW"]
}

grant {
  role       = role.e2e_readwrite.id
  database   = database.e2e_app.name
  privileges = ["INSERT", "UPDATE"]
}
