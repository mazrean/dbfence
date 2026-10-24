# Stage 2: change what stage 1 created. run.sh applies it with --prune and
# --force-password (managed services do not let the admin read password
# verifiers), so e2e_migrator is dropped and e2e_app gets a new password.

role "e2e_owner" {}

role "e2e_readonly" {}

role "e2e_readwrite" {
  member_of = [role.e2e_readonly.id]
}

user "e2e_app" {
  password         = secretenv("DBFENCE_E2E_APP_PASSWORD_NEXT")
  member_of        = [role.e2e_readwrite.id]
  connection_limit = 20
}

database "e2e_app" {
  owner    = role.e2e_owner.name
  encoding = "UTF8"
}

schema "e2e_api" {
  database = database.e2e_app.name
  owner    = role.e2e_owner.name
}

schema "public" {
  database = database.e2e_app.name
}

grant {
  role       = role.e2e_readonly.id
  database   = database.e2e_app.name
  privileges = ["CONNECT"]
}

grant {
  role       = role.e2e_readonly.id
  database   = schema.e2e_api.database
  schema     = schema.e2e_api.name
  privileges = ["USAGE"]
}

grant {
  role       = role.e2e_readwrite.id
  database   = schema.e2e_api.database
  schema     = schema.e2e_api.name
  privileges = ["USAGE", "CREATE"]
}

grant {
  role       = "PUBLIC"
  database   = database.e2e_app.name
  privileges = []
}

grant {
  role       = "PUBLIC"
  database   = schema.public.database
  schema     = schema.public.name
  privileges = []
}
