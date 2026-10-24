# Stage 1: create everything from scratch. run.sh composes this file with
# ignore.hcl, the target's admin connection and its IAM user declaration.

role "e2e_owner" {}

role "e2e_readonly" {}

role "e2e_readwrite" {
  member_of = [role.e2e_readonly.id]
}

user "e2e_app" {
  password         = secretenv("DBFENCE_E2E_APP_PASSWORD")
  member_of        = [role.e2e_readwrite.id]
  connection_limit = 10
}

user "e2e_migrator" {
  password = secretenv("DBFENCE_E2E_MIGRATOR_PASSWORD")
  member_of = [
    { role = role.e2e_owner.id, inherit = false, set = true },
  ]
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
  database   = database.e2e_app.name
  privileges = ["TEMPORARY"]
}

grant {
  role       = user.e2e_migrator.id
  database   = database.e2e_app.name
  privileges = ["CONNECT"]
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
