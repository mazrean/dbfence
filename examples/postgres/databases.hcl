database "app" {
  owner    = role.app_owner.name
  encoding = "UTF8" # encoding, lc_collate and lc_ctype are create-only
}

schema "api" {
  database = database.app.name
  owner    = role.app_owner.name
}

# Declared only to manage what PUBLIC may do in it (see grants.hcl).
schema "public" {
  database = database.app.name
}
