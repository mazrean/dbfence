# Privileges on declared databases and schemas that are not listed here are
# revoked from declared roles. Table privileges are out of scope: grant them
# from your migrations.

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

grant {
  role       = user.migrator.id
  database   = database.app.name
  privileges = ["CONNECT"]
}

# Lock the database down: roles that are not granted CONNECT above may not
# connect (PostgreSQL grants CONNECT and TEMPORARY to PUBLIC by default).
grant {
  role       = "PUBLIC"
  database   = database.app.name
  privileges = []
}

# ... and may not use the public schema either.
grant {
  role       = "PUBLIC"
  database   = schema.public.database
  schema     = schema.public.name
  privileges = []
}
