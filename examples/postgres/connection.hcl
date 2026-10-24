# dbfence reads every *.hcl file in this directory and merges them into one
# configuration: run it with `dbfence -C examples/postgres plan`.

connection {
  engine = "postgres"

  # Connect as the superuser of examples/compose.yaml. Reading password
  # verifiers (pg_authid) needs superuser; without it dbfence still works but
  # cannot tell whether a declared password already matches.
  host     = "127.0.0.1"
  port     = env("DBFENCE_PG_PORT", "15432")
  user     = "postgres"
  database = "postgres"
  tls      = "disable"

  # secretenv marks the value as a secret, so it is redacted in all output.
  password = secretenv("DBFENCE_PG_ADMIN_PASSWORD", "dbfence-admin")
}

# Roles that exist on the server but are managed elsewhere (a monitoring
# agent, a cloud provider, ...): they are neither reported nor pruned.
ignore {
  roles = ["monitoring"]
}
