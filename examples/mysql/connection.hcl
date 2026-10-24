# dbfence reads every *.hcl file in this directory and merges them into one
# configuration: run it with `dbfence -C examples/mysql plan`.

connection {
  engine = "mysql"

  # Connect as root of examples/compose.yaml so dbfence can read mysql.user,
  # mysql.db, mysql.role_edges and mysql.default_roles.
  host     = "127.0.0.1"
  port     = env("DBFENCE_MYSQL_PORT", "13306")
  user     = "root"
  password = secretenv("DBFENCE_MYSQL_ROOT_PASSWORD", "dbfence-root")
  tls      = "disable"
}

# Accounts managed elsewhere: neither reported nor pruned. A pattern without
# a host matches the account on every host.
ignore {
  roles = ["monitoring"]
}
