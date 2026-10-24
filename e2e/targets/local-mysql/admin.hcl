# The administrator connection of the cleanup and stage phases.

connection "mysql" {
  host            = env("DBFENCE_E2E_HOST")
  port            = env("DBFENCE_E2E_PORT", "3306")
  tls             = "disable"
  connect_timeout = env("DBFENCE_E2E_CONNECT_TIMEOUT", "30")
  user            = env("DBFENCE_E2E_ADMIN_USER")
  password        = secretenv("DBFENCE_E2E_ADMIN_PASSWORD")
}
