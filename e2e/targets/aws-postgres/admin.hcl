# The administrator connection of the cleanup and stage phases.

connection "postgres" {
  host            = env("DBFENCE_E2E_HOST")
  port            = env("DBFENCE_E2E_PORT", "5432")
  database        = "postgres"
  tls             = "verify-full"
  tls_ca_file     = env("DBFENCE_E2E_TLS_CA_FILE")
  connect_timeout = env("DBFENCE_E2E_CONNECT_TIMEOUT", "30")
  user            = env("DBFENCE_E2E_ADMIN_USER")
  password        = aws_secretsmanager(env("DBFENCE_E2E_ADMIN_SECRET"), "password")
}
