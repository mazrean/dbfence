# Logs in as e2e_app with the password stage 2 set: plan with nothing
# declared must succeed and report no changes.

connection "mysql" {
  host            = env("DBFENCE_E2E_HOST")
  port            = env("DBFENCE_E2E_PORT", "3306")
  tls             = "verify-full"
  tls_ca_file     = env("DBFENCE_E2E_TLS_CA_FILE")
  connect_timeout = env("DBFENCE_E2E_CONNECT_TIMEOUT", "30")
  user            = "e2e_app"
  password        = secretenv("DBFENCE_E2E_APP_PASSWORD_NEXT")
}
