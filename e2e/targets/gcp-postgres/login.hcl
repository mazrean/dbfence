# Logs in as e2e_app with the password stage 2 set: plan with nothing
# declared must succeed and report no changes.

connection "postgres" {
  host            = env("DBFENCE_E2E_HOST")
  port            = env("DBFENCE_E2E_PORT", "5432")
  database        = "postgres"
  tls             = "require"
  connect_timeout = env("DBFENCE_E2E_CONNECT_TIMEOUT", "30")
  user            = "e2e_app"
  password        = secretenv("DBFENCE_E2E_APP_PASSWORD_NEXT")
}
