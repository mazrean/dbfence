# Logs in as the IAM database user that the stage phases declare: plan with
# nothing declared must succeed and report no changes.

connection "mysql" {
  host            = env("DBFENCE_E2E_HOST")
  port            = env("DBFENCE_E2E_PORT", "3306")
  tls             = "verify-full"
  tls_ca_file     = env("DBFENCE_E2E_TLS_CA_FILE")
  connect_timeout = env("DBFENCE_E2E_CONNECT_TIMEOUT", "30")
  user            = "e2e_iam"
  aws_iam {}
}
