# Added to both stages. Terraform creates the Cloud SQL IAM user of the
# Cloud Run job's service account; dbfence manages its memberships.

user "iam" {
  name      = env("DBFENCE_E2E_IAM_USER")
  member_of = [role.e2e_readonly.id]
  gcp_iam {}
}
