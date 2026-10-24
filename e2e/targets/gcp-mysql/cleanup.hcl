# The IAM user outlives every run (Terraform owns it, and its name does not
# start with e2e_), so cleanup only takes its memberships away.

user "iam" {
  name      = env("DBFENCE_E2E_IAM_USER")
  member_of = []
  gcp_iam {}
}
