# Added to both stages. dbfence creates the IAM user; the ECS task role may
# connect as it (rds-db:connect on dbuser:<cluster resource id>/e2e_iam).

user "iam" {
  name      = "e2e_iam"
  member_of = [role.e2e_readonly.id]
  aws_iam {}
}
