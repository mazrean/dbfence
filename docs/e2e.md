# End-to-end tests on Amazon Aurora and Google Cloud SQL

The [E2E workflow](../.github/workflows/e2e.yml) runs dbfence against real managed servers: Aurora Serverless v2 for PostgreSQL and MySQL, started as a one-shot ECS task by [ecspresso](https://github.com/kayac/ecspresso), and Cloud SQL for PostgreSQL and MySQL, from a Cloud Run job. The cloud resources live in a separate Terraform repository, which also writes every setting this repository needs into two GitHub environments. This page is the contract between the two repositories.

## What runs

```
build ──► aws-image (ECR) ──► aws  [postgres, mysql]: ecspresso run ──► Fargate task ──► Aurora
      └─► gcp-image (AR)  ──► gcp  [postgres, mysql]: gcloud run jobs  ──► Cloud Run job ──► Cloud SQL
```

1. `build` compiles a static linux/amd64 `dbfence` with the repository's toolchain.
2. `aws-image` and `gcp-image` build [`e2e/Dockerfile`](../e2e/Dockerfile) (the binary, [`e2e/run.sh`](../e2e/run.sh), the scenario and the RDS CA bundle) and push it to ECR and Artifact Registry, tagged `<commit>-<run attempt>`.
3. `aws` runs `ecspresso run --config e2e/aws/ecspresso.yml` once per engine. The task and service definitions read the ARNs, subnets, endpoints and so on from the Terraform outputs in the state ([tfstate plugin](https://github.com/kayac/ecspresso#plugins)). ecspresso registers a task definition revision, starts the task with the network configuration of the local service definition (there is no ECS service), streams its CloudWatch Logs and fails when the container exits non-zero.
4. `gcp` starts the Cloud SQL instance of the engine (`gcloud sql instances patch --activation-policy ALWAYS`, which returns once it runs), deploys the Cloud Run job `dbfence-e2e-<engine>` with the new image, runs it with `gcloud run jobs execute --wait` and prints the execution's logs. Finally it stops the instance again (`--activation-policy NEVER`), also when the run failed or was cancelled, so the instances cost only storage between runs.

The workflow runs on pushes to `main` that touch Go code or `e2e/`, weekly, and on demand. Runs against the same server are serialized (`concurrency`), because the scenario uses fixed names.

### The scenario

`e2e/run.sh` composes one configuration directory per phase from `e2e/scenario/<engine>` and `e2e/targets/<platform>-<engine>`, and runs:

| Phase | Connected as | Commands |
|---|---|---|
| cleanup | admin (password from Secrets Manager / Secret Manager) | `plan --prune` (retried while Aurora resumes from 0 ACU), `apply --prune` |
| stage1 | admin | `apply --target user.e2e_app`, then `apply`: roles, users with passwords, an IAM user, a database, schemas (PostgreSQL), memberships with options, grants, PUBLIC revokes |
| stage2 | admin | `apply --prune --force-password`: a password rotation, changed attributes and grants, a dropped user |
| login | `e2e_app` with the rotated password | `plan` with nothing declared |
| iam | the IAM database user, with an RDS IAM token / a Google access token | `plan` with nothing declared |
| cleanup | admin | `apply --prune` |

After every `apply`, `plan --detailed-exitcode` must report no changes. In the admin phases, any warning that `e2e/scenario/<engine>/expected-warnings` does not list also fails the run, because dbfence warns about what it did not change. Every object the scenario creates is named `e2e_*`, and `ignore` hides everything else, so `--prune` never touches other objects on the server.

On PostgreSQL the admin of Aurora and Cloud SQL is not a superuser. `run.sh` sets `PGOPTIONS=-c createrole_self_grant=set,inherit` so that it can give the roles it creates databases and schemas.

Known limitation (listed in `expected-warnings`): on PostgreSQL 16+ the server grants every role a non-superuser creates to its creator, and `--prune` keeps roles granted to the connected user. So on Aurora and Cloud SQL, `--prune` does not drop the `e2e_*` roles; the databases are dropped and the roles stay between runs.

### Running locally

```sh
mise run e2e:local   # needs Docker
```

This runs the same image against `postgres:17` (with a non-superuser admin, like the managed services) and `mysql:8.4` from [`e2e/compose.yaml`](../e2e/compose.yaml). The `iam` phase is skipped.

## Terraform contract

### GitHub

Use the [`integrations/github`](https://registry.terraform.io/providers/integrations/github/latest/docs) provider to create two environments in `mazrean/dbfence` and their variables:

- `github_repository_environment` `e2e-aws` and `e2e-gcp`. Restrict deployments to the `main` branch (`deployment_branch_policy`), since the cloud credentials trust these environments.
- `github_actions_environment_variable` for every row below. Create the variable after its environment (`depends_on`, or reference `github_repository_environment.*.environment`).

No GitHub secrets are needed: the workflow authenticates with OIDC (no long-lived keys), and the database passwords stay in Secrets Manager / Secret Manager, which the tasks read themselves. The variables hold only names, ARNs and addresses. On AWS, what the ECS task needs is not copied into variables at all: ecspresso reads it from the Terraform state.

### `e2e-aws` variables

| Variable | Value | Terraform source |
|---|---|---|
| `AWS_REGION` | Region of every resource below | — |
| `AWS_ROLE_ARN` | Role the workflow assumes with OIDC | `aws_iam_role.github.arn` |
| `DBFENCE_E2E_ECR_REPOSITORY` | Repository URI, without tag | `aws_ecr_repository.e2e.repository_url` |
| `DBFENCE_E2E_ECS_CLUSTER` | Cluster name. `ecspresso.yml` is rendered before its plugins are set up, so the cluster cannot come from the state | `aws_ecs_cluster.e2e.name` |
| `DBFENCE_E2E_TFSTATE_URL` | URL of the Terraform state that holds the outputs below, for example `s3://<bucket>/<key>` (with workspaces: `s3://<bucket>/env:/<workspace>/<key>`) | the backend configuration |

### Terraform outputs read by ecspresso

The root module of the state at `DBFENCE_E2E_TFSTATE_URL` must define these outputs. [`e2e/aws/ecs-task-def.jsonnet`](../e2e/aws/ecs-task-def.jsonnet) and [`ecs-service-def.jsonnet`](../e2e/aws/ecs-service-def.jsonnet) read them with `tfstate('output.<name>')`.

| Output | Type | Value |
|---|---|---|
| `ecs_execution_role_arn` | string | `aws_iam_role.execution.arn` |
| `ecs_task_role_arn` | string | `aws_iam_role.task.arn` |
| `ecs_task_subnet_ids` | list(string) | Subnets of the task |
| `ecs_task_security_group_ids` | list(string) | Security groups of the task |
| `ecs_task_assign_public_ip` | string | `ENABLED` in public subnets, `DISABLED` behind NAT or VPC endpoints |
| `ecs_log_group_name` | string | `aws_cloudwatch_log_group.e2e.name` |
| `postgres_endpoint` | string | `aws_rds_cluster.postgres.endpoint` |
| `postgres_master_username` | string | `aws_rds_cluster.postgres.master_username` |
| `postgres_master_user_secret_arn` | string | `aws_rds_cluster.postgres.master_user_secret[0].secret_arn` |
| `mysql_endpoint` | string | `aws_rds_cluster.mysql.endpoint` |
| `mysql_master_username` | string | `aws_rds_cluster.mysql.master_username` |
| `mysql_master_user_secret_arn` | string | `aws_rds_cluster.mysql.master_user_secret[0].secret_arn` |

The GitHub role reads the whole state file, so keep the e2e resources in a state of their own, without unrelated secrets: anything in it (including `sensitive` outputs and resource attributes) is readable by the workflow. With `manage_master_user_password` the master passwords are not in the state.

### AWS resources

**Aurora clusters** (one `aws_rds_cluster` per engine, with one `db.serverless` writer instance):

- `engine = "aurora-postgresql"` with PostgreSQL 16 or later (`inherit`/`set` membership options and `createrole_self_grant`), and `engine = "aurora-mysql"` (version 3).
- `serverlessv2_scaling_configuration { min_capacity = 0, max_capacity = 1 }` (or more), with `seconds_until_auto_pause`. 0 ACU needs Aurora PostgreSQL 16.3+ / Aurora MySQL 3.08.0+. The first connection of a run resumes the cluster; `run.sh` retries it 6 times, 20 seconds apart, with a 30-second connect timeout.
- `iam_database_authentication_enabled = true`.
- `manage_master_user_password = true`: RDS keeps the master password in a Secrets Manager secret whose JSON has `username` and `password`; dbfence reads `password`.
- Port 5432 / 3306 (the defaults). TLS is verified (`verify-full`) against the [RDS global CA bundle](https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem) baked into the image.
- A security group that allows the task's security group on the database port.

**ECS**:

- `aws_ecs_cluster` (Fargate; no capacity provider configuration needed). No service and no task definition: ecspresso registers the task definition `dbfence-e2e-<engine>` on every run.
- `aws_cloudwatch_log_group` for the task (for example 14 days retention).
- Task subnets that reach the clusters and also ECR, CloudWatch Logs, Secrets Manager and STS: public subnets with `ecs_task_assign_public_ip = "ENABLED"`, or private subnets with a NAT gateway or VPC endpoints (`ecr.api`, `ecr.dkr`, `s3` gateway, `logs`, `secretsmanager`, `sts`).
- A security group for the task with outbound HTTPS and the database ports.

**ECR**: `aws_ecr_repository` (for example `dbfence-e2e`), with a lifecycle policy that expires old images. Every run pushes a new tag, so tag immutability may be on.

**IAM roles**:

- Execution role: trusted by `ecs-tasks.amazonaws.com`, with `AmazonECSTaskExecutionRolePolicy`.
- Task role: trusted by `ecs-tasks.amazonaws.com`, with
  - `secretsmanager:GetSecretValue` on both master user secrets (and `kms:Decrypt` if they use a customer managed key);
  - `rds-db:connect` on `arn:aws:rds-db:<region>:<account>:dbuser:<cluster_resource_id>/e2e_iam` of both clusters (`aws_rds_cluster.*.cluster_resource_id`). `e2e_iam` is the name the scenario gives its IAM user (`e2e/targets/aws-*/iam_user.hcl`); dbfence creates it.
- GitHub role (`AWS_ROLE_ARN`): trusted by the GitHub OIDC provider (`aws_iam_openid_connect_provider` for `https://token.actions.githubusercontent.com`, audience `sts.amazonaws.com`) with the condition `token.actions.githubusercontent.com:sub` = `repo:mazrean/dbfence:environment:e2e-aws`, and
  - `ecr:GetAuthorizationToken` (resource `*`), and `ecr:BatchCheckLayerAvailability`, `ecr:InitiateLayerUpload`, `ecr:UploadLayerPart`, `ecr:CompleteLayerUpload`, `ecr:PutImage`, `ecr:BatchGetImage` on the repository;
  - `ecs:RegisterTaskDefinition`, `ecs:DescribeTaskDefinition`, `ecs:ListTaskDefinitions`, `ecs:TagResource` (resource `*`), and `ecs:RunTask`, `ecs:DescribeTasks`, `ecs:StopTask`, `ecs:DescribeClusters` on the cluster and its tasks;
  - `iam:PassRole` on the execution and task roles (condition `iam:PassedToService` = `ecs-tasks.amazonaws.com`);
  - `logs:GetLogEvents`, `logs:FilterLogEvents`, `logs:DescribeLogStreams` on the log group, so that ecspresso can stream the output;
  - `s3:GetObject` on the state object (and `kms:Decrypt` on its key if the bucket uses SSE-KMS), for the tfstate plugin.

### `e2e-gcp` variables

| Variable | Value | Terraform source |
|---|---|---|
| `GCP_PROJECT_ID` | Project of every resource below | — |
| `GCP_REGION` | Region of the Cloud Run job | — |
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | Full provider name, `projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>` | `google_iam_workload_identity_pool_provider.github.name` |
| `GCP_SERVICE_ACCOUNT` | Email of the service account the workflow impersonates | `google_service_account.github.email` |
| `DBFENCE_E2E_ARTIFACT_REPOSITORY` | `<region>-docker.pkg.dev/<project>/<repository>`; the image is `<this>/dbfence-e2e` | `google_artifact_registry_repository.e2e` |
| `DBFENCE_E2E_RUN_SERVICE_ACCOUNT` | Email of the job's runtime service account | `google_service_account.job.email` |
| `DBFENCE_E2E_RUN_NETWORK` | VPC network of Direct VPC egress | `google_compute_network.e2e.name` |
| `DBFENCE_E2E_RUN_SUBNET` | Subnet of Direct VPC egress | `google_compute_subnetwork.e2e.name` |
| `DBFENCE_E2E_POSTGRES_INSTANCE` | Name of the PostgreSQL instance, which the workflow starts and stops | `google_sql_database_instance.postgres.name` |
| `DBFENCE_E2E_POSTGRES_HOST` | Private IP of the PostgreSQL instance | `google_sql_database_instance.postgres.private_ip_address` |
| `DBFENCE_E2E_POSTGRES_ADMIN_USER` | Built-in admin user (for example `postgres`) | `google_sql_user.postgres_admin.name` |
| `DBFENCE_E2E_POSTGRES_ADMIN_SECRET` | `projects/<project>/secrets/<secret>` holding its password | `google_secret_manager_secret.postgres_admin.id` |
| `DBFENCE_E2E_POSTGRES_IAM_USER` | Database user name of the runtime service account: its email without `.gserviceaccount.com` | `trimsuffix(google_service_account.job.email, ".gserviceaccount.com")` |
| `DBFENCE_E2E_MYSQL_INSTANCE` | Name of the MySQL instance, which the workflow starts and stops | `google_sql_database_instance.mysql.name` |
| `DBFENCE_E2E_MYSQL_HOST` | Private IP of the MySQL instance | `google_sql_database_instance.mysql.private_ip_address` |
| `DBFENCE_E2E_MYSQL_ADMIN_USER` | Built-in admin user (for example `root`) | `google_sql_user.mysql_admin.name` |
| `DBFENCE_E2E_MYSQL_ADMIN_SECRET` | `projects/<project>/secrets/<secret>` holding its password | `google_secret_manager_secret.mysql_admin.id` |
| `DBFENCE_E2E_MYSQL_IAM_USER` | Database user name of the runtime service account: the part of its email before `@` | `split("@", google_service_account.job.email)[0]` |

### Google Cloud resources

Enable the APIs `run`, `sqladmin`, `secretmanager`, `artifactregistry`, `iamcredentials`, `servicenetworking`, `compute` and `logging`.

**Network**: a VPC network with

- a subnet for Cloud Run Direct VPC egress in `GCP_REGION` (at least /26); the job sends only private ranges through it (`--vpc-egress private-ranges-only`), and reaches Google APIs directly;
- private services access (`google_compute_global_address` with `purpose = "VPC_PEERING"` and `google_service_networking_connection`) for the Cloud SQL private IPs;
- no extra firewall rule is needed for egress from the subnet to Cloud SQL (implied allow egress).

**Cloud SQL instances** (`google_sql_database_instance`, one per engine):

- `POSTGRES_17` (16 or later) and `MYSQL_8_4` (or `MYSQL_8_0`); the smallest tier is enough (for example `db-f1-micro` / `db-custom-1-3840`).
- `ip_configuration { ipv4_enabled = false, private_network = <network>, ssl_mode = "ENCRYPTED_ONLY" }`. dbfence connects with `tls = "require"` over the private IP.
- Database flags `cloudsql.iam_authentication = on` (PostgreSQL) and `cloudsql_iam_authentication = on` (MySQL).
- `settings { activation_policy = "NEVER" }`: the instance is stopped except while a run uses it. The workflow switches the policy, so add `lifecycle { ignore_changes = [settings[0].activation_policy] }`, or `terraform apply` during a run stops the instance under it. Terraform cannot change most settings of a stopped instance either: start it with `gcloud sql instances patch <name> --activation-policy ALWAYS` before such an apply, and stop it afterwards. The private IP stays the same across stops.
- A runner that dies without running the stop step (the step runs on failure and cancellation, but not when the runner is lost) leaves the instance running until the next run of that engine stops it. Check `gcloud sql instances list --filter settings.activationPolicy=ALWAYS` if a run was lost.
- `deletion_protection` as you prefer; the scenario only creates and drops `e2e_*` objects.

**Users and secrets**:

- An admin `google_sql_user` per instance (type `BUILT_IN`) with a `random_password`, stored as a `google_secret_manager_secret_version` of a secret per engine (`DBFENCE_E2E_*_ADMIN_SECRET`). The payload is the bare password.
- A `google_sql_user` of type `CLOUD_IAM_SERVICE_ACCOUNT` for the runtime service account on each instance. On PostgreSQL its `name` is the email without `.gserviceaccount.com`; on MySQL pass the email, and Cloud SQL names the database user after the part before `@`. dbfence never creates this user; the scenario grants it memberships (`e2e/targets/gcp-*/iam_user.hcl`) and takes them away at cleanup.

**Service accounts**:

- Runtime (`DBFENCE_E2E_RUN_SERVICE_ACCOUNT`): `roles/cloudsql.client` and `roles/cloudsql.instanceUser` on the project, `roles/secretmanager.secretAccessor` on the two admin secrets, and `roles/logging.logWriter`.
- GitHub (`GCP_SERVICE_ACCOUNT`): `roles/run.developer` on the project (creates, updates and executes the jobs), `roles/cloudsql.editor` on the project (`cloudsql.instances.update`, to start and stop the instances; a custom role with `cloudsql.instances.get` and `cloudsql.instances.update` is enough), `roles/iam.serviceAccountUser` on the runtime service account, `roles/artifactregistry.writer` on the repository and `roles/logging.viewer` on the project (prints the job's logs). Allow the GitHub workload identity to impersonate it: `roles/iam.workloadIdentityUser` for `principal://iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/subject/repo:mazrean/dbfence:environment:e2e-gcp`.

**Workload Identity Federation**: a `google_iam_workload_identity_pool` and an OIDC `google_iam_workload_identity_pool_provider` for `https://token.actions.githubusercontent.com`, with `attribute_mapping` `google.subject = assertion.sub`, `attribute.repository = assertion.repository`, and `attribute_condition = "assertion.repository == 'mazrean/dbfence'"`.

**Artifact Registry**: a `DOCKER` `google_artifact_registry_repository` in `GCP_REGION`, with a cleanup policy that deletes old images.

**Cloud Run**: nothing. The workflow deploys the jobs `dbfence-e2e-postgres` and `dbfence-e2e-mysql` itself on every run (`gcloud run jobs deploy`), because their image changes every time; ignore them in Terraform.

### Names shared by both repositories

| Name | Owned by | Used in |
|---|---|---|
| `e2e_iam` | this repository (`e2e/targets/aws-*/iam_user.hcl`) | the task role's `rds-db:connect` resource |
| GitHub environments `e2e-aws`, `e2e-gcp` | this repository (`.github/workflows/e2e.yml`) | the OIDC trust conditions |
| `dbfence-e2e` image name in Artifact Registry | this repository | the repository cleanup policy, if it filters by package |
| ECS task family `dbfence-e2e-<engine>`, Cloud Run jobs `dbfence-e2e-<engine>` | this repository | IAM conditions, if you narrow `ecs:RegisterTaskDefinition` or `run.jobs.*` |
| `e2e_*` objects in the databases | this repository | nothing else on these servers should use the prefix |

### Example: GitHub variables from Terraform

```hcl
resource "github_repository_environment" "e2e_aws" {
  repository  = "dbfence"
  environment = "e2e-aws"
  deployment_branch_policy {
    protected_branches     = true
    custom_branch_policies = false
  }
}

locals {
  e2e_aws_variables = {
    AWS_REGION                          = var.region
    AWS_ROLE_ARN                        = aws_iam_role.github.arn
    DBFENCE_E2E_ECR_REPOSITORY          = aws_ecr_repository.e2e.repository_url
    DBFENCE_E2E_ECS_CLUSTER             = aws_ecs_cluster.e2e.name
    DBFENCE_E2E_TFSTATE_URL             = "s3://${var.state_bucket}/${var.state_key}"
  }
}

resource "github_actions_environment_variable" "e2e_aws" {
  for_each      = local.e2e_aws_variables
  repository    = "dbfence"
  environment   = github_repository_environment.e2e_aws.environment
  variable_name = each.key
  value         = each.value
}
```

`e2e-gcp` follows the same pattern with the variables of its table.

### Example: outputs for ecspresso

```hcl
output "ecs_execution_role_arn" { value = aws_iam_role.execution.arn }
output "ecs_task_role_arn" { value = aws_iam_role.task.arn }
output "ecs_task_subnet_ids" { value = var.task_subnet_ids }
output "ecs_task_security_group_ids" { value = [aws_security_group.task.id] }
output "ecs_task_assign_public_ip" { value = "DISABLED" }
output "ecs_log_group_name" { value = aws_cloudwatch_log_group.e2e.name }

output "postgres_endpoint" { value = aws_rds_cluster.postgres.endpoint }
output "postgres_master_username" { value = aws_rds_cluster.postgres.master_username }
output "postgres_master_user_secret_arn" { value = aws_rds_cluster.postgres.master_user_secret[0].secret_arn }
output "mysql_endpoint" { value = aws_rds_cluster.mysql.endpoint }
output "mysql_master_username" { value = aws_rds_cluster.mysql.master_username }
output "mysql_master_user_secret_arn" { value = aws_rds_cluster.mysql.master_user_secret[0].secret_arn }
```
