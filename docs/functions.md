# Functions

| Function | Returns |
|---|---|
| `env(name, [default])` | An environment variable. It is an error if the variable is unset and no default is given |
| `secretenv(name, [default])` | Like `env`, for a variable that holds a secret such as a password |
| `aws_secretsmanager(secret_id, [json_key])` | An AWS Secrets Manager secret string, or one key of a JSON secret (a string, number or boolean; use `jsondecode(aws_secretsmanager(id))` for objects and arrays). Standard AWS credentials and `AWS_ENDPOINT_URL` apply |
| `gcp_secretmanager(name, [version])` | A GCP Secret Manager payload. `name` is `projects/<p>/secrets/<s>[/versions/<v>]` (regional `locations/` names are not supported), and `version` defaults to `latest` |
| `tfstate(url, address)` | A value from a Terraform state on `s3://`, `gs://`, a local path, and so on. Relative paths are resolved against the configuration directory. Examples: `aws_db_instance.main.address`, `output.db_host` |
| `urlencode(str)` | `str` percent-encoded for any URL part, such as the userinfo of a `tfstate` URL. A space becomes `%20` (not `+` as in Terraform) and `+` becomes `%2B` |

The results of `secretenv`, `aws_secretsmanager`, `gcp_secretmanager` and `tfstate`, and every value computed from them, are secrets; `env` results are not. See [Secrets](secrets.md).

Each secret is fetched once per run. Secret payloads and `base64decode` results must be valid UTF-8, and strings are NFC-normalised (a password in decomposed Unicode form reaches the server composed).

A subset of the cty standard library is also available: `abs`, `base64decode`, `base64encode`, `chomp`, `coalesce`, `concat`, `contains`, `csvdecode`, `distinct`, `flatten`, `format`, `formatlist`, `join`, `jsondecode`, `jsonencode`, `keys`, `length`, `lookup`, `lower`, `merge`, `regex`, `replace`, `split`, `substr`, `tolist`, `tomap`, `tonumber`, `toset`, `tostring`, `trimspace`, `upper` and `values`. `lookup(map, key, default)` requires all three arguments.
