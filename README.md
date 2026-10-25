# dbfence

Declarative management of the *outer frame* of MySQL and PostgreSQL servers —
databases, users / roles, role memberships, privileges and PostgreSQL schemas —
written in HCL. Tables are out of scope; use your schema migration tool for those.

- `plan` compares the configuration with the live server and prints the SQL it would run. Passwords are redacted.
- `apply` runs that SQL.
- There is no state file: every run compares the HCL with the live server.

Supported engines: MySQL 8.0+ and PostgreSQL, including Amazon RDS and Google Cloud SQL:

- dbfence can connect with RDS or Cloud SQL IAM database authentication instead of a password.
- Users can be declared to log in with IAM (`aws_iam {}`, `gcp_iam {}`).
- Passwords and endpoints can come from AWS Secrets Manager, GCP Secret Manager or Terraform state.

## Install

```sh
go install github.com/mazrean/dbfence@latest
```

Prebuilt binaries for Linux, macOS and Windows are on the [releases page](https://github.com/mazrean/dbfence/releases).

<details>
<summary>Homebrew, Linux packages, Docker</summary>

### Homebrew (macOS)

```sh
brew install --cask mazrean/tap/dbfence
```

### Linux packages (Debian / Ubuntu / RHEL / Fedora / openSUSE / Alpine)

```sh
# Debian / Ubuntu
curl -LO https://github.com/mazrean/dbfence/releases/latest/download/dbfence_<version>_linux_amd64.deb
sudo dpkg -i dbfence_<version>_linux_amd64.deb

# RHEL / Fedora / openSUSE
sudo rpm -i dbfence_<version>_linux_amd64.rpm

# Alpine
apk add --allow-untrusted dbfence_<version>_linux_amd64.apk
```

### Docker

The image `ghcr.io/mazrean/dbfence` (linux/amd64, linux/arm64) is tagged with the release (`v1.2.3`), its minor version (`1.2`) and `latest`.
It runs as a non-root user and includes CA certificates for TLS connections.

```sh
docker run --rm -v "$PWD:/work:ro" ghcr.io/mazrean/dbfence -C /work plan
docker run --rm -it -v "$PWD:/work:ro" ghcr.io/mazrean/dbfence -C /work apply
```

`apply` needs `-it` for its confirmation prompt (or `--auto-approve`).
Pass the environment variables the configuration reads (`-e PGPASSWORD`, AWS / GCP credentials, ...) to the container.

</details>

## Quick start

Write the configuration in `*.hcl` files. This example is for PostgreSQL; see [`examples/mysql`](examples/mysql) for MySQL.

```hcl
connection "postgres" {
  host     = "db.internal"
  user     = "admin"
  password = secretenv("PGPASSWORD")
  tls      = "verify-full"
}

role "readonly" {}                 # role: cannot log in

user "app" {                       # user: can log in
  password  = secretenv("APP_PASSWORD")
  member_of = [role.readonly.id]
}

database "app" {
  owner = user.app.name
}

grant {
  role       = role.readonly.id
  database   = database.app.name
  privileges = ["CONNECT"]
}
```

Then, in the same directory:

```sh
dbfence validate   # check the configuration
dbfence plan       # print the SQL it would run
dbfence apply      # print the SQL, ask for "yes", then run it
```

dbfence reads every `*.hcl` file in the working directory (`-C DIR` for another one) and merges them.

`plan` prints annotated SQL:

```sql
-- warning: unmanaged user "stray" (use --prune to drop it)

-- [create] role "readonly"
CREATE ROLE "readonly" WITH NOLOGIN;

-- [create] user "app"
CREATE ROLE "app" WITH LOGIN PASSWORD '<redacted>';

-- [grant] membership of "app" in "readonly"
GRANT "readonly" TO "app";

-- [create] database "app"
CREATE DATABASE "app" OWNER "app";

-- [grant] CONNECT on database "app" to "readonly"
GRANT CONNECT ON DATABASE "app" TO "readonly";

-- Plan: 3 to create, 0 to change, 2 to grant, 0 to drop (5 statements).
```

To try it on local servers, see [`examples/`](examples).

## Safety

- Nothing is dropped unless you pass `--prune`; undeclared roles, databases and schemas only produce warnings.
- Built-in objects, the connected user and the database it is connected to are never dropped, and changes that would lock the connected user out are skipped.
- Every plan is checked again, by code independent of the planner, before it is printed or applied.
- Secrets are redacted from all output.

See [Safety](docs/safety.md) for the details.

## Agent Skill

[`skills/managing-dbfence`](skills/managing-dbfence) is an [Agent Skill](https://agentskills.io/specification)
that teaches coding agents (Claude Code, Codex, ...) to write dbfence HCL and run `validate` / `plan` / `apply` safely.
Add it to the `dependencies.apm` list of your `apm.yml` as `mazrean/dbfence/skills/managing-dbfence`,
or copy the directory into your agent's skills directory (for Claude Code, `.claude/skills/`).

## Documentation

- [CLI](docs/cli.md): commands, flags, `--target`, output and exit codes
- [Configuration](docs/configuration.md): every block and attribute
- [Functions](docs/functions.md): `env`, `secretenv`, secret stores, Terraform state
- [Secrets](docs/secrets.md): which values are secrets and how output is redacted
- [Passwords](docs/passwords.md): how passwords are compared and set
- [Safety](docs/safety.md): what dbfence never drops or changes
- [Required privileges](docs/privileges.md): what the connected user needs
- [Amazon RDS](docs/aws-rds.md) and [Google Cloud SQL](docs/gcp-cloud-sql.md): IAM authentication and other setups
- [Development](docs/development.md): tests, lint and the SQL building rules
