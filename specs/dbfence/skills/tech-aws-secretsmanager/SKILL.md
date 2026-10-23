---
name: tech-aws-secretsmanager
description: aws-sdk-go-v2 Secrets Manager research digest (GetSecretValue, credential chain, JSON secrets). Use when implementing the aws_secretsmanager() HCL function in dbfence internal/funcs.
---

# AWS Secrets Manager (aws-sdk-go-v2) — Research Digest

## TL;DR

Lazily build one client from `config.LoadDefaultConfig(ctx)` on first call, then `GetSecretValue`.
The secret is in `SecretString` (usually) or `SecretBinary`. With `json_key`, parse the string as a
JSON object and return that key's value (string as-is, other types JSON-encoded).

## Identity

- **Version**: `github.com/aws/aws-sdk-go-v2/service/secretsmanager` v1.x, `aws-sdk-go-v2/config` v1.x — pin via `go get` (verify latest at implementation time).
- **Docs**: https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/secretsmanager — License Apache-2.0

## API We Use

```go
cfg, err := config.LoadDefaultConfig(ctx)          // env, shared config/SSO, IMDS, IRSA
c := secretsmanager.NewFromConfig(cfg)
out, err := c.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(id)})
out.SecretString *string ; out.SecretBinary []byte
var nf *types.ResourceNotFoundException ; errors.As(err, &nf)
```

`SecretId` accepts a name or full ARN (ARN needed for cross-account). Version stage defaults to `AWSCURRENT`.

## Pitfalls

- **No region** → LoadDefaultConfig succeeds but call fails; as built, region comes only from the default
  chain (`AWS_REGION`/profile) — region-from-ARN is not implemented.
- **Client init** → built lazily once on the first call; `validate` also calls it (functions are evaluated).
- **Error text** may include the secret id but never the value; still wrap errors without echoing returned data.
- **Interface** `AWSSecretsManager.GetSecretString(ctx, id)` in `internal/funcs` (`WithAWS` overrides).
- **Tests** run the real SDK against the in-process `sivchari/kumo` emulator via `AWS_ENDPOINT_URL`
  (`internal/funcs/aws_test.go`); not parallel with other tests because of `t.Setenv`.

## Confidence

- **High**: API shape (stable since v1.0). **Medium**: region-from-ARN behavior — implement explicitly.
