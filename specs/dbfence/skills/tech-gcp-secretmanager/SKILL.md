---
name: tech-gcp-secretmanager
description: Google Cloud Secret Manager Go client research digest (AccessSecretVersion, ADC, resource names). Use when implementing the gcp_secretmanager() HCL function in dbfence internal/funcs.
---

# GCP Secret Manager — Research Digest

## TL;DR

`secretmanager.NewClient(ctx)` (Application Default Credentials) then `AccessSecretVersion` with the
resource name `projects/<p>/secrets/<s>/versions/<v>`. dbfence accepts `name` as
`projects/p/secrets/s` and appends `/versions/<version>` (default `latest`); a name already containing
`/versions/` is used as-is.

## Identity

- **Version**: `cloud.google.com/go/secretmanager` v1.x (apiv1) — pin via `go get`.
- **Docs**: https://pkg.go.dev/cloud.google.com/go/secretmanager/apiv1 — License Apache-2.0

## API We Use

```go
import secretmanager "cloud.google.com/go/secretmanager/apiv1"
import "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
c, err := secretmanager.NewClient(ctx); defer c.Close()
resp, err := c.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{Name: name})
resp.GetPayload().GetData() []byte   // optional: verify resp.Payload.DataCrc32C (crc32.Castagnoli)
```

## Pitfalls

- **gRPC client is heavy** → created lazily once per process (as built it is not explicitly closed).
- **Payload is bytes** → returned as string (as built, no explicit UTF-8 check).
- **Not-found / permission** → `status.Code(err)` is `codes.NotFound` / `codes.PermissionDenied`; wrap with the resource name only.
- **Interface** `GCPSecretManager.AccessSecretVersion(ctx, name) (string, error)` in `internal/funcs`;
  tests use a fake via `WithGCP` (no emulator).

## Confidence

- **High**: API and resource-name format. **Medium**: CRC check worth it — optional.
