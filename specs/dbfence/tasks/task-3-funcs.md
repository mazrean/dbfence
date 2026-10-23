---
description: HCL functions env / aws_secretsmanager / gcp_secretmanager / tfstate for dbfence
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Skill
---

# Task 3: HCL functions env / aws_secretsmanager / gcp_secretmanager / tfstate

> **As built** (implementation deviates from the steps below):
> - Interfaces are `AWSSecretsManager.GetSecretString`, `GCPSecretManager.AccessSecretVersion(ctx, name)`, `TFState.Lookup(ctx, url, address)`; `With*` options override them.
> - No sensitive marks and no validate mode: `validate` evaluates functions for real. Redaction is structural in `plan.Secret`.
> - AWS (Secrets Manager + tfstate on S3) is tested against the in-process `sivchari/kumo` emulator via `AWS_ENDPOINT_URL`/`AWS_ENDPOINT_URL_S3`; GCP uses a fake.

<background_information>
- **PRD**: specs/dbfence/skills/prd-dbfence/SKILL.md
- **Design**: specs/dbfence/design-dbfence.md
- **Depends on**: Task 2
- **Spec refs**: FR-5 … FR-11, FR-22, NFR-2
</background_information>

<instructions>
## Pre-check

Confirm the dependencies are checked `- [x]` in `specs/dbfence/tasks/overview.md` and their packages build
(`go build ./...`). If not, report which task must be completed first and stop without committing.

## Core Task

Implement `internal/funcs.Registry` with cached, context-carrying functions and sensitive marks, and plug it into
`config.Load`. External services go through the `AWSSecrets`, `GCPSecrets`, `TFStateReader` interfaces from the
design. Validate mode returns unknown (marked) values without network calls. Research:
`specs/dbfence/skills/tech-hcl-cty/`, `tech-aws-secretsmanager/`, `tech-gcp-secretmanager/`, `tech-tfstate-lookup/`.

## Scope

Files to create or modify:
- `internal/funcs/*.go` + `testdata/*.tfstate`
- `internal/config/` (EvalContext wiring only)
- `go.mod`, `go.sum`
- `specs/dbfence/tasks/overview.md` (checklist flip only — see **Update Overview**)

Do NOT modify files outside this scope.

## Steps

1. Implement in order env → aws → gcp → tfstate, each with mock-based tests (call counter for cache).
2. Lazily construct real AWS/GCP clients on first call only.
3. Test that `jsondecode(gcp_secretmanager(...)).password` remains marked (tech-hcl-cty Confidence: Medium item).
4. Test that no secret value appears in any returned error string.

## Verify

Run these verification commands. ALL must pass before moving on:

```bash
go build ./...
go test ./internal/funcs/... ./internal/config/...
go tool lint ./...
```

If verification fails, fix and re-run — do not proceed to commit.

## Update Overview

1. Open `specs/dbfence/tasks/overview.md`.
2. Flip the line starting with `- [ ] Task 3:` to `- [x] Task 3:`.
3. Do not touch other tasks' checkboxes or anything outside the Progress list.
4. Bundle this edit into the same atomic commit as the task changes.

## Commit

1. Review scope: `git status` and `git diff` — only files listed in **Scope** are changed.
2. Invoke the `committing-code` skill to produce and execute the commit.
3. Suggested message:

   ```text
   feat(dbfence): hCL functions env / aws_secretsmanager / gcp_secretmanager / tfstate

   Implements Task 3 (funcs) for dbfence.
   Spec refs: FR-5 … FR-11, FR-22, NFR-2
   ```

4. Verify: `git log -1 --stat` — the overview.md flip must appear in the same commit.
</instructions>

## Done When

- [x] All **Verify** commands pass
- [x] `overview.md` checklist shows `- [x]` for this task
- [ ] `git status` is clean within task scope
- [ ] `git log -1` shows the task commit (with the overview.md flip) and a Conventional Commits message

## Safety & Fallback

- If verification fails, fix and re-run — do not commit a broken state
- If blocked by a dependency, report it and do NOT commit
- Do not modify files outside the defined scope
- Do not amend or rewrite prior task commits
- If unrelated changes are already staged, unstage them before committing
