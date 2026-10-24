# Development

```sh
mise run test               # unit tests (-short)
mise run test:integration   # also starts MySQL 8.4 / PostgreSQL 17 containers with dockertest
mise run lint               # go vet -vettool=$(go tool -n lint) ./...
mise run generate           # regenerate kessoku injectors
mise run test:fuzz          # run each Go fuzz target for 30s
mise run e2e:local          # run the end-to-end scenario against local Docker servers
```

The end-to-end scenario also runs against Aurora and Cloud SQL from GitHub Actions; see [End-to-end tests](e2e.md).

## Fuzzing

Fuzz targets (`Fuzz*`) cover ignore patterns, the MySQL database pattern matcher, the SCRAM / md5 / caching_sha2 / sha256 / native verifier parsers, the inspected PostgreSQL ACL and membership state, loading a configuration file, and the SQL of both Dialects: for arbitrary names every statement must lex as a single statement with no `;`, `--`, `/*` (or MySQL `#`) outside quoted identifiers and literals. Their seed corpora run with the normal `go test`.

## Building SQL

SQL statements are built only from typed fragments (`internal/plan`): SQL text is a constant `plan.Keyword`, and names, literals, privilege and charset words and numbers enter only through the engine Dialect, which quotes, escapes or validates them. A runtime string passed as SQL does not compile.

The `sqlfragment` lint rule rejects:

- converting a non-constant to `plan.Keyword` (or to a pointer, slice, struct or other type built from it);
- building quoted fragments outside `internal/driver`.

Outside `internal/plan` and tests it also rejects the ways to fill a `plan.Keyword` without a conversion, and code it cannot read:

- pointers to values that contain one (`&k`, `new`, `*plan.Keyword` types, which `json.Unmarshal` or `fmt.Sscan` would write through);
- instantiating a generic defined outside `internal/plan` with a type argument that contains one;
- slicing or indexing a `plan.Keyword`, and concatenating Keywords at runtime (`k + k2`, `k += k2`; join fragments with `plan.Seq` instead);
- importing `reflect`, `unsafe` or `encoding/gob`;
- function declarations without a Go body (assembly) and non-Go files such as `.s` or `.syso`.

`mise run lint` checks the host build, and a test fails on any file excluded by a build constraint or a `_GOOS`/`_GOARCH` suffix, with or without cgo, so every build compiles exactly the files the linter checked.

The lint rule catches mistakes, not deliberate obfuscation: picking one-character constant Keywords by a runtime index can still spell any string, and code review has to reject that.

## Plan metadata

Each planned statement also records what it does (`Kind`: create role, grant, drop database, ...) and its target object, plus what a role change sets (login disabled, account lock, superuser removed, connection limit), so plans can be checked without parsing SQL. The [independent safety check](safety.md#independent-safety-check) reads only this metadata.
