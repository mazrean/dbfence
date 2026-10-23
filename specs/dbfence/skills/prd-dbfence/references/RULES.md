# dbfence - Code-Area Constraints

These constraints should be extracted to L2 path-conditional rules. As built, `.claude/rules/dbfence.md`
has NOT been created yet; the constraints below are enforced by review only.

## Constraints

- Never format a secret into an error message, log line or `fmt.Stringer`; carry sensitive literals as
  `plan.Secret` fragments of a `plan.Statement` so redaction is structural, not regex-based.
- Identifiers MUST go through the driver's `Ident` function; literals through its `Literal` function.
  No `fmt.Sprintf("... %s ...", name)` with raw names.
- `internal/diff` and `internal/plan` do no I/O (no DB, no network). Driver `Dialect`s own all SQL text.
- Engine-specific logic lives only under `internal/driver/<engine>/` and `internal/password/`.
- Built-in exclusion lists live in one place per driver (`Dialect.IsSystem*`).
- SQLite or any other engine MUST NOT be added (no `modernc.org/sqlite`, no `mattn/go-sqlite3`).
- External services (AWS, GCP, tfstate backends) are reached only through small interfaces in
  `internal/funcs` so tests can mock them.

## L2 Extraction Target

Extract to `.claude/rules/dbfence.md`:

    ---
    paths:
      - "internal/**/*.go"
      - "*.go"
    ---

    dbfence constraints (from specs/dbfence/skills/prd-dbfence/SKILL.md):
    - Secrets never in errors/logs; sensitive literals are plan.Secret fragments
    - Quote identifiers / escape literals via the driver only
    - diff and plan packages are pure (no I/O)
    - Engine-specific code only in internal/driver/<engine> and internal/password
    - MySQL and PostgreSQL only; never add SQLite
    - External services behind interfaces in internal/funcs
