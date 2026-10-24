# Secrets

SQL output prints passwords as `'<redacted>'`. As a last line of defense, every [known secret](#known-secrets) is also replaced by `<redacted>` wherever it appears in stdout and stderr, for example in a server error or in a name that happens to equal a password.

`--show-secrets` turns this redaction off: passwords are printed instead of `'<redacted>'`, and known secrets are printed in every message on stdout and stderr, errors included.

## Known secrets

- Role passwords.
- The `password` of the `connection` block, and the IAM tokens dbfence sends instead.
- The userinfo (user name and password), query string, query values and fragment of a literal `tfstate` state URL (`https://user:token@host/...?token=...`).
- Every string returned by `secretenv`, `aws_secretsmanager`, `gcp_secretmanager` and `tfstate`, including strings nested in their objects and lists.
- Every string a function computes from a secret, such as a field `jsondecode` takes out of a secret, or `upper(secretenv("PW"))`.

`env` results are not secrets: use `secretenv` for environment variables that hold passwords. Conversely, a name or host taken from `tfstate` (or equal to a password) is redacted too: use `env` or a literal for values that should stay visible.

## How secrets are found in output

- Besides its raw form, a secret is also found NFC-normalised, URL-encoded (as `urlencode` does, and as a URL query or path), base64-encoded (standard and URL alphabets), JSON-escaped, Go-quoted, SQL-quoted (`'` doubled, with or without `\` doubled as well) and identifier-quoted (`"` or `` ` `` doubled), each also with control characters escaped as printed.
- A multi-line secret is found as a whole across output lines (a line that may begin one is printed once the next lines show it does not), and each of its lines is also found alone.
- Secrets shorter than 4 bytes are not redacted, since they would match ordinary output.
- A secret equal (ignoring case) to an engine name or to the user or database of the connection, such as the password of a default `postgres:postgres` or `root:root` account, is not redacted, since output shows those names by design. SQL output still prints passwords as `'<redacted>'`.

## Errors

- When a function fails on a secret value (for example `tonumber(secretenv("PW"))`), its error is replaced by `the error is not shown because the arguments include a secret value`. A duplicate key error of a `for` expression does not show a secret-derived key.
- The source lines that configuration diagnostics quote show the value of every `password` assignment as `*`, even with `--show-secrets`, since an error can come before the value is known to be a secret. The value is hidden to the end of its line, and further while it has open brackets, heredocs or `${ ... }` / `%{ ... }` template sequences, so a multi-line `format(...)`, `trimspace(<<EOT ...)` or a `${ ... }` spanning lines is hidden as a whole.
- A file with a syntax error that assigns `password` is quoted without source: its diagnostics name the file and line only.
- The literal strings of `password` values are known secrets as soon as the file is parsed, also inside lists, conditionals and function calls other than `env`, `secretenv`, `aws_secretsmanager`, `gcp_secretmanager` and `tfstate` (whose arguments name the secret).
- When a statement with a password fails, see [Passwords](passwords.md#errors).
