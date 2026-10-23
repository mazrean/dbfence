---
name: tech-password-hashing
description: Stored password hash formats and verification research digest — PostgreSQL SCRAM-SHA-256 and md5, MySQL mysql_native_password and caching_sha2_password ($A$ SHA256-crypt). Use when implementing or testing internal/password in dbfence, or any password-drift detection.
---

# Password Hash Verification — Research Digest

## TL;DR

Given a plaintext from HCL and the stored hash from the server, recompute and compare in constant time
(`crypto/subtle`). Four formats; anything else ⇒ "unsupported" (warn, skip). As built: `SHA256Crypt` is
verified against `openssl passwd -5` vectors in unit tests; real-server verification of SCRAM and
caching_sha2 happens in the dockertest integration tests (apply then re-plan converges). No
`testdata/` fixtures are committed.

## Identity

- Go 1.27 stdlib: `crypto/pbkdf2` (`func Key[Hash hash.Hash](h func() Hash, password string, salt []byte, iter, keyLength int) ([]byte, error)`, verified 2026-10-23), `crypto/hmac`, `crypto/sha256`, `crypto/sha1`, `crypto/md5`, `crypto/subtle`.
- SASLprep: `golang.org/x/text/secure/precis` (`precis.OpaqueString`).
- Sources: RFC 5802 / RFC 7677 (SCRAM), PostgreSQL `src/common/scram-common.c`;
  MySQL `sql/auth/sha2_password.cc`, `sql/auth/sha2_password_common.cc`, `mysys/crypt_genhash_impl.cc`;
  cross-check: go-mysql-org/go-mysql.

## Formats

| Engine | Format | Verify |
|--------|--------|--------|
| PG | `SCRAM-SHA-256$<iter>:<b64 salt>$<b64 StoredKey>:<b64 ServerKey>` | `salted = PBKDF2-HMAC-SHA256(SASLprep(pw), salt, iter, 32)`; `ClientKey = HMAC(salted, "Client Key")`; `StoredKey = SHA256(ClientKey)`; compare. (Optionally also `ServerKey = HMAC(salted, "Server Key")`.) |
| PG | `md5<32 hex>` | `"md5" + hex(md5(pw + rolname))` |
| MySQL `mysql_native_password` | `*<40 HEX>` | `"*" + upper(hex(sha1(sha1(pw))))` |
| MySQL `caching_sha2_password` | `$A$<3 hex iter/1000>$<20-byte salt><43-char digest>` | iterations = hex value × 1000 (default `005` ⇒ 5000); digest = SHA256-crypt (Drepper, `$5$` algorithm) of pw with the 20-byte salt and that round count, crypt-base64 alphabet `./0-9A-Za-z`, 43 chars; compare last 43 chars. |

## Pitfalls

- **SASLprep failure** (prohibited chars) → PostgreSQL uses the raw password; do the same on error.
- **caching_sha2 salt is raw bytes** (masked to 7-bit, `\0` and `$` bumped) → read via `HEX(authentication_string)` and decode; never treat as UTF-8 string.
- **Iteration field is hex**, not decimal (`std::hex` in serialize); MySQL caps at MAX_ITERATIONS.
- **SHA256-crypt with non-default rounds** — Drepper's spec; MySQL calls it with a fixed salt length of 20 (spec's 16-byte max salt does NOT apply). Port carefully; this is the riskiest item → fixtures first (Task 4).
- **Empty stored hash** (`''`/NULL) → "no password"; desired password present ⇒ change (MySQL: matches only an empty password).
- **Plugins `auth_socket`, `sha256_password`, `authentication_ldap_*`** → unsupported ⇒ warn + skip.
- **Never log** plaintext or computed digests.

## Integration Pattern

```go
// internal/password
func MatchPostgres(verifier, user, password string) (bool, error) // ErrUnsupported for unknown formats
func MatchMySQL(plugin string, authString []byte, password string) (bool, error) // authString from HEX(authentication_string)
func SHA256Crypt(password, salt []byte, rounds int) []byte                        // 43-char digest
```

## Confidence

- **High**: SCRAM, md5, native formats (RFCs/docs). 
- **High**: caching_sha2 rounds/salt handling — hex iteration ×1000 from `sha2_password.cc`; SHA256-crypt matches
  `openssl passwd -5`; convergence against MySQL 8.4 is covered by the integration test.
