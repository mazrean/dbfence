# Upgrading

Changes that affect existing configurations:

- MySQL: database grants written by earlier versions without escaping (`GRANT ... ON my_app.*`, a wildcard) are revoked and granted again escaped (`my\_app`). The plan shows them under `database pattern "my_app"`.
- MySQL: `role = "public"` without a host is an error; write `"public@%"`.
- PostgreSQL: role and user names equal to `public` in any case are reserved, because grant blocks read them as PUBLIC.
- PostgreSQL: passwords are sent in plaintext and hashed by the server again, so server-side password policies apply. Statement logging can record them (see [Passwords](passwords.md#sending-passwords)).
- PostgreSQL: the default privileges of PUBLIC are now read. Where a grant block manages PUBLIC, undeclared defaults are revoked; elsewhere the only new output is the "keeps ... through PUBLIC" warning when a role loses a privilege PUBLIC still holds.
