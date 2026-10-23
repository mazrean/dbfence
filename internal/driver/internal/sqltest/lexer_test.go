package sqltest

import "testing"

func TestCheckSingle(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, sql string
		sx        Syntax
		ok        bool
	}{
		{"plain", `DROP ROLE "a"`, PostgreSQL, true},
		{"semicolon in identifier", `DROP ROLE "a;b"`, PostgreSQL, true},
		{"doubled quote", `DROP ROLE "a""; DROP ROLE x; --"`, PostgreSQL, true},
		{"broken out of identifier", `DROP ROLE "a"; DROP ROLE x; --"`, PostgreSQL, false},
		{"semicolon", `DROP ROLE a; DROP ROLE b`, PostgreSQL, false},
		{"line comment", `DROP ROLE a -- x`, PostgreSQL, false},
		{"block comment", `DROP ROLE a /* x */`, PostgreSQL, false},
		{"unterminated", `DROP ROLE "a`, PostgreSQL, false},
		{"literal with doubled quote", `ALTER ROLE "a" PASSWORD 'it''s; --'`, PostgreSQL, true},
		{"E string with escaped quote", `ALTER ROLE "a" PASSWORD E'x\\'' `, PostgreSQL, false},
		{"E string with backslashes", `ALTER ROLE "a" PASSWORD E'x\\\\'`, PostgreSQL, true},
		{"E string escape", `ALTER ROLE "a" PASSWORD E'\'; DROP ROLE x'`, PostgreSQL, true},
		{"standard string with backslash", `ALTER ROLE "a" PASSWORD 'x\'; DROP ROLE b; --'`, PostgreSQL, false},
		{"dollar quote", `DO $$ x $$`, PostgreSQL, false},
		{"backtick in postgres", "DROP ROLE `a`", PostgreSQL, false},
		{"mysql account", "DROP USER 'a'@'%'", MySQL(false), true},
		{"mysql backslash escape", `CREATE USER 'a\'; DROP USER b; #'@'%'`, MySQL(false), true},
		{"mysql backslash literal", `CREATE USER 'a\'; DROP USER b; #'@'%'`, MySQL(true), false},
		{"mysql hash comment", "DROP USER 'a'@'%' # x", MySQL(false), false},
		{"mysql backtick", "DROP DATABASE `a``;`", MySQL(false), true},
		{"mysql double quote", `DROP DATABASE "a"`, MySQL(false), false},
		{"empty", "", PostgreSQL, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := CheckSingle(tt.sql, tt.sx); (err == nil) != tt.ok {
				t.Errorf("CheckSingle(%q) = %v, want ok %v", tt.sql, err, tt.ok)
			}
		})
	}
}
