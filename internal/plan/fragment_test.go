package plan

import (
	"testing"

	"github.com/mazrean/dbfence/internal/model"
)

func TestFragmentRendering(t *testing.T) {
	t.Parallel()
	secret := NewSecret(EscapedLiteral("'pw'"))
	tests := []struct {
		name, wantSQL, wantDisplay string
		parts                      []Fragment
		wantSecret                 bool
	}{
		{name: "keyword", parts: []Fragment{Keyword("DROP ROLE ")}, wantSQL: "DROP ROLE ", wantDisplay: "DROP ROLE "},
		{name: "ident", parts: []Fragment{QuotedIdent(`"a""b"`)}, wantSQL: `"a""b"`, wantDisplay: `"a""b"`},
		{name: "literal", parts: []Fragment{EscapedLiteral(`'it''s'`)}, wantSQL: `'it''s'`, wantDisplay: `'it''s'`},
		{name: "token", parts: []Fragment{NewToken("CREATE TEMPORARY TABLES")}, wantSQL: "CREATE TEMPORARY TABLES", wantDisplay: "CREATE TEMPORARY TABLES"},
		{name: "number", parts: []Fragment{Keyword("CONNECTION LIMIT "), Number(-1)}, wantSQL: "CONNECTION LIMIT -1", wantDisplay: "CONNECTION LIMIT -1"},
		{name: "secret", parts: []Fragment{Keyword("PASSWORD "), secret}, wantSQL: "PASSWORD 'pw'", wantDisplay: "PASSWORD '<redacted>'", wantSecret: true},
		{name: "secret nested in a sequence", parts: []Fragment{Seq{Keyword("BY "), Seq{secret}}}, wantSQL: "BY 'pw'", wantDisplay: "BY '<redacted>'", wantSecret: true},
		{name: "join", parts: []Fragment{Join(", ", NewToken("SELECT"), NewToken("INSERT"))}, wantSQL: "SELECT, INSERT", wantDisplay: "SELECT, INSERT"},
		{name: "join of nothing", parts: []Fragment{Join[Token](", ")}, wantSQL: "", wantDisplay: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := SQL("", tt.parts...)
			if got := s.SQL(); got != tt.wantSQL {
				t.Errorf("SQL() = %q, want %q", got, tt.wantSQL)
			}
			if got := s.Display(false); got != tt.wantDisplay {
				t.Errorf("Display(false) = %q, want %q", got, tt.wantDisplay)
			}
			if got := s.HasSecret(); got != tt.wantSecret {
				t.Errorf("HasSecret() = %v, want %v", got, tt.wantSecret)
			}
		})
	}
}

func TestNewToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		word string
		ok   bool
	}{
		{word: "SELECT", ok: true},
		{word: "GRANT OPTION", ok: true},
		{word: "utf8mb4_0900_ai_ci", ok: true},
		{word: "", ok: false},
		{word: "SELECT ", ok: false},
		{word: "SELECT  INSERT", ok: false},
		{word: "SELECT, INSERT", ok: false},
		{word: "x'; DROP ROLE r; --", ok: false},
		{word: "auth-pam", ok: false},
		{word: "café", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.word, func(t *testing.T) {
			t.Parallel()
			if got := IsWords(tt.word); got != tt.ok {
				t.Errorf("IsWords(%q) = %v, want %v", tt.word, got, tt.ok)
			}
			defer func() {
				if r := recover(); (r == nil) != tt.ok {
					t.Errorf("NewToken(%q) panicked = %v, want %v", tt.word, r != nil, !tt.ok)
				}
			}()
			_ = NewToken(tt.word)
		})
	}
}

func TestStatementMetadata(t *testing.T) {
	t.Parallel()
	r := model.RoleID{Name: "r"}
	limit := 0
	tests := []struct {
		wantChange RoleChange
		name       string
		wantKind   Kind
		stmt       Statement
		wantTarget Target
	}{
		{name: "SQL is other", stmt: SQL("", Keyword("SELECT 1")), wantKind: KindOther},
		{
			name: "role", stmt: New("", KindAlterRole, RoleTarget(r), Keyword("ALTER ROLE ...")).WithRoleChange(RoleChange{DisablesLogin: true, ConnectionLimit: &limit}),
			wantKind: KindAlterRole, wantTarget: Target{Object: ObjectRole, Role: r}, wantChange: RoleChange{DisablesLogin: true, ConnectionLimit: &limit},
		},
		{
			name: "membership", stmt: New("", KindGrantMembership, MembershipTarget(model.RoleID{Name: "m"}, r).WithOption(true)),
			wantKind: KindGrantMembership, wantTarget: Target{Object: ObjectRole, Role: r, Grantee: model.RoleID{Name: "m"}, Option: true},
		},
		{
			name: "privilege on a schema", stmt: New("d", KindGrant, PrivilegeTarget(r, model.Object{Type: model.ObjectSchema, Database: "d", Schema: "s"})),
			wantKind: KindGrant, wantTarget: Target{Object: ObjectSchema, Database: "d", Schema: "s", Grantee: r},
		},
		{
			name: "database pattern", stmt: New("", KindRevoke, PrivilegeTarget(r, model.Object{Type: model.ObjectDatabase, Database: "a_b", Pattern: "a_%"})),
			wantKind: KindRevoke, wantTarget: Target{Object: ObjectDatabase, Database: "a_b", Pattern: "a_%", Grantee: r},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.stmt.Kind(); got != tt.wantKind {
				t.Errorf("Kind() = %q, want %q", got, tt.wantKind)
			}
			if got := tt.stmt.Target(); got != tt.wantTarget {
				t.Errorf("Target() = %+v, want %+v", got, tt.wantTarget)
			}
			got := tt.stmt.RoleChange()
			if (got.ConnectionLimit == nil) != (tt.wantChange.ConnectionLimit == nil) ||
				(got.ConnectionLimit != nil && *got.ConnectionLimit != *tt.wantChange.ConnectionLimit) {
				t.Errorf("RoleChange().ConnectionLimit = %v, want %v", got.ConnectionLimit, tt.wantChange.ConnectionLimit)
			}
			got.ConnectionLimit, tt.wantChange.ConnectionLimit = nil, nil
			if got != tt.wantChange {
				t.Errorf("RoleChange() = %+v, want %+v", got, tt.wantChange)
			}
		})
	}
}
