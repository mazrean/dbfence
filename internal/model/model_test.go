package model_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mazrean/dbfence/internal/model"
)

func TestRoleIDFormat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		id   model.RoleID
		q, s string
	}{
		{id: model.RoleID{Name: "app"}, q: `"app"`, s: "app"},
		{id: model.RoleID{Name: "app", Host: "%"}, q: `"app"@"%"`, s: "app@%"},
		{id: model.RoleID{Name: "team@ops", Host: "%"}, q: `"team@ops"@"%"`, s: "team@ops@%"},
		{id: model.RoleID{Name: `o'b\r`, Host: "10.0.%"}, q: `"o'b\\r"@"10.0.%"`, s: `o'b\r@10.0.%`},
	}
	for _, tt := range tests {
		if got := fmt.Sprintf("%q", tt.id); got != tt.q {
			t.Errorf("%%q of %#v = %s, want %s", tt.id.Name, got, tt.q)
		}
		if got := fmt.Sprintf("%s|%v", tt.id, tt.id); got != tt.s+"|"+tt.s {
			t.Errorf("%%s of %#v = %s, want %s", tt.id.Name, got, tt.s)
		}
	}
}

func TestSortRoleIDs(t *testing.T) {
	t.Parallel()
	// "a@b" with host "c" and "a" with host "b@c" print the same; sorting
	// by name, then host keeps them apart.
	got := model.SortRoleIDs([]model.RoleID{{Name: "a@b", Host: "c"}, {Name: "a", Host: "z"}, {Name: "a", Host: "b@c"}})
	want := []model.RoleID{{Name: "a", Host: "b@c"}, {Name: "a", Host: "z"}, {Name: "a@b", Host: "c"}}
	if d := cmp.Diff(want, got); d != "" {
		t.Errorf("SortRoleIDs (-want +got):\n%s", d)
	}
}

func TestCompileIgnorePattern(t *testing.T) {
	t.Parallel()
	tests := []struct {
		pattern, name string
		match, err    bool
	}{
		{pattern: "staging", name: "staging", match: true},
		{pattern: "staging", name: "app.staging"},
		{pattern: `app\.staging`, name: "app.staging", match: true},
		{pattern: `app\.stag`, name: "app.staging"},
		{pattern: "a|b", name: "ab"},
		{pattern: "a|b", name: "b", match: true},
		{pattern: "(", err: true},
		{pattern: `\Qrds_`, err: true},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"/"+tt.name, func(t *testing.T) {
			t.Parallel()
			re, err := model.CompileIgnorePattern(tt.pattern)
			if (err != nil) != tt.err {
				t.Fatalf("err = %v, want error %v", err, tt.err)
			}
			if err == nil && re.MatchString(tt.name) != tt.match {
				t.Errorf("match %q = %v, want %v", tt.name, !tt.match, tt.match)
			}
		})
	}
}
