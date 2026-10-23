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
