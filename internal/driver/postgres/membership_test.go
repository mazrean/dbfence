package postgres

import (
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/model"
)

func TestGrantMembershipRendering(t *testing.T) {
	t.Parallel()
	yes, no := true, false
	tests := []struct {
		opts model.MembershipOptions
		name string
		want string
	}{
		{name: "plain", want: `GRANT "g" TO "u"`, opts: model.MembershipOptions{}},
		{name: "admin", want: `GRANT "g" TO "u" WITH ADMIN OPTION`, opts: model.MembershipOptions{Admin: &yes}},
		{name: "admin false is the default", want: `GRANT "g" TO "u"`, opts: model.MembershipOptions{Admin: &no}},
		{name: "inherit and set", want: `GRANT "g" TO "u" WITH INHERIT FALSE, SET TRUE`, opts: model.MembershipOptions{Inherit: &no, Set: &yes}},
		{name: "all", want: `GRANT "g" TO "u" WITH ADMIN TRUE, INHERIT TRUE, SET FALSE`, opts: model.MembershipOptions{Admin: &yes, Inherit: &yes, Set: &no}},
		{name: "admin false with set", want: `GRANT "g" TO "u" WITH SET FALSE`, opts: model.MembershipOptions{Admin: &no, Set: &no}},
	}
	for _, tt := range tests {
		if got := sqlOf(Dialect{}.GrantMembership(pg("u"), pg("g"), tt.opts)); got != tt.want {
			t.Errorf("%s: got %s, want %s", tt.name, got, tt.want)
		}
	}
}

func TestDialectAlterMembership(t *testing.T) {
	t.Parallel()
	yes, no := true, false
	tests := []struct {
		opts model.MembershipOptions
		name string
		want string
		have model.MembershipState
	}{
		{name: "add admin", want: `GRANT "g" TO "u" WITH ADMIN OPTION`, opts: model.MembershipOptions{Admin: &yes}, have: model.MembershipState{}},
		{name: "drop admin", want: `REVOKE ADMIN OPTION FOR "g" FROM "u"`, opts: model.MembershipOptions{Admin: &no}, have: model.MembershipState{Admin: true}},
		{
			name: "drop admin and inherit", want: `REVOKE ADMIN OPTION FOR "g" FROM "u"` + "\n" + `GRANT "g" TO "u" WITH INHERIT FALSE`,
			opts: model.MembershipOptions{Admin: &no, Inherit: &no}, have: model.MembershipState{Admin: true, Inherit: true},
		},
	}
	for _, tt := range tests {
		stmts, _ := Dialect{}.AlterMembership(pg("u"), pg("g"), tt.opts, tt.have)
		if got := sqlOf(stmts); got != tt.want {
			t.Errorf("%s: got\n%s\nwant\n%s", tt.name, got, tt.want)
		}
		// Before PostgreSQL 16 the driver renders the same statements.
		d := &Driver{st: &state{version: 150000, members: []memberEntry{{role: "g", member: "u", grantor: "x", admin: true}}}}
		stmts, _ = d.AlterMembership(pg("u"), pg("g"), tt.opts, tt.have)
		if got := sqlOf(stmts); got != tt.want {
			t.Errorf("%s on 15: got\n%s\nwant\n%s", tt.name, got, tt.want)
		}
	}
}

func TestStateAlterMembership(t *testing.T) {
	t.Parallel()
	yes, no := true, false
	members := []memberEntry{
		{role: "g", member: "u", grantor: "postgres", admin: true, inherit: true, set: true},
		{role: "g", member: "u", grantor: "other", admin: true, inherit: false, set: true},
		{role: "g", member: "d", grantor: "u", inherit: true, set: true},
		{role: "g", member: "e", grantor: "d", inherit: true, set: true},
		{role: "h", member: "u", grantor: "boss", admin: false, inherit: true, set: true},
		{role: "h", member: "boss", grantor: "postgres", admin: true, inherit: true, set: true},
	}
	desired := &model.Desired{Roles: []model.Role{
		{ID: pg("d"), MemberOf: []model.RoleID{pg("g")}, MemberOptions: map[model.RoleID]model.MembershipOptions{pg("g"): {Inherit: &no}}},
		{ID: pg("e")},
		// boss loses ADMIN OPTION on h, which removes the grant it made.
		{ID: pg("boss"), MemberOf: []model.RoleID{pg("h")}, MemberOptions: map[model.RoleID]model.MembershipOptions{pg("h"): {Admin: &no}}},
	}}
	tests := []struct {
		opts      model.MembershipOptions
		name      string
		role      string
		want      string
		have      model.MembershipState
		superuser bool
		wantWarn  bool
	}{
		{
			name: "revoke admin from every grant and regrant declared dependents", role: "g", superuser: true,
			opts: model.MembershipOptions{Admin: &no}, have: model.MembershipState{Admin: true, Inherit: true, Set: true},
			want: `-- CASCADE: memberships in "g" that "u" granted to "d", "e" are revoked too; declared ones are granted again` + "\n" +
				`REVOKE ADMIN OPTION FOR "g" FROM "u" GRANTED BY "postgres" CASCADE` + "\n" +
				`-- CASCADE: memberships in "g" that "u" granted to "d", "e" are revoked too; declared ones are granted again` + "\n" +
				`REVOKE ADMIN OPTION FOR "g" FROM "u" GRANTED BY "other" CASCADE` + "\n" +
				`GRANT "g" TO "d" WITH INHERIT FALSE`,
		},
		{
			name: "inherit per grant", role: "g", superuser: true,
			opts: model.MembershipOptions{Inherit: &no, Set: &no}, have: model.MembershipState{Admin: true, Inherit: true, Set: true},
			want: `GRANT "g" TO "u" WITH INHERIT FALSE, SET FALSE GRANTED BY "postgres"` + "\n" + `GRANT "g" TO "u" WITH SET FALSE GRANTED BY "other"`,
		},
		{
			name: "non-superuser cannot change another grantor's grant", role: "g",
			opts: model.MembershipOptions{Set: &no}, have: model.MembershipState{Admin: true, Inherit: true, Set: true},
			want: `GRANT "g" TO "u" WITH SET FALSE GRANTED BY "postgres"`, wantWarn: true,
		},
		{
			name: "add admin carries inherit and set", role: "h", superuser: true,
			opts: model.MembershipOptions{Admin: &yes, Set: &yes}, have: model.MembershipState{Inherit: true, Set: true},
			want: `GRANT "h" TO "u" WITH ADMIN TRUE, SET TRUE`,
		},
		{
			name: "grant removed by its grantor's cascade is skipped", role: "h", superuser: true,
			opts: model.MembershipOptions{Inherit: &no}, have: model.MembershipState{Inherit: true, Set: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			st := &state{user: "postgres", version: 170000, superuser: tt.superuser, members: members, desired: desired}
			stmts, warns := st.alterMembership("u", tt.role, tt.opts, tt.have)
			if got := sqlOf(stmts); got != tt.want {
				t.Errorf("got\n%s\nwant\n%s", got, tt.want)
			}
			if (len(warns) > 0) != tt.wantWarn {
				t.Errorf("warnings = %v", warns)
			}
		})
	}
}

func TestRevokeMembershipRegrantsWithOptions(t *testing.T) {
	t.Parallel()
	yes := true
	st := &state{
		user: "postgres", version: 170000, superuser: true,
		members: []memberEntry{
			{role: "g", member: "u", grantor: "postgres", admin: true},
			{role: "g", member: "d", grantor: "u"},
		},
		desired: &model.Desired{Roles: []model.Role{
			{ID: pg("u"), MemberOf: []model.RoleID{}},
			{ID: pg("d"), MemberOf: []model.RoleID{pg("g")}, MemberOptions: map[model.RoleID]model.MembershipOptions{pg("g"): {Admin: &yes}}},
		}},
	}
	got := sqlOf(st.revokeMembership("u", "g"))
	if want := `GRANT "g" TO "d" WITH ADMIN OPTION`; !strings.HasSuffix(got, want) {
		t.Errorf("got\n%s\nwant suffix %s", got, want)
	}
}

func TestInheritOptionsSkipsDeclaredMembershipInherit(t *testing.T) {
	t.Parallel()
	no, yes := false, true
	st := &state{user: "postgres", version: 170000, superuser: true, members: []memberEntry{
		{role: "g1", member: "u", grantor: "postgres", inherit: true},
		{role: "g2", member: "u", grantor: "postgres", inherit: true},
	}}
	stmts, _ := st.inheritOptions(model.Role{
		ID: pg("u"), Inherit: &no, MemberOf: []model.RoleID{pg("g1"), pg("g2")},
		MemberOptions: map[model.RoleID]model.MembershipOptions{pg("g1"): {Inherit: &yes}},
	})
	if got, want := sqlOf(stmts), `GRANT "g2" TO "u" WITH INHERIT FALSE GRANTED BY "postgres"`; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestCheckMembershipOptions(t *testing.T) {
	t.Parallel()
	yes, no := true, false
	role := func(inherit *bool, opts model.MembershipOptions) *model.Desired {
		return &model.Desired{Roles: []model.Role{{
			ID: pg("u"), Inherit: inherit, MemberOf: []model.RoleID{pg("g")},
			MemberOptions: map[model.RoleID]model.MembershipOptions{pg("g"): opts},
		}}}
	}
	tests := []struct {
		desired *model.Desired
		name    string
		wantErr string
		warn    string
		version int
	}{
		{name: "admin before 16", desired: role(nil, model.MembershipOptions{Admin: &yes}), version: 150000},
		{name: "inherit before 16", desired: role(nil, model.MembershipOptions{Inherit: &yes}), version: 150000, wantErr: "need PostgreSQL 16 or later"},
		{name: "set before 16", desired: role(nil, model.MembershipOptions{Set: &no}), version: 140000, wantErr: "server_version_num 140000"},
		{name: "set on 16", desired: role(nil, model.MembershipOptions{Set: &no}), version: 160000},
		{name: "agreeing inherit", desired: role(&yes, model.MembershipOptions{Inherit: &yes}), version: 170000},
		{
			name: "disagreeing inherit", desired: role(&no, model.MembershipOptions{Inherit: &yes}), version: 170000,
			warn: `membership of "u" in "g" declares inherit = true, but the role has inherit = false`,
		},
	}
	for _, tt := range tests {
		warns, err := checkMembershipOptions(tt.desired, tt.version)
		switch {
		case tt.wantErr != "":
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("%s: err = %v, want %q", tt.name, err, tt.wantErr)
			}
		case err != nil:
			t.Errorf("%s: %v", tt.name, err)
		}
		if got := strings.Join(warns, "\n"); (tt.warn == "") != (got == "") || !strings.Contains(got, tt.warn) {
			t.Errorf("%s: warnings = %q, want %q", tt.name, got, tt.warn)
		}
	}
}
