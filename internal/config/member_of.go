package config

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

// memberOfEntry is one member_of element: a role id, or an object naming
// the role and the membership options to manage.
type memberOfEntry struct {
	opts model.MembershipOptions
	role string
}

// memberOfOptions lists the attributes of the object form.
var memberOfOptions = []string{"role", "admin", "inherit", "set"}

// decodeMemberOf evaluates member_of. It returns nil when the attribute
// is absent or null, which leaves memberships unmanaged.
func decodeMemberOf(expr hcl.Expression, ctx *hcl.EvalContext, engine model.Engine) ([]memberOfEntry, bool, hcl.Diagnostics) {
	v, diags := expr.Value(ctx)
	if diags.HasErrors() {
		return nil, false, diags
	}
	rng := expr.Range()
	invalid := func(detail string) hcl.Diagnostics {
		return append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError, Summary: "Invalid member_of", Detail: detail,
			Subject: rng.Ptr(), Expression: expr, EvalContext: ctx,
		})
	}
	switch {
	case v.IsNull():
		return nil, false, diags
	case !v.IsWhollyKnown():
		// Same wording as gohcl, so that dropCascades hides it behind
		// the diagnostic of the reference that failed.
		return nil, false, append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError, Summary: "Unsuitable value type", Detail: "Unsuitable value: value must be known",
			Subject: rng.Ptr(), Context: rng.Ptr(),
		})
	case !v.Type().IsListType() && !v.Type().IsTupleType() && !v.Type().IsSetType():
		return nil, false, invalid("member_of must be a list of role ids or { role = ..., admin = ..., inherit = ..., set = ... } objects.")
	}
	entries := []memberOfEntry{}
	for it := v.ElementIterator(); it.Next(); {
		_, el := it.Element()
		e, detail := memberOfElement(el, engine)
		if detail != "" {
			diags = invalid(detail)
			continue
		}
		entries = append(entries, e)
	}
	return entries, true, diags
}

// memberOfElement decodes one element, or explains why it is invalid.
func memberOfElement(el cty.Value, engine model.Engine) (memberOfEntry, string) {
	if el.IsNull() {
		return memberOfEntry{}, "member_of entries must not be null."
	}
	if !el.Type().IsObjectType() && !el.Type().IsMapType() {
		s, err := convert.Convert(el, cty.String)
		if err != nil {
			return memberOfEntry{}, fmt.Sprintf("member_of entries must be role ids (strings) or objects, got %s.", el.Type().FriendlyName())
		}
		return memberOfEntry{role: s.AsString()}, ""
	}
	attrs := el.AsValueMap()
	var e memberOfEntry
	for _, name := range slices.Sorted(maps.Keys(attrs)) {
		if !slices.Contains(memberOfOptions, name) {
			return e, fmt.Sprintf("member_of object has unsupported attribute %q; expected %s.", name, strings.Join(memberOfOptions, ", "))
		}
	}
	raw, ok := attrs["role"]
	if !ok || raw.IsNull() {
		return e, `member_of object must set role to a role id, e.g. { role = role.app.id, admin = true }.`
	}
	role, err := convert.Convert(raw, cty.String)
	if err != nil {
		return e, `member_of object must set role to a role id, e.g. { role = role.app.id, admin = true }.`
	}
	e.role = role.AsString()
	for _, o := range []struct {
		dst  **bool
		name string
	}{{&e.opts.Admin, "admin"}, {&e.opts.Inherit, "inherit"}, {&e.opts.Set, "set"}} {
		raw, ok := attrs[o.name]
		if !ok || raw.IsNull() {
			continue
		}
		b, err := convert.Convert(raw, cty.Bool)
		if err != nil {
			return e, fmt.Sprintf("member_of option %s of role %q must be a bool.", o.name, e.role)
		}
		*o.dst = new(b.True())
		if engine == model.EngineMySQL && o.name != "admin" {
			return e, fmt.Sprintf("member_of option %s of role %q is only supported for postgres (PostgreSQL 16 or later); MySQL memberships only have admin.", o.name, e.role)
		}
	}
	return e, ""
}
