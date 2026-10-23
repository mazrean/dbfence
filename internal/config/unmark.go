package config

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// unmarkedBody wraps an hcl.Body so that every attribute expression in it,
// and in its nested blocks, evaluates to a value without cty marks.
//
// Values derived from secrets carry funcs.Sensitive while they are being
// computed, which keeps function errors about them from quoting them.
// gohcl and gocty cannot decode marked values (they panic), so the marks
// are dropped once an attribute's value is complete.
type unmarkedBody struct{ hcl.Body }

func (b unmarkedBody) Content(schema *hcl.BodySchema) (*hcl.BodyContent, hcl.Diagnostics) {
	c, diags := b.Body.Content(schema)
	return unmarkContent(c), diags
}

func (b unmarkedBody) PartialContent(schema *hcl.BodySchema) (*hcl.BodyContent, hcl.Body, hcl.Diagnostics) {
	c, remain, diags := b.Body.PartialContent(schema)
	if remain != nil {
		remain = unmarkedBody{remain}
	}
	return unmarkContent(c), remain, diags
}

func (b unmarkedBody) JustAttributes() (hcl.Attributes, hcl.Diagnostics) {
	attrs, diags := b.Body.JustAttributes()
	return unmarkAttributes(attrs), diags
}

func unmarkContent(c *hcl.BodyContent) *hcl.BodyContent {
	if c == nil {
		return nil
	}
	out := *c
	out.Attributes = unmarkAttributes(c.Attributes)
	out.Blocks = make(hcl.Blocks, len(c.Blocks))
	for i, b := range c.Blocks {
		nb := *b
		nb.Body = unmarkedBody{b.Body}
		out.Blocks[i] = &nb
	}
	return &out
}

func unmarkAttributes(attrs hcl.Attributes) hcl.Attributes {
	if attrs == nil {
		return nil
	}
	out := make(hcl.Attributes, len(attrs))
	for name, a := range attrs {
		na := *a
		na.Expr = unmarkedExpr{a.Expr}
		out[name] = &na
	}
	return out
}

// unmarkedExpr evaluates to the value of its expression without marks.
type unmarkedExpr struct{ hcl.Expression }

func (e unmarkedExpr) Value(ctx *hcl.EvalContext) (cty.Value, hcl.Diagnostics) {
	v, diags := e.Expression.Value(ctx)
	v, _ = v.UnmarkDeep()
	return v, diags
}
