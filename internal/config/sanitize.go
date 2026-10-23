package config

import (
	"bytes"
	"net/url"
	"regexp"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/mazrean/dbfence/internal/secret"
	"github.com/zclconf/go-cty/cty"
)

// Diagnostics quote the source lines around an error, and an error can
// come before the values of password and dsn are known and registered
// (a parse error, or another attribute of the same block). The source
// shown in diagnostics is masked, and literal values are registered as
// soon as the files are parsed.

// secretAttrs are the attributes whose values are secret.
var secretAttrs = map[string]bool{"password": true, "dsn": true}

// secretAssign finds an assignment to a secret attribute on a line. It
// works on raw bytes, so it also finds them in files that do not parse.
var secretAssign = regexp.MustCompile(`(?:^|[^\w-])"?(?:password|dsn)"?[ \t]*=`)

// heredocStart is a heredoc introducer that ends the line.
var heredocStart = regexp.MustCompile(`^[ \t]*<<-?([A-Za-z_][\w-]*)[ \t]*\r?$`)

// maskSecrets returns a copy of src in which the value of every
// assignment to password or dsn, up to the end of its line, and the
// body of a heredoc it starts, are replaced by '*' byte for byte, so
// that diagnostic ranges keep pointing at the same columns.
func maskSecrets(src []byte) []byte {
	out := bytes.Clone(src)
	mask := func(b []byte) {
		for i, c := range b {
			if c != '\r' {
				b[i] = '*'
			}
		}
	}
	heredoc := ""
	for start := 0; start < len(out); {
		end := bytes.IndexByte(out[start:], '\n')
		if end < 0 {
			end = len(out)
		} else {
			end += start
		}
		line := out[start:end]
		switch {
		case heredoc != "":
			if string(bytes.TrimSpace(line)) == heredoc {
				heredoc = ""
			} else {
				mask(line)
			}
		default:
			if v := secretValue(line); v >= 0 {
				if m := heredocStart.FindSubmatch(line[v:]); m != nil {
					heredoc = string(m[1])
				}
				mask(line[v:])
			}
		}
		start = end + 1
	}
	return out
}

// secretValue returns the offset in line of the value of the first
// assignment to a secret attribute, or -1.
func secretValue(line []byte) int {
	for off := 0; off < len(line); {
		loc := secretAssign.FindIndex(line[off:])
		if loc == nil {
			return -1
		}
		v := off + loc[1]
		if v < len(line) && line[v] == '=' {
			// "==" compares; it does not assign.
			off = v + 1
			continue
		}
		return v
	}
	return -1
}

// maskedFiles returns copies of files whose source is masked by
// maskSecrets, for rendering diagnostics.
func maskedFiles(files map[string]*hcl.File) map[string]*hcl.File {
	out := make(map[string]*hcl.File, len(files))
	for name, f := range files {
		if f == nil {
			continue
		}
		c := *f
		c.Bytes = maskSecrets(f.Bytes)
		out[name] = &c
	}
	return out
}

// registerLiteralSecrets registers the literal parts of every password
// and dsn attribute of body and its nested blocks. It runs right after
// parsing, before anything can fail on the values.
func registerLiteralSecrets(body hcl.Body) {
	b, ok := body.(*hclsyntax.Body)
	if !ok || b == nil {
		return
	}
	for name, a := range b.Attributes {
		if !secretAttrs[name] {
			continue
		}
		parts := literalParts(a.Expr)
		if name == "dsn" {
			// Only a whole literal: the literal text around a lookup
			// is not secret, and redacting it would garble messages.
			if len(parts) != 1 || !isWholeLiteral(a.Expr) {
				continue
			}
			if u, err := url.Parse(parts[0]); err == nil && u.User != nil {
				if pw, ok := u.User.Password(); ok {
					secret.Register(pw)
				}
			}
		}
		for _, p := range parts {
			secret.Register(p)
		}
	}
	for _, blk := range b.Blocks {
		registerLiteralSecrets(blk.Body)
	}
}

// literalParts returns the literal strings of a string literal or a
// template. Function arguments are not included: they name secrets
// (environment variables, secret IDs) rather than hold them.
func literalParts(e hclsyntax.Expression) []string {
	switch e := e.(type) {
	case *hclsyntax.ParenthesesExpr:
		return literalParts(e.Expression)
	case *hclsyntax.LiteralValueExpr:
		if s, ok := stringValue(e.Val); ok {
			return []string{s}
		}
	case *hclsyntax.TemplateExpr:
		var out []string
		for _, p := range e.Parts {
			if lit, ok := p.(*hclsyntax.LiteralValueExpr); ok {
				if s, ok := stringValue(lit.Val); ok {
					out = append(out, s)
				}
			}
		}
		return out
	}
	return nil
}

// isWholeLiteral reports whether e is a string with no interpolation.
func isWholeLiteral(e hclsyntax.Expression) bool {
	switch e := e.(type) {
	case *hclsyntax.ParenthesesExpr:
		return isWholeLiteral(e.Expression)
	case *hclsyntax.LiteralValueExpr:
		return true
	case *hclsyntax.TemplateExpr:
		return e.IsStringLiteral()
	}
	return false
}

func stringValue(v cty.Value) (string, bool) {
	if v.IsNull() || !v.IsKnown() || !v.Type().Equals(cty.String) {
		return "", false
	}
	return v.AsString(), true
}
