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
var heredocStart = regexp.MustCompile(`<<-?([A-Za-z_][\w-]*)[ \t]*\r?$`)

// maskSecrets returns a copy of src in which the value of every
// assignment to password or dsn is replaced by '*' byte for byte, so
// that diagnostic ranges keep pointing at the same columns. The value
// is masked up to the end of its line and, while it has open brackets
// or heredocs, on the lines that follow: a multi-line expression such as
// format(\n"...") or trimspace(<<EOT\n...) is masked as a whole. A
// value with an unclosed bracket is masked to the end of the file.
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
	depth := 0
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
		case depth > 0:
			depth, heredoc = scanValue(line, depth)
			mask(line)
		default:
			if v := secretValue(line); v >= 0 {
				depth, heredoc = scanValue(line[v:], 0)
				mask(line[v:])
			}
		}
		start = end + 1
	}
	return out
}

// scanValue returns the bracket depth after the expression text of one
// line, starting at depth, and the delimiter of a heredoc that the line
// introduces. Brackets inside quoted strings are not counted.
func scanValue(line []byte, depth int) (int, string) {
	inString := false
	code := make([]byte, 0, len(line))
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case inString && c == '\\':
			i++
			continue
		case c == '"':
			inString = !inString
		case inString:
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth = max(depth-1, 0)
		case c == '#' || c == '/' && i+1 < len(line) && line[i+1] == '/':
			// A comment ends the line.
			i = len(line)
			continue
		}
		if !inString {
			code = append(code, c)
		}
	}
	if m := heredocStart.FindSubmatch(code); m != nil && !inString {
		return depth, string(m[1])
	}
	return depth, ""
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
			for _, p := range parts {
				registerURLPassword(p)
			}
			// Only a whole literal: the literal text around a lookup
			// is not secret, and redacting it would garble messages.
			if len(parts) != 1 || !isWholeLiteral(a.Expr) {
				continue
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

// registerStateURLPasswords registers the password of every literal
// state URL passed to tfstate anywhere in body, such as
// https://user:token@host/x.tfstate, since a diagnostic on the line of
// the call quotes it whichever attribute it is on.
func registerStateURLPasswords(body hcl.Body) {
	b, ok := body.(*hclsyntax.Body)
	if !ok || b == nil {
		return
	}
	_ = hclsyntax.VisitAll(b, func(n hclsyntax.Node) hcl.Diagnostics {
		if call, ok := n.(*hclsyntax.FunctionCallExpr); ok && call.Name == "tfstate" && len(call.Args) > 0 {
			for _, p := range literalParts(call.Args[0]) {
				registerURLPassword(p)
			}
		}
		return nil
	})
}

// registerURLPassword registers the password of s if s is a URL with
// one.
func registerURLPassword(s string) {
	if u, err := url.Parse(s); err == nil && u.User != nil {
		if pw, ok := u.User.Password(); ok {
			secret.Register(pw)
		}
	}
}

// lookupFuncs are the functions whose arguments name a value (an
// environment variable, a secret ID, a state address) rather than hold
// it. Their arguments are not registered, so that a message naming the
// variable or the secret stays readable.
var lookupFuncs = map[string]bool{
	"env": true, "secretenv": true, "aws_secretsmanager": true, "gcp_secretmanager": true, "tfstate": true,
}

// literalParts returns the literal strings of an expression: of string
// literals and templates, also inside lists, indexes, conditionals and
// the arguments of functions such as format and trimspace. The
// arguments of lookupFuncs are not included.
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
			out = append(out, literalParts(p)...)
		}
		return out
	case *hclsyntax.TemplateWrapExpr:
		return literalParts(e.Wrapped)
	case *hclsyntax.TupleConsExpr:
		var out []string
		for _, x := range e.Exprs {
			out = append(out, literalParts(x)...)
		}
		return out
	case *hclsyntax.IndexExpr:
		return literalParts(e.Collection)
	case *hclsyntax.RelativeTraversalExpr:
		return literalParts(e.Source)
	case *hclsyntax.ConditionalExpr:
		return append(literalParts(e.TrueResult), literalParts(e.FalseResult)...)
	case *hclsyntax.FunctionCallExpr:
		if lookupFuncs[e.Name] {
			return nil
		}
		var out []string
		for _, x := range e.Args {
			out = append(out, literalParts(x)...)
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
