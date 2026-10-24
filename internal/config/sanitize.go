package config

import (
	"bytes"
	"net/url"
	"regexp"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/mazrean/dbfence/internal/secret"
	"github.com/zclconf/go-cty/cty"
)

// Diagnostics quote the source lines around an error, and an error can
// come before the values of password are known and registered
// (a parse error, or another attribute of the same block). The source
// shown in diagnostics is masked, and literal values are registered as
// soon as the files are parsed.

// secretAttrs are the attributes whose values are secret.
var secretAttrs = map[string]bool{"password": true}

// secretAssign finds an assignment to a secret attribute on a line. It
// works on raw bytes, so it also finds them in files that do not parse.
var secretAssign = regexp.MustCompile(`(?:^|[^\w-])"?password"?[ \t]*=`)

// statementStart matches a line that visibly starts a new statement: an
// attribute assignment, a block header, or the '}' that closes a block.
var statementStart = regexp.MustCompile(`^[ \t]*(?:\}|"[^"]*"[ \t]*=(?:[^=]|$)|[A-Za-z_][\w-]*[ \t]*=(?:[^=]|$)|[A-Za-z_][\w-]*(?:[ \t]+(?:[A-Za-z_][\w-]*|"[^"]*"))*[ \t]*\{)`)

// heredocStart is a heredoc introducer that ends the line.
var heredocStart = regexp.MustCompile(`^<<-?([A-Za-z_][\w-]*)[ \t]*\r?$`)

// maskSecrets returns a copy of src in which the value of every
// assignment to password is replaced by '*' byte for byte, so
// that diagnostic ranges keep pointing at the same columns. The value
// is masked up to the end of its line and, while it has open brackets,
// heredocs or template interpolations, on the lines that follow: a
// multi-line expression such as format(\n"..."),
// trimspace(<<EOT\n...) or "a${\n x\n}b" is masked as a whole. A value
// that is never closed is masked to the end of the file.
//
// It fails closed: the lines after a value are masked as well until one
// visibly starts a new statement (see statementStart), so that a value
// written on the line after '=', or a quoted string broken across lines
// in error, is masked too.
func maskSecrets(src []byte) []byte {
	out := bytes.Clone(src)
	mask := func(b []byte) {
		for i, c := range b {
			if c != '\r' {
				b[i] = '*'
			}
		}
	}
	var sc valueScanner
	pending := false // the last value may go on onto the next lines
	for start := 0; start < len(out); {
		end := bytes.IndexByte(out[start:], '\n')
		if end < 0 {
			end = len(out)
		} else {
			end += start
		}
		line := out[start:end]
		switch {
		case sc.open():
			if !sc.scan(line) {
				mask(line)
			}
		case pending && !statementStart.Match(line):
			sc.scan(line)
			mask(line)
		default:
			pending = false
			if v := secretValue(line); v >= 0 {
				pending = true
				sc.scan(line[v:])
				mask(line[v:])
			}
		}
		start = end + 1
	}
	return out
}

// Kinds of valueScanner frames, besides the brackets '(', '[' and '{'.
const (
	frameString  = '"' // a quoted template
	frameInterp  = '$' // a ${ or %{ sequence of a template
	frameHeredoc = '<' // the body of a heredoc
	frameComment = '*' // a /* */ comment
)

type scanFrame struct {
	delim string // of a heredoc
	kind  byte
}

// valueScanner follows the nesting of an HCL expression across lines:
// brackets, quoted templates with their ${ and %{ sequences, and
// heredocs, and /* */ comments, which can span lines. Brackets in
// comments and in the literal text of templates are not counted.
type valueScanner struct{ stack []scanFrame }

// open reports whether the expression goes on past the scanned lines.
func (s *valueScanner) open() bool { return len(s.stack) > 0 }

func (s *valueScanner) top() byte {
	if len(s.stack) == 0 {
		return 0
	}
	return s.stack[len(s.stack)-1].kind
}

func (s *valueScanner) push(kind byte, delim string) {
	s.stack = append(s.stack, scanFrame{kind: kind, delim: delim})
}

// scan follows one line of the expression. It reports whether the line
// is the delimiter that ends a heredoc, which is not part of the value.
func (s *valueScanner) scan(line []byte) bool {
	if s.top() == frameHeredoc && string(bytes.TrimSpace(line)) == s.stack[len(s.stack)-1].delim {
		s.stack = s.stack[:len(s.stack)-1]
		return true
	}
	at := func(i int) byte {
		if i < len(line) {
			return line[i]
		}
		return 0
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch top := s.top(); top {
		case frameComment:
			if c == '*' && at(i+1) == '/' {
				s.stack = s.stack[:len(s.stack)-1]
				i++
			}
		case frameString, frameHeredoc:
			switch {
			case top == frameString && c == '\\':
				i++
			case (c == '$' || c == '%') && bytes.HasPrefix(line[i+1:], []byte{c, '{'}):
				// $${ and %%{ are literal text.
				i += len("${")
			case (c == '$' || c == '%') && at(i+1) == '{':
				s.push(frameInterp, "")
				i++
			case top == frameString && c == '"':
				s.stack = s.stack[:len(s.stack)-1]
			}
		default:
			switch {
			case c == '"':
				s.push(frameString, "")
			case c == '(' || c == '[' || c == '{':
				s.push(c, "")
			case c == ')' || c == ']' || c == '}':
				if s.open() {
					s.stack = s.stack[:len(s.stack)-1]
				}
			case c == '/' && at(i+1) == '*':
				s.push(frameComment, "")
				i++
			case c == '#' || c == '/' && at(i+1) == '/':
				// A comment ends the line.
				return false
			case c == '<':
				if m := heredocStart.FindSubmatch(line[i:]); m != nil {
					s.push(frameHeredoc, string(m[1]))
					return false
				}
			}
		}
	}
	// A quoted template cannot span lines: it ends, as an error, with
	// its line. Its interpolations can.
	if s.top() == frameString {
		s.stack = s.stack[:len(s.stack)-1]
	}
	return false
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
		if secretAssign.Match(f.Bytes) && !parses(name, f.Bytes) {
			// Where the syntax is broken, masking can only guess where a
			// value ends. Leave the file out: its diagnostics keep their
			// position and message but quote no source.
			continue
		}
		c := *f
		c.Bytes = maskSecrets(f.Bytes)
		out[name] = &c
	}
	return out
}

// parses reports whether src is syntactically valid HCL.
func parses(name string, src []byte) bool {
	_, diags := hclsyntax.ParseConfig(src, name, hcl.InitialPos)
	return !diags.HasErrors()
}

// registerLiteralSecrets registers the literal parts of every password
// attribute of body and its nested blocks. It runs right after
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
		for _, p := range literalParts(a.Expr) {
			secret.Register(p)
		}
	}
	for _, blk := range b.Blocks {
		registerLiteralSecrets(blk.Body)
	}
}

// registerStateURLPasswords registers the credentials of every literal
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
			for _, t := range templateTexts(call.Args[0]) {
				registerPieces(stateURLSecrets(t)...)
			}
		}
		return nil
	})
}

// hole stands for an interpolation in the texts of templateTexts.
const hole = "\x00"

// registerPieces registers the pieces of each of ss between holes, as
// written and percent-decoded.
func registerPieces(ss ...string) {
	for _, s := range ss {
		for p := range strings.SplitSeq(s, hole) {
			secret.Register(p)
			if d, err := url.PathUnescape(p); err == nil {
				secret.Register(d)
			}
		}
	}
}

// stateURLSecrets returns the parts of the state URL text s that the
// tfstate function does not print (see redactURL in internal/funcs):
// the whole userinfo, since a token may be passed as the username, the
// query string and each of its values, and the fragment. A local path
// has none.
func stateURLSecrets(s string) []string {
	if !strings.Contains(s, "://") {
		return nil
	}
	var out []string
	if info, ok := userinfo(s); ok {
		name, pw, _ := strings.Cut(info, ":")
		out = append(out, info, name, pw)
	}
	rest, frag, _ := strings.Cut(s, "#")
	out = append(out, frag)
	if _, query, ok := strings.Cut(rest, "?"); ok {
		out = append(out, query)
		for f := range strings.SplitSeq(query, "&") {
			_, v, _ := strings.Cut(f, "=")
			out = append(out, v)
		}
	}
	return out
}

// userinfo returns the userinfo of the URL s: the text before the last
// '@' of its authority.
func userinfo(s string) (string, bool) {
	_, rest, _ := strings.Cut(s, "://")
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	i := strings.LastIndex(rest, "@")
	if i < 0 {
		return "", false
	}
	return rest[:i], true
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
func literalParts(e hclsyntax.Expression) []string { return literals(e, false) }

// templateTexts returns the texts of the string literals and templates
// that literalParts finds in e, one for each template with its
// interpolations replaced by hole.
func templateTexts(e hclsyntax.Expression) []string { return literals(e, true) }

func literals(e hclsyntax.Expression, joined bool) []string {
	switch e := e.(type) {
	case *hclsyntax.ParenthesesExpr:
		return literals(e.Expression, joined)
	case *hclsyntax.LiteralValueExpr:
		if s, ok := stringValue(e.Val); ok {
			return []string{s}
		}
	case *hclsyntax.TemplateExpr:
		var out []string
		if joined {
			var sb strings.Builder
			for _, p := range e.Parts {
				if l, ok := p.(*hclsyntax.LiteralValueExpr); ok {
					if s, ok := stringValue(l.Val); ok {
						sb.WriteString(s)
						continue
					}
				}
				sb.WriteString(hole)
			}
			out = append(out, sb.String())
		}
		// The literals inside interpolations, such as format(...).
		for _, p := range e.Parts {
			if _, ok := p.(*hclsyntax.LiteralValueExpr); !ok || !joined {
				out = append(out, literals(p, joined)...)
			}
		}
		return out
	case *hclsyntax.TemplateWrapExpr:
		return literals(e.Wrapped, joined)
	case *hclsyntax.TupleConsExpr:
		var out []string
		for _, x := range e.Exprs {
			out = append(out, literals(x, joined)...)
		}
		return out
	case *hclsyntax.IndexExpr:
		return literals(e.Collection, joined)
	case *hclsyntax.RelativeTraversalExpr:
		return literals(e.Source, joined)
	case *hclsyntax.ConditionalExpr:
		return append(literals(e.TrueResult, joined), literals(e.FalseResult, joined)...)
	case *hclsyntax.FunctionCallExpr:
		if lookupFuncs[e.Name] {
			return nil
		}
		var out []string
		for _, x := range e.Args {
			out = append(out, literals(x, joined)...)
		}
		return out
	}
	return nil
}

func stringValue(v cty.Value) (string, bool) {
	if v.IsNull() || !v.IsKnown() || !v.Type().Equals(cty.String) {
		return "", false
	}
	return v.AsString(), true
}
