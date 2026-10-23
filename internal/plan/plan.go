// Package plan holds the ordered list of SQL statements that bring the
// live server to the desired state.
package plan

import (
	"fmt"
	"io"
	"slices"
	"strings"
)

// Secret is a SQL fragment that must be redacted in output.
type Secret string

// Statement is a single SQL statement executed on Database ("" means the
// connection given in configuration).
type Statement struct {
	Database string
	parts    []any
}

// SQL builds a statement from string and Secret fragments.
func SQL(database string, parts ...any) Statement {
	for _, p := range parts {
		switch p.(type) {
		case string, Secret:
		default:
			panic(fmt.Sprintf("plan.SQL: unsupported fragment %T", p))
		}
	}
	return Statement{Database: database, parts: parts}
}

// SQL returns the executable text.
func (s Statement) SQL() string { return s.render(true) }

// Display returns the text with secrets redacted unless showSecrets is set.
func (s Statement) Display(showSecrets bool) string { return s.render(showSecrets) }

func (s Statement) render(showSecrets bool) string {
	var sb strings.Builder
	for _, p := range s.parts {
		switch p := p.(type) {
		case string:
			sb.WriteString(p)
		case Secret:
			if showSecrets {
				sb.WriteString(string(p))
			} else {
				sb.WriteString("'<redacted>'")
			}
		}
	}
	return sb.String()
}

// minRedactPrefix is the shortest truncated secret prefix that Redact
// removes; shorter fragments are too likely to match unrelated text.
const minRedactPrefix = 4

// Redact removes the secrets of s from text, so that server error messages
// quoting the statement do not leak them. Only literal contexts are
// considered: a secret, or a prefix of at least minRedactPrefix bytes of
// it, that starts right after a single quote and ends at a single quote or
// at the end of text. This covers the full literal, its unescaped value
// inside quotes, and fragments truncated by the server (MySQL cuts the
// "near '...'" part of syntax errors at 80 characters), without rewriting
// unrelated text that merely contains a short password.
func (s Statement) Redact(text string) string {
	for _, p := range s.parts {
		sec, ok := p.(Secret)
		if !ok {
			continue
		}
		for _, v := range secretValues(string(sec)) {
			text = redactValue(text, v)
		}
	}
	return text
}

// secretValues returns the forms in which the value of the literal sec may
// be echoed between single quotes: escaped as written and unescaped.
func secretValues(sec string) []string {
	inner := strings.TrimSuffix(strings.TrimPrefix(sec, "'"), "'")
	if inner == "" {
		return nil
	}
	quotes := strings.ReplaceAll(inner, "''", "'")
	backslash := strings.NewReplacer(`\\`, `\`, `\'`, "'").Replace(quotes)
	out := []string{inner}
	for _, v := range []string{quotes, backslash} {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	// Longest first, so a longer form is not cut short by a shorter one.
	slices.SortStableFunc(out, func(a, b string) int { return len(b) - len(a) })
	return out
}

// redactValue replaces v, or a prefix of it of at least minRedactPrefix
// bytes, when it starts after a single quote and ends at a single quote or
// at the end of text.
func redactValue(text, v string) string {
	const marker = "<redacted>"
	var sb strings.Builder
	last := 0
	for i := 0; i < len(text); i++ {
		if text[i] != '\'' {
			continue
		}
		start := i + 1
		k := literalMatchLen(text[start:], v)
		if k == 0 {
			continue
		}
		end := start + k
		sb.WriteString(text[last:start])
		sb.WriteString(marker)
		last = end
		i = end - 1
	}
	if last == 0 {
		return text
	}
	sb.WriteString(text[last:])
	return sb.String()
}

// literalMatchLen returns the length of the longest prefix of rest that is
// v or a prefix of v of at least minRedactPrefix bytes and that is followed
// by a single quote or the end of rest, or 0 when there is none.
func literalMatchLen(rest, v string) int {
	n := min(len(rest), len(v))
	k := 0
	for k < n && rest[k] == v[k] {
		k++
	}
	for ; k > 0; k-- {
		if k < len(v) && k < minRedactPrefix {
			return 0
		}
		if k == len(rest) || rest[k] == '\'' {
			return k
		}
	}
	return 0
}

// Action is the kind of a change.
type Action string

const (
	ActionCreate Action = "create"
	ActionUpdate Action = "update"
	ActionDrop   Action = "drop"
	ActionGrant  Action = "grant"
	ActionRevoke Action = "revoke"
)

// Change is a set of statements for one resource.
type Change struct {
	Action     Action
	Resource   string
	Statements []Statement
}

// Plan is the ordered result of a diff.
type Plan struct {
	Changes  []Change
	Warnings []string
}

// Empty reports whether there is nothing to execute.
func (p *Plan) Empty() bool { return len(p.Changes) == 0 }

// Statements flattens all changes in execution order.
func (p *Plan) Statements() []Statement {
	var out []Statement
	for _, c := range p.Changes {
		out = append(out, c.Statements...)
	}
	return out
}

// Render writes the plan as annotated SQL.
func (p *Plan) Render(w io.Writer, showSecrets bool) error {
	var sb strings.Builder
	for _, warn := range p.Warnings {
		fmt.Fprintf(&sb, "-- warning: %s\n", warn)
	}
	if len(p.Warnings) > 0 {
		sb.WriteString("\n")
	}
	if p.Empty() {
		sb.WriteString("-- No changes. The server matches the configuration.\n")
	}
	for _, c := range p.Changes {
		fmt.Fprintf(&sb, "-- [%s] %s\n", c.Action, c.Resource)
		for _, s := range c.Statements {
			if s.Database != "" {
				fmt.Fprintf(&sb, "-- (on database %q)\n", s.Database)
			}
			sb.WriteString(s.Display(showSecrets))
			sb.WriteString(";\n")
		}
		sb.WriteString("\n")
	}
	_, err := io.WriteString(w, sb.String())
	return err
}

// Count formats n with noun, adding "s" unless n is 1 ("1 statement",
// "2 statements").
func Count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
