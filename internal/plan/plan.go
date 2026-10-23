// Package plan holds the ordered list of SQL statements that bring the
// live server to the desired state.
package plan

import (
	"fmt"
	"io"
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

// Redact replaces every secret of s found in text, so that server error
// messages quoting the statement do not leak them.
func (s Statement) Redact(text string) string {
	for _, p := range s.parts {
		sec, ok := p.(Secret)
		if !ok || sec == "" {
			continue
		}
		text = strings.ReplaceAll(text, string(sec), "'<redacted>'")
		// Also cover the value without its surrounding quotes.
		if inner := strings.Trim(string(sec), "'"); inner != "" {
			text = strings.ReplaceAll(text, inner, "<redacted>")
		}
	}
	return text
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
