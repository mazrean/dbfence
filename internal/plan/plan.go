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

// HasSecret reports whether s contains a Secret fragment.
func (s Statement) HasSecret() bool {
	return slices.ContainsFunc(s.parts, func(p any) bool {
		_, ok := p.(Secret)
		return ok
	})
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
	switch {
	case !p.Empty():
	case len(p.Warnings) == 0:
		sb.WriteString("-- No changes. The server matches the configuration.\n")
	default:
		// Warnings report drift that is not changed, or attributes that
		// were not compared, so the server is not known to match.
		fmt.Fprintf(&sb, "-- No changes to apply. See the %s above for differences that are not changed and items that were not compared.\n",
			Count(len(p.Warnings), "warning"))
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
	if !p.Empty() {
		p.summary(&sb)
	}
	_, err := io.WriteString(w, sb.String())
	return err
}

// summary writes the number of changes per action and lists the drops.
func (p *Plan) summary(sb *strings.Builder) {
	counts := map[Action]int{}
	var drops []string
	for _, c := range p.Changes {
		counts[c.Action]++
		if c.Action == ActionDrop {
			drops = append(drops, c.Resource)
		}
	}
	parts := []string{fmt.Sprintf("%d to create", counts[ActionCreate]), fmt.Sprintf("%d to change", counts[ActionUpdate])}
	if n := counts[ActionGrant]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d to grant", n))
	}
	if n := counts[ActionRevoke]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d to revoke", n))
	}
	parts = append(parts, fmt.Sprintf("%d to drop", counts[ActionDrop]))
	fmt.Fprintf(sb, "-- Plan: %s (%s).\n", strings.Join(parts, ", "), Count(len(p.Statements()), "statement"))
	if len(drops) > 0 {
		fmt.Fprintf(sb, "-- DESTRUCTIVE: this plan drops %s: %s\n", Count(len(drops), "object"), strings.Join(drops, ", "))
	}
}

// WriteWarnings writes one "warning:" line per warning, for stderr.
func (p *Plan) WriteWarnings(w io.Writer) error {
	var sb strings.Builder
	for _, warn := range p.Warnings {
		fmt.Fprintf(&sb, "warning: %s\n", warn)
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
