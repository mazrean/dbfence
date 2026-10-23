// Package plan holds the ordered list of SQL statements that bring the
// live server to the desired state.
package plan

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/mazrean/dbfence/internal/model"
)

// Statement is a single SQL statement executed on Database ("" means the
// connection given in configuration). A Statement is always exactly one
// SQL command: drivers send it so that the server rejects a second one.
// Its text is built only from Fragments.
type Statement struct {
	role RoleChange
	// Database is the database the statement runs on.
	Database string
	// AsRole, when set, is the role the statement runs as. The driver
	// switches to it for this statement only, so the SQL never chains a
	// SET ROLE in front of the statement.
	AsRole string
	kind   Kind
	parts  []Fragment
	notes  []string
	// defaults are the roles a SET DEFAULT ROLE statement makes the
	// default roles of its target; empty for SET DEFAULT ROLE NONE.
	defaults []model.RoleID
	target   Target
}

// New builds a statement of kind on target from SQL fragments. Dialect
// builders use it, so that every planned statement says what it does.
func New(database string, kind Kind, target Target, parts ...Fragment) Statement {
	return Statement{Database: database, kind: kind, target: target, parts: parts}
}

// SQL builds a statement of KindOther from SQL fragments.
func SQL(database string, parts ...Fragment) Statement {
	return New(database, KindOther, Target{}, parts...)
}

// Kind returns what s does.
func (s Statement) Kind() Kind { return s.kind }

// Target returns the object s acts on.
func (s Statement) Target() Target { return s.target }

// RoleChange returns what s sets on the role it creates or alters.
func (s Statement) RoleChange() RoleChange { return s.role }

// WithRoleChange returns s with the role attributes it sets.
func (s Statement) WithRoleChange(c RoleChange) Statement {
	s.role = c
	return s
}

// DefaultRoles returns the roles a statement of KindSetDefaultRole makes
// the default roles of its target role. They replace all current default
// roles, so an empty result means none.
func (s Statement) DefaultRoles() []model.RoleID { return slices.Clone(s.defaults) }

// WithDefaultRoles returns s with the default roles it sets (see
// DefaultRoles).
func (s Statement) WithDefaultRoles(roles []model.RoleID) Statement {
	s.defaults = slices.Clone(roles)
	return s
}

// WithNote returns s with note in front of its other notes. Notes explain
// the statement in plan and apply output, such as a CASCADE; they are
// never part of the SQL sent to the server.
func (s Statement) WithNote(note string) Statement {
	s.notes = append([]string{note}, s.notes...)
	return s
}

// WithRole returns s run as role (see AsRole).
func (s Statement) WithRole(role string) Statement {
	s.AsRole = role
	return s
}

// Where describes where s runs, such as `on database "app", as role
// "ro"`, or returns "" for the configured connection and user. Names are
// Go-quoted, so control characters in them are escaped.
func (s Statement) Where() string {
	var parts []string
	if s.Database != "" {
		parts = append(parts, fmt.Sprintf("on database %q", s.Database))
	}
	if s.AsRole != "" {
		parts = append(parts, fmt.Sprintf("as role %q", s.AsRole))
	}
	return strings.Join(parts, ", ")
}

// Notes returns the notes explaining s, in display order.
func (s Statement) Notes() []string { return slices.Clone(s.notes) }

// SQL returns the executable text.
func (s Statement) SQL() string { return s.render(true) }

// Display returns the text for output: secrets are redacted unless
// showSecrets is set, and control characters are escaped (see Escape).
func (s Statement) Display(showSecrets bool) string { return Escape(s.render(showSecrets)) }

func (s Statement) render(showSecrets bool) string {
	var sb strings.Builder
	Seq(s.parts).render(&sb, showSecrets)
	return sb.String()
}

// HasSecret reports whether s contains a Secret fragment.
func (s Statement) HasSecret() bool { return hasSecret(Seq(s.parts)) }

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
		fmt.Fprintf(&sb, "-- warning: %s\n", Escape(warn))
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
		fmt.Fprintf(&sb, "-- [%s] %s\n", c.Action, Escape(c.Resource))
		for _, s := range c.Statements {
			if c := s.Where(); c != "" {
				fmt.Fprintf(&sb, "-- (%s)\n", c)
			}
			for _, n := range s.notes {
				fmt.Fprintf(&sb, "-- %s\n", Escape(n))
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
			drops = append(drops, Escape(c.Resource))
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
		fmt.Fprintf(&sb, "warning: %s\n", Escape(warn))
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

// Escape returns s with control characters, including line breaks, and
// bidirectional formatting characters written as Go escapes (\x1b, \n,
// \u202e). Names read from the server may contain them; escaped, they
// cannot redraw the terminal or forge lines of output.
func Escape(s string) string { return escape(s, false) }

// EscapeLines is Escape that keeps line breaks and tabs, for multi-line
// messages such as configuration diagnostics.
func EscapeLines(s string) string { return escape(s, true) }

func escape(s string, keepLines bool) string {
	unsafe := func(r rune) bool {
		if keepLines && (r == '\n' || r == '\t') {
			return false
		}
		return unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r)
	}
	if !strings.ContainsFunc(s, unsafe) {
		return s
	}
	var sb strings.Builder
	for _, r := range s {
		if !unsafe(r) {
			sb.WriteRune(r)
			continue
		}
		q := strconv.QuoteRune(r)
		sb.WriteString(q[1 : len(q)-1])
	}
	return sb.String()
}
