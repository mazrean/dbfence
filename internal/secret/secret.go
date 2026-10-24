// Package secret keeps the secret values dbfence has seen and redacts
// them from program output. It is the last line of defense: SQL output
// already prints passwords as '<redacted>', and errors do not quote
// secret values, but any text that still contains one is caught by the
// output Writer.
package secret

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/mazrean/dbfence/internal/plan"
	"golang.org/x/text/unicode/norm"
)

// MinLength is the shortest secret, in bytes, that is redacted. Shorter
// values would match ordinary words and numbers of the output.
const MinLength = 4

// Placeholder replaces every secret in output.
const Placeholder = "<redacted>"

// Registry is a set of secret values, each kept in every form in which
// it may be printed. It is safe for concurrent use.
type Registry struct {
	secrets map[string][]string // secret -> its forms
	public  map[string]struct{} // lower-cased values printed by design
	sorted  []string            // forms, longest first; nil when stale
	lines   [][]string          // forms that span lines, split into their lines
	mu      sync.Mutex
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{secrets: map[string][]string{}, public: map[string]struct{}{}}
}

var defaultRegistry = NewRegistry()

// Default returns the process-wide Registry that the secret sources
// register into and the output streams redact.
func Default() *Registry { return defaultRegistry }

// Register adds s to the default Registry.
func Register(s string) { defaultRegistry.Add(s) }

// RegisterPublic adds s to the public values of the default Registry.
func RegisterPublic(s string) { defaultRegistry.AddPublic(s) }

// Add registers s. Values shorter than MinLength are ignored.
func (r *Registry) Add(s string) {
	if len(s) < MinLength {
		return
	}
	r.mu.Lock()
	_, ok := r.secrets[s]
	r.mu.Unlock()
	if ok {
		return
	}
	vs := Variants(s)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.secrets[s] = vs
	r.sorted = nil
}

// AddPublic records s as a value dbfence prints by design: an engine
// name, or the user and database of the connection. A secret equal to a
// public value (ignoring case), such as the password of the default
// postgres:postgres account, is not redacted: it is shown as that name
// anyway, and redacting it would hide every occurrence of the name.
func (r *Registry) AddPublic(s string) {
	if s == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.public[strings.ToLower(s)] = struct{}{}
	r.sorted = nil
}

// Variants returns the forms of s that are redacted: s itself and its
// NFC normalization, each URL-encoded (query, path, and with spaces as
// %20), base64-encoded (standard and URL alphabets, padded and raw),
// JSON-escaped, Go-quoted, and SQL-literal-escaped (quotes doubled, and
// also with backslashes doubled as in MySQL and PostgreSQL E'' literals).
// The output Writer escapes control characters before it redacts, so
// every form is also kept with control characters escaped as by
// plan.EscapeLines and plan.Escape. A form spanning lines is also kept
// without its leading and trailing line breaks, and split into its
// lines, so that a single line of it printed alone is found too. Forms
// shorter than MinLength are dropped.
func Variants(s string) []string {
	bases := []string{s}
	if n := norm.NFC.String(s); n != s {
		bases = append(bases, n)
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(v string) {
		for _, form := range []string{v, plan.EscapeLines(v), plan.Escape(v)} {
			for _, piece := range append(strings.Split(form, "\n"), form, strings.Trim(form, "\n")) {
				if _, ok := seen[piece]; ok || len(piece) < MinLength {
					continue
				}
				seen[piece] = struct{}{}
				out = append(out, piece)
			}
		}
	}
	for _, b := range bases {
		add(b)
		add(url.QueryEscape(b))
		add(url.PathEscape(b))
		add(strings.ReplaceAll(url.QueryEscape(b), "+", "%20"))
		add(base64.StdEncoding.EncodeToString([]byte(b)))
		add(base64.URLEncoding.EncodeToString([]byte(b)))
		add(base64.RawStdEncoding.EncodeToString([]byte(b)))
		add(base64.RawURLEncoding.EncodeToString([]byte(b)))
		add(jsonEscape(b, true))
		add(jsonEscape(b, false))
		add(unquote(strconv.Quote(b)))
		add(strings.ReplaceAll(b, "'", "''"))
		add(strings.ReplaceAll(strings.ReplaceAll(b, `\`, `\\`), "'", "''"))
		// Quoted identifiers: PostgreSQL doubles '"', MySQL doubles '`'.
		add(strings.ReplaceAll(b, `"`, `""`))
		add(strings.ReplaceAll(b, "`", "``"))
	}
	return out
}

// jsonEscape returns s as the contents of a JSON string.
func jsonEscape(s string, escapeHTML bool) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(escapeHTML)
	if err := enc.Encode(s); err != nil {
		return s
	}
	return unquote(strings.TrimSuffix(buf.String(), "\n"))
}

// unquote drops the surrounding quotes of a quoted string.
func unquote(q string) string {
	if len(q) < len(`""`) {
		return q
	}
	return q[1 : len(q)-1]
}

// snapshot returns the registered forms, longest first, and those that
// span lines (without leading and trailing line breaks) split into their
// lines.
func (r *Registry) snapshot() ([]string, [][]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sorted == nil && len(r.secrets) > 0 {
		set := map[string]struct{}{}
		for s, forms := range r.secrets {
			if _, ok := r.public[strings.ToLower(s)]; ok {
				continue
			}
			for _, f := range forms {
				set[f] = struct{}{}
			}
		}
		r.sorted = make([]string, 0, len(set))
		r.lines = nil
		for v := range set {
			r.sorted = append(r.sorted, v)
			if strings.Contains(v, "\n") && strings.Trim(v, "\n") == v {
				r.lines = append(r.lines, strings.Split(v, "\n"))
			}
		}
		slices.SortFunc(r.sorted, func(a, b string) int {
			if d := len(b) - len(a); d != 0 {
				return d
			}
			return strings.Compare(a, b)
		})
	}
	return r.sorted, r.lines
}

// Redact returns s with every occurrence of a registered form replaced
// by Placeholder. Overlapping and adjacent occurrences, of the same or of
// different secrets, are replaced together, so no part of any occurrence
// remains.
func (r *Registry) Redact(s string) string {
	return replaceSpans(s, r.spans(s))
}

// spans returns the merged byte ranges of s that hold registered forms,
// in order.
func (r *Registry) spans(s string) [][2]int {
	forms, _ := r.snapshot()
	if len(forms) == 0 || len(s) < MinLength {
		return nil
	}
	var spans [][2]int
	for _, f := range forms {
		for i := 0; i+len(f) <= len(s); {
			j := strings.Index(s[i:], f)
			if j < 0 {
				break
			}
			start := i + j
			spans = append(spans, [2]int{start, start + len(f)})
			i = start + 1
		}
	}
	slices.SortFunc(spans, func(a, b [2]int) int { return a[0] - b[0] })
	var merged [][2]int
	for _, sp := range spans {
		if n := len(merged); n > 0 && sp[0] <= merged[n-1][1] {
			merged[n-1][1] = max(merged[n-1][1], sp[1])
			continue
		}
		merged = append(merged, sp)
	}
	return merged
}

// replaceSpans returns s with each of the ordered, disjoint spans
// replaced by Placeholder.
func replaceSpans(s string, spans [][2]int) string {
	if len(spans) == 0 {
		return s
	}
	var sb strings.Builder
	pos := 0
	for _, sp := range spans {
		sb.WriteString(s[pos:sp[0]])
		sb.WriteString(Placeholder)
		pos = sp[1]
	}
	sb.WriteString(s[pos:])
	return sb.String()
}

// openFrom returns the index of the first of lines (complete lines
// without their line breaks) from which the lines to the end are the
// beginning of a registered form spanning lines that has more lines to
// come, or -1. Output from there on may be the beginning of a secret.
func (r *Registry) openFrom(lines []string) int {
	_, forms := r.snapshot()
	first := -1
	for _, f := range forms {
		for s := max(0, len(lines)-(len(f)-1)); s < len(lines); s++ {
			if first >= 0 && s >= first {
				break
			}
			if !strings.HasSuffix(lines[s], f[0]) {
				continue
			}
			if slices.Equal(lines[s+1:], f[1:len(lines)-s]) {
				first = s
				break
			}
		}
	}
	return first
}
