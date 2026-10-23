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
	set    map[string]struct{}
	sorted []string // set, longest first; nil when stale
	mu     sync.Mutex
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{set: map[string]struct{}{}}
}

var defaultRegistry = NewRegistry()

// Default returns the process-wide Registry that the secret sources
// register into and the output streams redact.
func Default() *Registry { return defaultRegistry }

// Register adds s to the default Registry.
func Register(s string) { defaultRegistry.Add(s) }

// Add registers s. Values shorter than MinLength are ignored.
func (r *Registry) Add(s string) {
	if len(s) < MinLength {
		return
	}
	vs := Variants(s)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range vs {
		if _, ok := r.set[v]; !ok {
			r.set[v] = struct{}{}
			r.sorted = nil
		}
	}
}

// Variants returns the forms of s that are redacted: s itself and its
// NFC normalization, each URL-encoded (query, path, and with spaces as
// %20), base64-encoded (standard and URL alphabets, padded and raw),
// JSON-escaped, Go-quoted, SQL-literal-escaped (quotes doubled), and
// with control characters escaped as in plan output. A form spanning
// lines is also split into its lines, because output is redacted line
// by line. Forms shorter than MinLength are dropped.
func Variants(s string) []string {
	bases := []string{s}
	if n := norm.NFC.String(s); n != s {
		bases = append(bases, n)
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(v string) {
		for _, piece := range append(strings.Split(v, "\n"), v) {
			if _, ok := seen[piece]; ok || len(piece) < MinLength {
				continue
			}
			seen[piece] = struct{}{}
			out = append(out, piece)
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
		add(plan.Escape(b))
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

// snapshot returns the registered forms, longest first.
func (r *Registry) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sorted == nil && len(r.set) > 0 {
		r.sorted = make([]string, 0, len(r.set))
		for v := range r.set {
			r.sorted = append(r.sorted, v)
		}
		slices.SortFunc(r.sorted, func(a, b string) int {
			if d := len(b) - len(a); d != 0 {
				return d
			}
			return strings.Compare(a, b)
		})
	}
	return r.sorted
}

// Redact returns s with every occurrence of a registered form replaced
// by Placeholder. Overlapping and adjacent occurrences, of the same or of
// different secrets, are replaced together, so no part of any occurrence
// remains.
func (r *Registry) Redact(s string) string {
	forms := r.snapshot()
	if len(forms) == 0 || len(s) < MinLength {
		return s
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
	if len(spans) == 0 {
		return s
	}
	slices.SortFunc(spans, func(a, b [2]int) int { return a[0] - b[0] })
	var sb strings.Builder
	pos := 0
	for k := 0; k < len(spans); {
		start, end := spans[k][0], spans[k][1]
		for k++; k < len(spans) && spans[k][0] <= end; k++ {
			end = max(end, spans[k][1])
		}
		sb.WriteString(s[pos:start])
		sb.WriteString(Placeholder)
		pos = end
	}
	sb.WriteString(s[pos:])
	return sb.String()
}
