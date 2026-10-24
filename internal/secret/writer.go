package secret

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"sync"

	"github.com/mazrean/dbfence/internal/plan"
)

// Writer is an output stream that escapes control characters (keeping
// line breaks and tabs, see plan.EscapeLines) and redacts the secrets of
// a Registry. It buffers the current line, so that a secret split across
// Write calls is still found, and writes each line once it is complete,
// unless the line may be the beginning of a secret that spans lines: such
// lines are held back until the lines that follow show whether they are.
// Flush writes the held lines and a pending partial line, such as a
// prompt.
type Writer struct {
	w      io.Writer
	reg    *Registry
	buf    []byte
	held   []string // escaped complete lines that may begin a secret
	mu     sync.Mutex
	reveal bool
}

// NewWriter returns a Writer redacting the secrets of reg into w.
func NewWriter(w io.Writer, reg *Registry) *Writer {
	return &Writer{w: w, reg: reg}
}

// ShowSecrets turns redaction off (--show-secrets) or back on. Control
// characters are escaped either way.
func (w *Writer) ShowSecrets(show bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.reveal = show
}

// Write implements io.Writer. It reports len(p) once p is buffered or
// written.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	i := bytes.LastIndexByte(w.buf, '\n')
	if i < 0 {
		return len(p), nil
	}
	lines := w.buf[:i+1]
	rest := w.buf[i+1:]
	err := w.emit(lines, false)
	w.buf = append(w.buf[:0:0], rest...)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Flush writes the held lines and the buffered partial line.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	err := w.emit(w.buf, true)
	w.buf = w.buf[:0]
	return err
}

// emit escapes and redacts text, which holds whole lines or, when final
// is set, the final partial line, and writes what is no longer held
// back. A final emit writes every held line.
func (w *Writer) emit(text []byte, final bool) error {
	var out strings.Builder
	for line := range bytes.SplitAfterSeq(text, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		s := plan.EscapeLines(string(line))
		if w.reveal {
			out.WriteString(w.release(len(w.held)))
			out.WriteString(s)
			continue
		}
		w.held = append(w.held, s)
		if strings.HasSuffix(s, "\n") {
			out.WriteString(w.release(w.safeLines()))
		}
	}
	if final {
		out.WriteString(w.release(len(w.held)))
	}
	if out.Len() == 0 {
		return nil
	}
	_, err := io.WriteString(w.w, out.String())
	return err
}

// safeLines returns how many of the held lines can be written: those
// before the first line from which the held lines may be the beginning
// of a secret spanning lines, moved back past any secret found that
// starts before it and ends after it.
func (w *Writer) safeLines() int {
	lines := make([]string, len(w.held))
	for i, l := range w.held {
		lines[i] = strings.TrimSuffix(l, "\n")
	}
	n := w.reg.openFrom(lines)
	if n < 0 {
		return len(w.held)
	}
	if n == 0 {
		return 0
	}
	text := strings.Join(w.held, "")
	offsets := make([]int, len(w.held)+1)
	for i, l := range w.held {
		offsets[i+1] = offsets[i] + len(l)
	}
	for _, sp := range slices.Backward(w.reg.spans(text)) {
		for n > 0 && sp[0] < offsets[n] && offsets[n] < sp[1] {
			n--
		}
	}
	return n
}

// release returns the first n held lines, redacted, and drops them.
func (w *Writer) release(n int) string {
	if n == 0 {
		return ""
	}
	text := strings.Join(w.held[:n], "")
	w.held = append(w.held[:0:0], w.held[n:]...)
	return w.reg.Redact(text)
}
