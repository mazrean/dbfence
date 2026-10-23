package secret

import (
	"bytes"
	"io"
	"sync"

	"github.com/mazrean/dbfence/internal/plan"
)

// Writer is an output stream that escapes control characters (keeping
// line breaks and tabs, see plan.EscapeLines) and redacts the secrets of
// a Registry. It buffers the current line, so that a secret split across
// Write calls is still found, and writes each line once it is complete.
// Flush writes a pending partial line, such as a prompt.
type Writer struct {
	w      io.Writer
	reg    *Registry
	buf    []byte
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
	err := w.emit(lines)
	w.buf = append(w.buf[:0:0], rest...)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Flush writes the buffered partial line.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buf) == 0 {
		return nil
	}
	err := w.emit(w.buf)
	w.buf = w.buf[:0]
	return err
}

// emit escapes and redacts text, which holds whole lines or the final
// partial line, line by line, and writes it.
func (w *Writer) emit(text []byte) error {
	var out bytes.Buffer
	for line := range bytes.SplitAfterSeq(text, []byte("\n")) {
		s := plan.EscapeLines(string(line))
		if !w.reveal {
			s = w.reg.Redact(s)
		}
		out.WriteString(s)
	}
	_, err := w.w.Write(out.Bytes())
	return err
}
