package app_test

import (
	"strings"
	"testing"

	"github.com/mazrean/dbfence/internal/app"
	"github.com/mazrean/dbfence/internal/funcs"
	"github.com/mazrean/dbfence/internal/secret"
)

// observingReader records what the output showed when the answer was
// first read.
type observingReader struct {
	out    *strings.Builder
	answer *strings.Reader
	seen   string
	read   bool
}

func (r *observingReader) Read(p []byte) (int, error) {
	if !r.read {
		r.read = true
		r.seen = r.out.String()
	}
	return r.answer.Read(p)
}

// TestApplyPromptVisibleBeforeRead checks that the confirmation prompt,
// which has no line break, reaches the terminal through the line-buffered
// output sink before the answer is read.
func TestApplyPromptVisibleBeforeRead(t *testing.T) {
	t.Parallel()
	_, d, _, dir := newApp(t, "")
	var out strings.Builder
	in := &observingReader{out: &out, answer: strings.NewReader("yes\n")}
	w := secret.NewWriter(&out, secret.NewRegistry())
	a := app.New(funcs.NewRegistry(t.Context()), fakeOpener{d}, &app.IO{In: in, Out: w, Err: w})
	if err := a.Apply(t.Context(), app.Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(in.seen, "Apply these changes? Only 'yes' is accepted: ") {
		t.Errorf("output when the answer was read = %q, want it to end with the prompt", in.seen)
	}
	if len(d.executed) != 1 {
		t.Errorf("executed = %v", d.executed)
	}
}
