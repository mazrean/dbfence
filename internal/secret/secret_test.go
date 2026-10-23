package secret

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestRedactVariants(t *testing.T) {
	t.Parallel()
	const pw = "p@ss w'rd/<&>+\u00e9"
	// The registered value has é decomposed; output may show it NFC.
	const decomposed = "p@ss w'rd/<&>+e\u0301"
	jsonText, err := json.Marshal(pw)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		text string
	}{
		{name: "raw", text: decomposed},
		{name: "NFC", text: pw},
		{name: "query escape", text: url.QueryEscape(pw)},
		{name: "path escape", text: url.PathEscape(pw)},
		{name: "urlencode", text: strings.ReplaceAll(url.QueryEscape(pw), "+", "%20")},
		{name: "base64 std", text: base64.StdEncoding.EncodeToString([]byte(pw))},
		{name: "base64 url", text: base64.URLEncoding.EncodeToString([]byte(pw))},
		{name: "base64 raw url", text: base64.RawURLEncoding.EncodeToString([]byte(pw))},
		{name: "json", text: string(jsonText)},
		{name: "go quoted", text: fmt.Sprintf("%q", pw)},
		{name: "sql literal", text: "'" + strings.ReplaceAll(pw, "'", "''") + "'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := NewRegistry()
			r.Add(decomposed)
			got := r.Redact("before " + tt.text + " after")
			if !strings.Contains(got, Placeholder) || strings.Contains(got, "ss w") || strings.Contains(got, "ss%20w") {
				t.Errorf("Redact = %q, want the %s form redacted", got, tt.name)
			}
			if !strings.HasPrefix(got, "before ") || !strings.HasSuffix(got, " after") {
				t.Errorf("Redact = %q, want the surrounding text kept", got)
			}
		})
	}
}

func TestRedact(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      string
		want    string
		secrets []string
	}{
		{name: "nothing registered", secrets: nil, in: "hello", want: "hello"},
		{name: "short secret is ignored", secrets: []string{"abc"}, in: "abc abcd", want: "abc abcd"},
		{name: "minimum length", secrets: []string{"abcd"}, in: "xabcdx", want: "x<redacted>x"},
		{name: "every occurrence", secrets: []string{"hunter2"}, in: "hunter2 and hunter2", want: "<redacted> and <redacted>"},
		{name: "longest wins", secrets: []string{"secret", "secret-long"}, in: "a secret-long b", want: "a <redacted> b"},
		{name: "overlapping secrets leave no fragment", secrets: []string{"abcd", "cdefgh"}, in: "xabcdefghx", want: "x<redacted>x"},
		{name: "overlapping occurrences", secrets: []string{"aaaa"}, in: "aaaaaa", want: "<redacted>"},
		{name: "multi-line secret is redacted per line", secrets: []string{"line-one\nline-two"}, in: "line-one\n", want: "<redacted>\n"},
		{name: "control characters as escaped in output", secrets: []string{"pw\x1b[2Kxyz"}, in: `pw\x1b[2Kxyz`, want: "<redacted>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := NewRegistry()
			for _, s := range tt.secrets {
				r.Add(s)
			}
			if got := r.Redact(tt.in); got != tt.want {
				t.Errorf("Redact(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func TestWriter(t *testing.T) {
	t.Parallel()
	const pw = "s3cr3t-value"
	tests := []struct {
		name   string
		want   string
		writes []string
		show   bool
		flush  bool
	}{
		{name: "split across writes", writes: []string{"password s3c", "r3t-", "value ok\n"}, want: "password <redacted> ok\n"},
		{name: "partial line waits for a newline", writes: []string{"s3cr3t-"}, want: ""},
		{name: "flush writes the partial line redacted", writes: []string{"prompt s3cr3t-value: "}, flush: true, want: "prompt <redacted>: "},
		{name: "several lines in one write", writes: []string{"a s3cr3t-value\nb s3cr3t-value\nc s3"}, want: "a <redacted>\nb <redacted>\n"},
		{name: "show secrets bypasses redaction", writes: []string{"pw s3cr3t-value\n"}, show: true, want: "pw s3cr3t-value\n"},
		{name: "control characters are escaped", writes: []string{"name \x1b[2K\r\ttab\n"}, want: "name \\x1b[2K\\r\ttab\n"},
		{name: "show secrets still escapes", writes: []string{"\x1b\n"}, show: true, want: "\\x1b\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := NewRegistry()
			r.Add(pw)
			var out bytes.Buffer
			w := NewWriter(&out, r)
			w.ShowSecrets(tt.show)
			for _, s := range tt.writes {
				n, err := w.Write([]byte(s))
				if err != nil || n != len(s) {
					t.Fatalf("Write(%q) = %d, %v", s, n, err)
				}
			}
			if tt.flush {
				if err := w.Flush(); err != nil {
					t.Fatal(err)
				}
			}
			if out.String() != tt.want {
				t.Errorf("output = %q, want %q", out.String(), tt.want)
			}
		})
	}
}

func TestWriterErrors(t *testing.T) {
	t.Parallel()
	w := NewWriter(failWriter{}, NewRegistry())
	if _, err := w.Write([]byte("line\n")); err == nil {
		t.Error("Write: want the underlying error")
	}
	if _, err := w.Write([]byte("partial")); err != nil {
		t.Errorf("Write of a partial line = %v, want nil", err)
	}
	if err := w.Flush(); err == nil {
		t.Error("Flush: want the underlying error")
	}
}

func TestRegisterDefault(t *testing.T) {
	t.Parallel()
	Register("default-registry-secret")
	if got := Default().Redact("x default-registry-secret"); got != "x "+Placeholder {
		t.Errorf("Default().Redact = %q", got)
	}
}

// TestWriterRedactsEscapedForms covers forms whose printed text the
// Writer escapes before it redacts: every form must match the escaped
// line, not the raw one.
func TestWriterRedactsEscapedForms(t *testing.T) {
	t.Parallel()
	jsonOf := func(s string) string {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	tests := []struct {
		name, secret, printed, leaked string
	}{
		{name: "backslash-escaped SQL literal", secret: `Ab\Cd9xYz`, printed: `'Ab\\Cd9xYz'`, leaked: "Cd9xYz"},
		{name: "JSON with bidi control and quote", secret: "Qw\"er\u202eTy7u", printed: jsonOf("Qw\"er\u202eTy7u"), leaked: "Ty7u"},
		{name: "SQL literal with control and quote", secret: "Mn'bv\x01Cx5z", printed: "'Mn''bv\x01Cx5z'", leaked: "Cx5z"},
		{name: "multi-line with control before newline", secret: "Lk8jHg\x01\nFd3sAa", printed: "Lk8jHg\x01\nFd3sAa", leaked: "Lk8jHg"},
		{name: "multi-line with control after newline", secret: "Po9iUy\n\x02Tr4eWq", printed: "Po9iUy\n\x02Tr4eWq", leaked: "Tr4eWq"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reg := NewRegistry()
			reg.Add(tt.secret)
			var buf bytes.Buffer
			w := NewWriter(&buf, reg)
			if _, err := w.Write([]byte("near " + tt.printed + " at line 1\n")); err != nil {
				t.Fatal(err)
			}
			if err := w.Flush(); err != nil {
				t.Fatal(err)
			}
			if got := buf.String(); strings.Contains(got, tt.leaked) || !strings.Contains(got, Placeholder) {
				t.Errorf("output = %q, want %q redacted", got, tt.leaked)
			}
		})
	}
}

// TestWriterMultiLineSecrets checks that a secret spanning lines is
// redacted as a whole, even when its lines are shorter than MinLength.
func TestWriterMultiLineSecrets(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		want    string
		secrets []string
		writes  []string
		flush   bool
	}{
		{name: "lines shorter than MinLength", secrets: []string{"k9Q\nz7W\nm2X\np4R"}, writes: []string{"near k9Q\nz7W\nm2X\np4R at line 1\n"}, want: "near <redacted> at line 1\n"},
		{name: "short last line", secrets: []string{"Vb6nMk2LqP\nx8Z"}, writes: []string{"near Vb6nMk2LqP\nx8Z at line 1\n"}, want: "near <redacted> at line 1\n"},
		{name: "one line per write", secrets: []string{"k9Q\nz7W\nm2X"}, writes: []string{"near k9Q\n", "z7W\n", "m2X at 1\n"}, want: "near <redacted> at 1\n"},
		{name: "lines are written once they differ", secrets: []string{"k9Q\nz7W\nm2X"}, writes: []string{"a k9Q\nz7W\nother\n"}, want: "a k9Q\nz7W\nother\n"},
		{name: "a possible beginning is held", secrets: []string{"k9Q\nz7W"}, writes: []string{"first\nsecond k9Q\n"}, want: "first\n"},
		{name: "flush writes held lines", secrets: []string{"k9Q\nz7W"}, writes: []string{"first\nsecond k9Q\n"}, flush: true, want: "first\nsecond k9Q\n"},
		{name: "leading and trailing line breaks", secrets: []string{"\nk9Q\nz7W\n"}, writes: []string{"x\nk9Q\nz7W\ny\n"}, want: "x\n<redacted>\ny\n"},
		{name: "secret across the start of another", secrets: []string{"aa\nbbbb", "bbbb\ncc\ndd"}, writes: []string{"x aa\n", "bbbb\n", "cc\n", "zz\n"}, want: "x <redacted>\ncc\nzz\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := NewRegistry()
			for _, s := range tt.secrets {
				r.Add(s)
			}
			var out bytes.Buffer
			w := NewWriter(&out, r)
			for _, s := range tt.writes {
				if _, err := w.Write([]byte(s)); err != nil {
					t.Fatal(err)
				}
			}
			if tt.flush {
				if err := w.Flush(); err != nil {
					t.Fatal(err)
				}
			}
			if out.String() != tt.want {
				t.Errorf("output = %q, want %q", out.String(), tt.want)
			}
		})
	}
}
