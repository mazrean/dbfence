package funcs

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"
)

func TestTFStateErrorsRedactURL(t *testing.T) {
	t.Parallel()
	state, err := testdata.ReadFile("testdata/terraform.tfstate")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(state)
	}))
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")

	secrets := []string{"pa55word", "X-Amz-Signature=SIG", "SIG", "frag", "p%zz", "T0KEN"}
	tests := []struct {
		name    string
		url     string
		address string
		wantErr []string
	}{
		{
			name:    "unreachable",
			url:     "https://user:pa55word@127.0.0.1:1/state?X-Amz-Signature=SIG#frag",
			address: "output.n",
			wantErr: []string{"failed to read tfstate from https://user:xxxxx@127.0.0.1:1/state: Get \"https://user:xxxxx@127.0.0.1:1/state\""},
		},
		{
			name:    "go-quoted url with a quote in the query",
			url:     `https://127.0.0.1:1/state?token=T0KEN&label="x"`,
			address: "output.n",
			wantErr: []string{`Get "https://127.0.0.1:1/state"`},
		},
		{
			name:    "address not found",
			url:     "http://user:pa55word@" + host + "/state?X-Amz-Signature=SIG",
			address: "aws_db_instance.nope.address",
			wantErr: []string{"not found in http://user:xxxxx@" + host + "/state"},
		},
		{
			name:    "unparsable url",
			url:     "https://u:p%zz@127.0.0.1:1/s",
			address: "output.n",
			wantErr: []string{"state URL cannot be parsed"},
		},
		{
			name:    "local path kept",
			url:     "testdata/none.tfstate",
			address: "output.n",
			wantErr: []string{"testdata/none.tfstate"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := newTFStateReader().Lookup(t.Context(), tt.url, tt.address)
			if err == nil {
				t.Fatal("want error")
			}
			msg := err.Error()
			for _, w := range tt.wantErr {
				if !strings.Contains(msg, w) {
					t.Errorf("err = %q, want it to contain %q", msg, w)
				}
			}
			for _, s := range secrets {
				if strings.Contains(msg, s) {
					t.Errorf("err = %q leaks %q", msg, s)
				}
			}
		})
	}
}

// TestTFStatePanicDoesNotLockReader checks that a URL on which
// tfstate-lookup panics yields a plain error and leaves later lookups
// working.
func TestTFStatePanicDoesNotLockReader(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		url  string
	}{
		{"remote without organization", "remote://app.terraform.io"},
		{"remote with a trailing slash", "remote://app.terraform.io/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fn := NewRegistry(t.Context()).Functions()["tfstate"]
			_, err := fn.Call([]cty.Value{cty.StringVal(tt.url), cty.StringVal("output.x")})
			if err == nil {
				t.Fatal("want error")
			}
			if msg := err.Error(); strings.Contains(msg, "panic") || strings.Contains(msg, "goroutine") {
				t.Errorf("err = %q, want no panic or stack trace", msg)
			}
			done := make(chan error, 1)
			go func() {
				_, err := fn.Call([]cty.Value{cty.StringVal("testdata/terraform.tfstate"), cty.StringVal("output.db_host")})
				done <- err
			}()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("second lookup: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("second lookup did not return: the reader stayed locked")
			}
		})
	}
}

// TestTFStateErrorsDoNotQuoteValues checks that lookup and decoding
// errors never quote values from the state.
func TestTFStateErrorsDoNotQuoteValues(t *testing.T) {
	t.Parallel()
	const secret = "S3cr3tPassw0rd"
	path := filepath.Join(t.TempDir(), "terraform.tfstate")
	state := `{"version": 4, "outputs": {}, "resources": [{"mode": "managed", "type": "aws_db_instance", "name": "main",
		"instances": [{"attributes": {"password": "` + secret + `"}}]}]}`
	if err := os.WriteFile(path, []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		tfstate TFState
		address string
		wantErr string
	}{
		{"address one level too deep", newTFStateReader(), "aws_db_instance.main.password.value", `cannot look up "aws_db_instance.main.password.value"`},
		{"undecodable value", fakeTFState{json: `{"a": "` + secret + `"`}, "output.x", `the value of "output.x" cannot be decoded`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fn := NewRegistry(t.Context(), WithTFState(tt.tfstate)).Functions()["tfstate"]
			_, err := fn.Call([]cty.Value{cty.StringVal(path), cty.StringVal(tt.address)})
			if err == nil {
				t.Fatal("want error")
			}
			if msg := err.Error(); strings.Contains(msg, secret) || !strings.Contains(msg, tt.wantErr) {
				t.Errorf("err = %q, want %q without the secret", msg, tt.wantErr)
			}
		})
	}
}
