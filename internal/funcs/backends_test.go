package funcs

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

	secrets := []string{"pa55word", "X-Amz-Signature=SIG", "SIG", "frag", "p%zz"}
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
