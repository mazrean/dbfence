package password

import (
	"strings"
	"testing"
)

func TestSCRAMVerifierWithSalt(t *testing.T) {
	t.Parallel()
	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	got, err := SCRAMVerifierWithSalt("pencil", salt, SCRAMIterations)
	if err != nil {
		t.Fatal(err)
	}
	// Computed independently with Python's hashlib/hmac.
	const want = "SCRAM-SHA-256$4096:AQIDBAUGBwgJCgsMDQ4PEA==$B9Mb8TSkDsvpddTD0BDmSDpJAo08+gvK8zcSCGRjCZw=:0z4kjgndRyJQnA93HtYE376F1vMDI59QM1nDcPyu8Rw="
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestSCRAMVerifier(t *testing.T) {
	t.Parallel()
	tests := []string{"pencil", "first'pw", `back\slash`, "md5aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "パスワード"}
	for _, pw := range tests {
		v, err := SCRAMVerifier(pw, 0)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(v, "SCRAM-SHA-256$4096:") || strings.ContainsAny(v, `'\`) {
			t.Errorf("unexpected verifier format %q", v)
		}
		ok, err := MatchPostgres(v, "u", pw)
		if err != nil || !ok {
			t.Errorf("MatchPostgres(SCRAMVerifier(%q)) = %v, %v", pw, ok, err)
		}
		if ok, _ := MatchPostgres(v, "u", pw+"x"); ok {
			t.Errorf("verifier of %q matches a different password", pw)
		}
		other, _ := SCRAMVerifier(pw, 0)
		if other == v {
			t.Errorf("salt is not random")
		}
	}
}
