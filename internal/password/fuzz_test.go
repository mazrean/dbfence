package password

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
)

// cheapIterations bounds the work an input may demand in the fuzz
// targets, so that the fuzzer explores the parsers rather than PBKDF2 and
// SHA256Crypt. The caps themselves are covered by the table tests.
const cheapIterations = 10_000

// FuzzMatchPostgres feeds arbitrary rolpassword values to the SCRAM and
// md5 parsers: they must not panic, only a classified verifier may match,
// and errors must not depend on the password.
func FuzzMatchPostgres(f *testing.F) {
	salt := []byte("0123456789abcdef")
	key, err := SCRAMStoredKey("secret", salt, 4096)
	if err != nil {
		f.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString
	for _, v := range []string{
		"", "plain", "md5", PostgresMD5("app", "secret"),
		"SCRAM-SHA-256$4096:" + b64(salt) + "$" + b64(key) + ":" + b64(make([]byte, 32)),
		"SCRAM-SHA-256$0:" + b64(salt) + "$" + b64(key) + ":" + b64(key),
		"SCRAM-SHA-256$4096:$:", "SCRAM-SHA-256$$$", "SCRAM-SHA-256$4096:" + b64(salt) + "$" + b64(key),
		"SCRAM-SHA-256$-1:AA==$AA==:AA==", "SCRAM-SHA-256$1000001:AA==$AA==:AA==",
	} {
		f.Add(v, "app", "secret")
	}
	f.Fuzz(func(t *testing.T, verifier, user, password string) {
		if iter, ok := scramIterations(verifier); ok && iter > cheapIterations && iter <= maxSCRAMIterations {
			t.Skip()
		}
		ok, err := MatchPostgres(verifier, user, password)
		if ok && err != nil {
			t.Errorf("MatchPostgres(%q) = true with error %v", verifier, err)
		}
		if ok && PostgresVerifierKind(verifier) == VerifierUnknown {
			t.Errorf("MatchPostgres(%q) matched an unknown verifier", verifier)
		}
		// The error must not depend on the password.
		if _, err2 := MatchPostgres(verifier, user, password+"x"); errText(err) != errText(err2) {
			t.Errorf("errors %q and %q differ with the password", err, err2)
		}
	})
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// scramIterations returns the iteration count of a SCRAM verifier.
func scramIterations(verifier string) (int, bool) {
	rest, ok := strings.CutPrefix(verifier, "SCRAM-SHA-256$")
	if !ok {
		return 0, false
	}
	iter, _, _ := strings.Cut(rest, ":")
	n, err := strconv.Atoi(iter)
	return n, err == nil
}

// FuzzMatchMySQL feeds arbitrary authentication strings to the
// mysql_native_password, caching_sha2_password and sha256_password
// parsers.
func FuzzMatchMySQL(f *testing.F) {
	salt := "abcdefghij0123456789"
	for _, a := range []struct{ plugin, auth string }{
		{PluginNative, MySQLNative("secret")},
		{PluginNative, ""},
		{PluginCachingSHA2, "$A$005$" + salt + string(SHA256Crypt([]byte("secret"), []byte(salt), 5000))},
		{PluginCachingSHA2, "$A$000$" + salt + strings.Repeat("a", 43)},
		{PluginCachingSHA2, "$A$fff$" + salt + strings.Repeat("a", 43)},
		{PluginCachingSHA2, "$A$005$short"},
		{PluginSHA256, "$5$" + salt + "$" + string(SHA256Crypt([]byte("pw"), []byte(salt), sha256Rounds))},
		{PluginSHA256, "$5$x"},
		{"auth_socket", ""},
	} {
		f.Add(a.plugin, []byte(a.auth), "secret")
	}
	f.Fuzz(func(t *testing.T, plugin string, auth []byte, password string) {
		const rounds = len(cachingSHA2Prefix) + 3
		if plugin == PluginCachingSHA2 && len(auth) > rounds {
			if n, err := strconv.ParseUint(string(auth[len(cachingSHA2Prefix):rounds]), 16, 12); err == nil &&
				n*cachingSHA2RoundsUnit > cheapIterations {
				t.Skip()
			}
		}
		ok, err := MatchMySQL(plugin, auth, password)
		if ok && err != nil {
			t.Errorf("MatchMySQL(%q, %q) = true with error %v", plugin, auth, err)
		}
		if _, err2 := MatchMySQL(plugin, auth, password+"x"); errText(err) != errText(err2) {
			t.Errorf("errors %q and %q differ with the password", err, err2)
		}
	})
}
