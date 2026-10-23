package password

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestSHA256Crypt(t *testing.T) {
	t.Parallel()
	// Reference vectors generated with `openssl passwd -5`.
	tests := []struct {
		name     string
		password string
		salt     string
		want     string
		rounds   int
	}{
		{name: "default rounds", password: "Hello world!", salt: "saltstring", rounds: 5000, want: "5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"},
		{name: "10000 rounds", password: "Hello world!", salt: "saltstringsaltst", rounds: 10000, want: "3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA"},
		{name: "long password", password: "we have a short salt string but not a short password", salt: "roundstoolow", rounds: 5000, want: "tnmBRVdOlMerN1PGoR.Nz.UgcICWpmaUcxSHCg/0Mc0"},
		{name: "password longer than digest", password: strings.Repeat("x", 70), salt: "abc", rounds: 1000, want: "Tl2XdQ9SsLJz3m78s1sTwwfV29P8cohDvJyKjd/CUW2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := string(SHA256Crypt([]byte(tt.password), []byte(tt.salt), tt.rounds))
			if got != tt.want {
				t.Errorf("SHA256Crypt() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestMatchMySQL(t *testing.T) {
	t.Parallel()
	salt := "abcdefghij0123456789"
	caching := "$A$005$" + salt + string(SHA256Crypt([]byte("secret"), []byte(salt), 5000))
	tests := []struct {
		name, plugin, auth, password string
		want, wantErr                bool
	}{
		{"native match", PluginNative, "*14E65567ABDB5135D0CFD9A70B3032C179A49EE7", "secret", true, false},
		{"native mismatch", PluginNative, "*14E65567ABDB5135D0CFD9A70B3032C179A49EE7", "other", false, false},
		{"native empty", PluginNative, "", "", true, false},
		{"caching match", PluginCachingSHA2, caching, "secret", true, false},
		{"caching mismatch", PluginCachingSHA2, caching, "Secret", false, false},
		{"caching empty password", PluginCachingSHA2, "", "x", false, false},
		{"caching hex rounds", PluginCachingSHA2, "$A$00A$" + salt + string(SHA256Crypt([]byte("secret"), []byte(salt), 10000)), "secret", true, false},
		{"caching malformed", PluginCachingSHA2, "$A$005$short", "x", false, true},
		{"unknown plugin", "auth_socket", "", "x", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := MatchMySQL(tt.plugin, []byte(tt.auth), tt.password)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchPostgres(t *testing.T) {
	t.Parallel()
	salt := []byte("0123456789abcdef")
	key, err := SCRAMStoredKey("secret", salt, 4096)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString
	key32 := b64(make([]byte, 32))
	scram := "SCRAM-SHA-256$4096:" + b64(salt) + "$" + b64(key) + ":" + key32
	tests := []struct {
		name, verifier, user, password string
		want, wantErr                  bool
	}{
		{"scram match", scram, "app", "secret", true, false},
		{"scram mismatch", scram, "app", "nope", false, false},
		{"scram malformed", "SCRAM-SHA-256$x", "app", "secret", false, true},
		{"scram zero iterations", "SCRAM-SHA-256$0:" + b64(salt) + "$" + b64(key) + ":" + key32, "app", "secret", false, true},
		{"scram negative iterations", "SCRAM-SHA-256$-5:" + b64(salt) + "$" + b64(key) + ":" + key32, "app", "secret", false, true},
		{"scram too many iterations", "SCRAM-SHA-256$10000001:" + b64(salt) + "$" + b64(key) + ":" + key32, "app", "secret", false, true},
		{"scram empty salt", "SCRAM-SHA-256$4096:$" + b64(key) + ":" + key32, "app", "secret", false, true},
		{"scram empty keys", "SCRAM-SHA-256$4096:" + b64(salt) + "$:", "app", "secret", false, true},
		{"scram short stored key", "SCRAM-SHA-256$4096:" + b64(salt) + "$AAAA:" + key32, "app", "secret", false, true},
		{"scram short server key", "SCRAM-SHA-256$4096:" + b64(salt) + "$" + b64(key) + ":AAAA", "app", "secret", false, true},
		{"scram missing server key", "SCRAM-SHA-256$4096:" + b64(salt) + "$" + b64(key), "app", "secret", false, true},
		{"md5 match", PostgresMD5("app", "secret"), "app", "secret", true, false},
		{"md5 other user", PostgresMD5("app", "secret"), "bob", "secret", false, false},
		{"no password", "", "app", "secret", false, false},
		{"no password empty declared", "", "app", "", true, false},
		{"unknown", "plain", "app", "secret", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := MatchPostgres(tt.verifier, tt.user, tt.password)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
