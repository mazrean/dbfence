// Package password verifies plaintext passwords against the verifiers
// stored by MySQL and PostgreSQL without contacting the server.
package password

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // PostgreSQL legacy md5 verifier.
	"crypto/pbkdf2"
	"crypto/sha1" //nolint:gosec // mysql_native_password verifier.
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrUnsupported is returned when the verifier format is unknown.
var ErrUnsupported = errors.New("unsupported password verifier")

// MySQLPlugin names.
const (
	PluginNative       = "mysql_native_password"
	PluginCachingSHA2  = "caching_sha2_password"
	cachingSHA2Prefix  = "$A$"
	cachingSHA2SaltLen = 20
	sha256CryptDigest  = 43
	// cachingSHA2RoundsUnit multiplies the stored iteration count.
	cachingSHA2RoundsUnit = 1000
)

// MatchMySQL reports whether password matches authentication_string
// stored for the given plugin.
func MatchMySQL(plugin string, authString []byte, password string) (bool, error) {
	switch plugin {
	case PluginNative:
		if len(authString) == 0 {
			return password == "", nil
		}
		return subtle.ConstantTimeCompare(authString, []byte(MySQLNative(password))) == 1, nil
	case PluginCachingSHA2:
		if len(authString) == 0 {
			return password == "", nil
		}
		return matchCachingSHA2(authString, password)
	default:
		return false, fmt.Errorf("%w: mysql plugin %q", ErrUnsupported, plugin)
	}
}

// MySQLNative returns the mysql_native_password verifier.
func MySQLNative(password string) string {
	first := sha1.Sum([]byte(password)) //nolint:gosec // protocol defined.
	second := sha1.Sum(first[:])        //nolint:gosec // protocol defined.
	return "*" + strings.ToUpper(hex.EncodeToString(second[:]))
}

// matchCachingSHA2 checks "$A$<rounds/1000 as 3 hex digits>$<20 byte salt><43 byte digest>".
func matchCachingSHA2(authString []byte, password string) (bool, error) {
	const header = len(cachingSHA2Prefix) + 4 // "$A$" + "005$"
	if len(authString) != header+cachingSHA2SaltLen+sha256CryptDigest ||
		!bytes.HasPrefix(authString, []byte(cachingSHA2Prefix)) || authString[header-1] != '$' {
		return false, fmt.Errorf("%w: malformed caching_sha2_password string", ErrUnsupported)
	}
	iter, err := strconv.ParseUint(string(authString[len(cachingSHA2Prefix):header-1]), 16, 12)
	if err != nil || iter == 0 {
		return false, fmt.Errorf("%w: invalid iteration count", ErrUnsupported)
	}
	salt := authString[header : header+cachingSHA2SaltLen]
	digest := authString[header+cachingSHA2SaltLen:]
	got := SHA256Crypt([]byte(password), salt, int(iter)*cachingSHA2RoundsUnit)
	return subtle.ConstantTimeCompare(got, digest) == 1, nil
}

// SHA256Crypt implements the SHA-256 based crypt by Ulrich Drepper
// (the "$5$" scheme), returning the 43 character encoded digest.
// MySQL's caching_sha2_password uses it with a 20 byte salt.
func SHA256Crypt(password, salt []byte, rounds int) []byte {
	const size = sha256.Size

	b := sha256.New()
	b.Write(password)
	b.Write(salt)
	b.Write(password)
	sumB := b.Sum(nil)

	a := sha256.New()
	a.Write(password)
	a.Write(salt)
	i := len(password)
	for ; i > size; i -= size {
		a.Write(sumB)
	}
	a.Write(sumB[:i])
	for i = len(password); i > 0; i >>= 1 {
		if i&1 != 0 {
			a.Write(sumB)
		} else {
			a.Write(password)
		}
	}
	sumA := a.Sum(nil)

	dp := sha256.New()
	for range len(password) {
		dp.Write(password)
	}
	p := repeat(dp.Sum(nil), len(password))

	ds := sha256.New()
	for range 16 + int(sumA[0]) {
		ds.Write(salt)
	}
	s := repeat(ds.Sum(nil), len(salt))

	c := sumA
	for r := range rounds {
		h := sha256.New()
		if r&1 != 0 {
			h.Write(p)
		} else {
			h.Write(c)
		}
		if r%3 != 0 {
			h.Write(s)
		}
		if r%7 != 0 {
			h.Write(p)
		}
		if r&1 != 0 {
			h.Write(c)
		} else {
			h.Write(p)
		}
		c = h.Sum(nil)
	}

	out := make([]byte, 0, sha256CryptDigest)
	for _, t := range [...][3]int{
		{0, 10, 20}, {21, 1, 11}, {12, 22, 2}, {3, 13, 23}, {24, 4, 14},
		{15, 25, 5}, {6, 16, 26}, {27, 7, 17}, {18, 28, 8}, {9, 19, 29},
	} {
		out = b64From24(out, c[t[0]], c[t[1]], c[t[2]], charsPer24Bits)
	}
	return b64From24(out, 0, c[31], c[30], charsPer16Bits)
}

// Characters emitted for 24 and 16 bits of digest.
const (
	charsPer24Bits = 4
	charsPer16Bits = 3
)

const cryptAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func b64From24(dst []byte, b2, b1, b0 byte, n int) []byte {
	w := uint(b2)<<16 | uint(b1)<<8 | uint(b0)
	for range n {
		dst = append(dst, cryptAlphabet[w&0x3f])
		w >>= 6
	}
	return dst
}

func repeat(seq []byte, n int) []byte {
	out := make([]byte, 0, n)
	for len(out) < n {
		out = append(out, seq[:min(len(seq), n-len(out))]...)
	}
	return out
}

// MatchPostgres reports whether password matches the rolpassword
// verifier of role user.
func MatchPostgres(verifier, user, password string) (bool, error) {
	switch {
	case verifier == "":
		// No stored password (NULL rolpassword). PostgreSQL stores an
		// empty password this way, so only "" matches.
		return password == "", nil
	case strings.HasPrefix(verifier, "SCRAM-SHA-256$"):
		return matchSCRAM(verifier, password)
	case strings.HasPrefix(verifier, "md5") && len(verifier) == 35:
		return subtle.ConstantTimeCompare([]byte(verifier), []byte(PostgresMD5(user, password))) == 1, nil
	default:
		return false, fmt.Errorf("%w: postgres verifier", ErrUnsupported)
	}
}

// PostgresMD5 returns the legacy md5 verifier.
func PostgresMD5(user, password string) string {
	sum := md5.Sum([]byte(password + user)) //nolint:gosec // protocol defined.
	return "md5" + hex.EncodeToString(sum[:])
}

// maxSCRAMIterations bounds the PBKDF2 work a stored verifier can demand
// from plan; PostgreSQL's default is 4096.
const maxSCRAMIterations = 10_000_000

// matchSCRAM checks "SCRAM-SHA-256$<iter>:<salt>$<StoredKey>:<ServerKey>".
func matchSCRAM(verifier, password string) (bool, error) {
	malformed := fmt.Errorf("%w: malformed SCRAM verifier", ErrUnsupported)
	params, keys, ok := strings.Cut(strings.TrimPrefix(verifier, "SCRAM-SHA-256$"), "$")
	if !ok || strings.Contains(keys, "$") {
		return false, malformed
	}
	iterStr, saltStr, ok1 := strings.Cut(params, ":")
	storedStr, serverStr, ok2 := strings.Cut(keys, ":")
	if !ok1 || !ok2 {
		return false, malformed
	}
	iter, err := strconv.Atoi(iterStr)
	if err != nil || iter < 1 {
		return false, malformed
	}
	if iter > maxSCRAMIterations {
		return false, fmt.Errorf("%w: SCRAM iteration count above %d", ErrUnsupported, maxSCRAMIterations)
	}
	salt, err := base64.StdEncoding.DecodeString(saltStr)
	if err != nil || len(salt) == 0 {
		return false, malformed
	}
	storedKey, err := base64.StdEncoding.DecodeString(storedStr)
	if err != nil || len(storedKey) != sha256.Size {
		return false, malformed
	}
	serverKey, err := base64.StdEncoding.DecodeString(serverStr)
	if err != nil || len(serverKey) != sha256.Size {
		return false, malformed
	}
	got, err := SCRAMStoredKey(password, salt, iter)
	if err != nil {
		return false, err
	}
	return hmac.Equal(got, storedKey), nil
}

// SCRAMStoredKey derives the SCRAM-SHA-256 StoredKey.
func SCRAMStoredKey(password string, salt []byte, iter int) ([]byte, error) {
	salted, err := pbkdf2.Key(sha256.New, saslPrep(password), salt, iter, sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("pbkdf2: %w", err)
	}
	mac := hmac.New(sha256.New, salted)
	mac.Write([]byte("Client Key"))
	stored := sha256.Sum256(mac.Sum(nil))
	return stored[:], nil
}
