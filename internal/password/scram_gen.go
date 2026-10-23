package password

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
)

// SCRAM parameters used by PostgreSQL's default verifier.
const (
	// SCRAMIterations is PostgreSQL's default iteration count, and the
	// only one before PostgreSQL 16 added scram_iterations.
	SCRAMIterations = 4096
	scramSaltLen    = 16
)

// SCRAMVerifier returns a PostgreSQL SCRAM-SHA-256 verifier for password
// with a random salt and iter iterations (SCRAMIterations when iter <= 0),
// as PQencryptPasswordConn does. Sending it instead of the plaintext keeps
// the password out of server logs.
func SCRAMVerifier(password string, iter int) (string, error) {
	if iter <= 0 {
		iter = SCRAMIterations
	}
	salt := make([]byte, scramSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("scram salt: %w", err)
	}
	return SCRAMVerifierWithSalt(password, salt, iter)
}

// SCRAMVerifierWithSalt returns
// "SCRAM-SHA-256$<iter>:<salt>$<StoredKey>:<ServerKey>".
func SCRAMVerifierWithSalt(password string, salt []byte, iter int) (string, error) {
	salted, err := pbkdf2.Key(sha256.New, saslPrep(password), salt, iter, sha256.Size)
	if err != nil {
		return "", fmt.Errorf("pbkdf2: %w", err)
	}
	clientMAC := hmac.New(sha256.New, salted)
	clientMAC.Write([]byte("Client Key"))
	stored := sha256.Sum256(clientMAC.Sum(nil))
	serverMAC := hmac.New(sha256.New, salted)
	serverMAC.Write([]byte("Server Key"))
	b64 := base64.StdEncoding.EncodeToString
	return "SCRAM-SHA-256$" + strconv.Itoa(iter) + ":" + b64(salt) + "$" + b64(stored[:]) + ":" + b64(serverMAC.Sum(nil)), nil
}
