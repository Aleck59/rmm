// Package tokens generates and hashes the bearer secrets used between agents
// and the server. Tokens carry a recognizable prefix (so secret scanners can
// find leaked ones) followed by 256 bits of randomness. The server stores only
// the SHA-256 of a token: a fast hash is sufficient because the input is
// high-entropy random data, not a human-chosen password.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

const (
	// EnrollPrefix marks enrollment tokens issued by an administrator.
	EnrollPrefix = "imenr_"
	// DevicePrefix marks per-device tokens issued to agents at enrollment.
	DevicePrefix = "imagt_"

	randomBytes = 32 // 256 bits
)

// Generate returns a new random token with the given prefix.
func Generate(prefix string) (string, error) {
	buf := make([]byte, randomBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// Hash returns the SHA-256 digest stored server-side for a token.
func Hash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// DisplayPrefix returns the non-secret leading part of a token (the type
// prefix plus four characters), safe to show in the UI and in audit records.
func DisplayPrefix(token string) string {
	for _, p := range []string{EnrollPrefix, DevicePrefix} {
		if strings.HasPrefix(token, p) && len(token) >= len(p)+4 {
			return token[:len(p)+4]
		}
	}
	return ""
}

// Valid reports whether token has the expected prefix and a plausible length.
// It is a cheap pre-check before a database lookup; it proves nothing about
// authenticity.
func Valid(token, prefix string) bool {
	if !strings.HasPrefix(token, prefix) {
		return false
	}
	body := token[len(prefix):]
	if len(body) != base64.RawURLEncoding.EncodedLen(randomBytes) {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(body)
	return err == nil
}
