// Package auth implements a minimal JWT issuer/verifier in the Go
// standard library. The point of this POC is to show the *mechanics* of
// token-based auth (issue -> verify on every request), not to be a
// production identity system.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// TTL is how long an issued token stays valid. Short on purpose: a
// leaked token is only useful for a few minutes.
const TTL = 15 * time.Minute

// Claims is the data carried inside the token.
type Claims struct {
	Subject   string `json:"sub"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

func signingKey() []byte {
	if k := os.Getenv("JWT_SECRET"); k != "" {
		return []byte(k)
	}
	// DEMO DEFAULT — overridable. This is the honest-limit flag of this POC:
	// HS256 with a shared secret means anyone holding the secret can mint
	// tokens. Production uses a key vault + rotation + RS256/JWKS.
	return []byte("demo-secret-NOT-FOR-PRODUCTION")
}

func b64(b []byte) string  { return base64.RawURLEncoding.EncodeToString(b) }
func unb64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// Issue creates a signed JWT for the given subject.
func Issue(subject string) (string, error) {
	header := b64([]byte(`{"alg":"HS256","typ":"JWT"}`))
	now := time.Now().Unix()
	payload, err := json.Marshal(Claims{
		Subject:   subject,
		IssuedAt:  now,
		ExpiresAt: now + int64(TTL/time.Second),
	})
	if err != nil {
		return "", err
	}
	body := b64(payload)
	mac := hmac.New(sha256.New, signingKey())
	mac.Write([]byte(header + "." + body))
	sig := b64(mac.Sum(nil))
	return header + "." + body + "." + sig, nil
}

// Verify checks the signature and expiry of a token. It returns the claims
// when the token is valid.
func Verify(token string) (Claims, error) {
	var zero Claims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return zero, fmt.Errorf("malformed token")
	}
	mac := hmac.New(sha256.New, signingKey())
	mac.Write([]byte(parts[0] + "." + parts[1]))
	want := b64(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[2]), []byte(want)) {
		return zero, fmt.Errorf("bad signature")
	}
	raw, err := unb64(parts[1])
	if err != nil {
		return zero, fmt.Errorf("bad payload")
	}
	var c Claims
	if err := json.Unmarshal(raw, &c); err != nil {
		return zero, fmt.Errorf("bad claims")
	}
	if time.Now().Unix() > c.ExpiresAt {
		return zero, fmt.Errorf("token expired")
	}
	return c, nil
}
