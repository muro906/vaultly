package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// TokenPrefix marks a Vaultly access token. A recognisable prefix lets secret
// scanners spot a leaked token in a repository or a log, which is the whole
// reason to have one.
const TokenPrefix = "vlt"

// Access tokens are formatted as:
//
//	vlt_<public prefix>_<secret>
//
// The public prefix is stored in plaintext so a token can be identified in the
// UI and in logs. The secret half is never stored: only a SHA-256 digest of
// the whole token is persisted.
// The public prefix is hex-encoded rather than base64 so it cannot contain an
// underscore, which would otherwise collide with the field separator. The
// secret half is base64url and may contain underscores, so parsing splits into
// a bounded number of fields rather than on every separator.
const (
	tokenPrefixBytes = 4  // bytes of the public identifier, hex-encoded
	tokenPrefixLen   = 8  // resulting characters (2 per byte)
	tokenSecretLen   = 32 // bytes of entropy in the secret half
)

var (
	// ErrMalformedToken means a presented token is not shaped like one this
	// server issues, so it can be rejected without touching the database.
	ErrMalformedToken = errors.New("auth: malformed access token")
)

// GeneratedToken is a freshly minted access token. Plaintext is returned to
// the caller exactly once; only Hash and Prefix are ever persisted.
type GeneratedToken struct {
	// Plaintext is the full token to hand to the user. It cannot be recovered
	// later.
	Plaintext string
	// Prefix is the non-secret identifier, safe to display and log.
	Prefix string
	// Hash is the SHA-256 digest of Plaintext, which is what the database
	// stores and what lookups match against.
	Hash []byte
}

// GenerateAccessToken mints a new machine token.
func GenerateAccessToken() (*GeneratedToken, error) {
	prefix, err := randomHex(tokenPrefixBytes)
	if err != nil {
		return nil, err
	}

	secret, err := randomBase64(tokenSecretLen)
	if err != nil {
		return nil, err
	}

	plaintext := fmt.Sprintf("%s_%s_%s", TokenPrefix, prefix, secret)

	return &GeneratedToken{
		Plaintext: plaintext,
		Prefix:    prefix,
		Hash:      HashToken(plaintext),
	}, nil
}

// HashToken returns the digest under which a token is stored and looked up.
//
// A plain SHA-256 is correct here, unlike for passwords: the token carries 256
// bits of uniform entropy, so there is nothing to brute-force and no benefit
// to a slow KDF. Using a fast hash also keeps token authentication cheap
// enough to run on every CI/CD request.
func HashToken(plaintext string) []byte {
	sum := sha256.Sum256([]byte(plaintext))
	return sum[:]
}

// ParseTokenPrefix extracts the public prefix from a presented token and
// checks its shape. It exists so that malformed input is rejected before a
// database round trip, and so a token can be logged by prefix without logging
// the secret half.
func ParseTokenPrefix(plaintext string) (string, error) {
	// SplitN with a limit of 3 keeps any underscore in the base64url secret
	// inside the final field instead of producing a fourth one.
	parts := strings.SplitN(plaintext, "_", 3)
	if len(parts) != 3 || parts[0] != TokenPrefix {
		return "", ErrMalformedToken
	}
	if len(parts[1]) != tokenPrefixLen || parts[2] == "" {
		return "", ErrMalformedToken
	}
	return parts[1], nil
}

// GenerateRefreshToken mints an opaque session refresh token. Refresh tokens
// are not JWTs: they must be revocable, which means the server has to look
// them up anyway, and a random string is simpler and smaller than a signed one.
func GenerateRefreshToken() (*GeneratedToken, error) {
	secret, err := randomBase64(tokenSecretLen)
	if err != nil {
		return nil, err
	}
	return &GeneratedToken{
		Plaintext: secret,
		Hash:      HashToken(secret),
	}, nil
}

// CompareTokenHash reports whether two digests match, in constant time.
func CompareTokenHash(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// randomBase64 returns n bytes of cryptographic randomness, URL-safe base64
// encoded so the result is copy-pasteable and safe in a header or a .env file.
func randomBase64(n int) (string, error) {
	buf, err := randomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// randomHex returns n bytes of cryptographic randomness, hex encoded. Hex is
// used where the result must not contain the token separator.
func randomHex(n int) (string, error) {
	buf, err := randomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func randomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("auth: generate random bytes: %w", err)
	}
	return buf, nil
}
