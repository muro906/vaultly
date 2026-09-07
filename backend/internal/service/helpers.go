package service

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode"

	"vaultly/backend/internal/domain"
)

// base64Encode and base64Decode wrap opaque cursors. URL-safe and unpadded so
// a cursor can be dropped into a query string untouched.
func base64Encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func base64Decode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// slugPattern is what a generated or supplied slug must match.
var slugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// nonSlugChars matches any run of characters that cannot appear in a slug.
var nonSlugChars = regexp.MustCompile(`[^a-z0-9]+`)

// Slugify converts a display name into a URL-safe slug.
func Slugify(name string) string {
	slug := nonSlugChars.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
	slug = strings.Trim(slug, "-")
	if len(slug) > 60 {
		slug = strings.Trim(slug[:60], "-")
	}
	return slug
}

// secretKeyPattern is the shape of a secret key. Restricting keys to the
// conventional environment-variable form means a pulled .env file is always
// valid shell, and it removes any question of how to escape a key name.
var secretKeyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// Validation limits. They exist to bound storage and to keep the UI honest,
// not as security boundaries.
const (
	maxNameLen        = 100
	maxDescriptionLen = 500
	maxSecretKeyLen   = 128
	maxSecretValueLen = 64 * 1024
	maxCommentLen     = 200
	minPasswordLen    = 12
	maxPasswordLen    = 1024
	maxEmailLen       = 254
)

// emailPattern is a deliberately permissive check. Full RFC 5322 validation in
// a regex is a well-known mistake; the real proof that an address works is
// sending mail to it.
var emailPattern = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// validateEmail checks an address and returns it normalised.
func validateEmail(v *domain.ValidationError, email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	switch {
	case email == "":
		v.Add("email", "is required")
	case len(email) > maxEmailLen:
		v.Add("email", "is too long")
	case !emailPattern.MatchString(email):
		v.Add("email", "is not a valid email address")
	}
	return email
}

// validatePassword enforces a length floor and nothing else.
//
// Composition rules (a digit, a symbol, mixed case) are deliberately omitted:
// they push users towards predictable substitutions without adding real
// entropy. Length is what matters, and Argon2id absorbs the rest.
func validatePassword(v *domain.ValidationError, password string) {
	switch {
	case password == "":
		v.Add("password", "is required")
	case len(password) < minPasswordLen:
		v.Add("password", "must be at least 12 characters")
	case len(password) > maxPasswordLen:
		v.Add("password", "is too long")
	}
}

// validateName checks a human-facing display name.
func validateName(v *domain.ValidationError, field, name string) string {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		v.Add(field, "is required")
	case len(name) > maxNameLen:
		v.Add(field, "is too long")
	case !hasPrintableContent(name):
		v.Add(field, "must contain visible characters")
	}
	return name
}

// validateDescription checks an optional free-text description.
func validateDescription(v *domain.ValidationError, field, description string) string {
	description = strings.TrimSpace(description)
	if len(description) > maxDescriptionLen {
		v.Add(field, "is too long")
	}
	return description
}

// validateSecretKey checks a secret's key.
func validateSecretKey(v *domain.ValidationError, key string) string {
	key = strings.TrimSpace(key)
	switch {
	case key == "":
		v.Add("key", "is required")
	case len(key) > maxSecretKeyLen:
		v.Add("key", "is too long")
	case !secretKeyPattern.MatchString(key):
		v.Add("key", "must start with an uppercase letter and contain only A-Z, 0-9 and underscores")
	}
	return key
}

// validateSecretValue checks a secret's value. Unlike a key, a value is
// arbitrary bytes: it is bounded but not otherwise constrained, since it may
// legitimately be a private key, a JSON blob or a connection string.
func validateSecretValue(v *domain.ValidationError, value string) {
	if len(value) > maxSecretValueLen {
		v.Add("value", "is too long")
	}
}

// hasPrintableContent reports whether s contains at least one visible
// character, rejecting names made only of spaces or control characters.
func hasPrintableContent(s string) bool {
	for _, r := range s {
		if unicode.IsGraphic(r) && !unicode.IsSpace(r) {
			return true
		}
	}
	return false
}
