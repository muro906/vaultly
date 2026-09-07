// Package auth implements credential handling: password hashing, session
// tokens for humans and opaque access tokens for machines.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. These follow the OWASP recommendation of 19 MiB of
// memory with two iterations, which resists GPU cracking while staying fast
// enough to run on every login.
//
// The parameters are stored inside each hash, so raising them here does not
// invalidate existing passwords: old hashes keep verifying under their own
// parameters and are upgraded on next login via NeedsRehash.
const (
	argonTime    = 2
	argonMemory  = 19 * 1024 // KiB
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16
)

var (
	// ErrInvalidHash means a stored hash is not in the expected encoded form.
	ErrInvalidHash = errors.New("auth: invalid password hash format")
	// ErrIncompatibleVersion means the hash was produced by a newer argon2.
	ErrIncompatibleVersion = errors.New("auth: incompatible argon2 version")
	// ErrMismatchedPassword means the password does not match the hash.
	ErrMismatchedPassword = errors.New("auth: password does not match")
)

// HashPassword derives an Argon2id hash of password, returning it in the
// standard PHC string format:
//
//	$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
//
// Encoding the parameters alongside the digest is what makes future parameter
// changes non-breaking.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: generate salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword reports whether password matches encodedHash. It returns
// ErrMismatchedPassword when the password is simply wrong, and a different
// error when the stored hash itself is unusable, so that a corrupt record is
// not silently reported as a failed login.
func VerifyPassword(password, encodedHash string) error {
	params, salt, want, err := decodeHash(encodedHash)
	if err != nil {
		return err
	}

	got := argon2.IDKey([]byte(password), salt, params.time, params.memory, params.threads, uint32(len(want)))

	// Constant time: a timing-variable comparison would leak how much of the
	// derived key matched.
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrMismatchedPassword
	}
	return nil
}

// NeedsRehash reports whether encodedHash was produced with weaker parameters
// than the current ones. Callers can re-hash on successful login to migrate
// stored credentials forward without asking users to change anything.
func NeedsRehash(encodedHash string) bool {
	params, _, _, err := decodeHash(encodedHash)
	if err != nil {
		// An unreadable hash certainly needs replacing.
		return true
	}
	return params.memory < argonMemory ||
		params.time < argonTime ||
		params.threads < argonThreads
}

type argonParams struct {
	memory  uint32
	time    uint32
	threads uint8
}

func decodeHash(encodedHash string) (argonParams, []byte, []byte, error) {
	var params argonParams

	parts := strings.Split(encodedHash, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash
	if len(parts) != 6 || parts[0] != "" {
		return params, nil, nil, ErrInvalidHash
	}
	if parts[1] != "argon2id" {
		return params, nil, nil, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return params, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return params, nil, nil, ErrIncompatibleVersion
	}

	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d",
		&params.memory, &params.time, &params.threads); err != nil {
		return params, nil, nil, ErrInvalidHash
	}
	if params.memory == 0 || params.time == 0 || params.threads == 0 {
		// Zero parameters would make argon2.IDKey panic.
		return params, nil, nil, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return params, nil, nil, ErrInvalidHash
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) == 0 {
		return params, nil, nil, ErrInvalidHash
	}

	return params, salt, key, nil
}
