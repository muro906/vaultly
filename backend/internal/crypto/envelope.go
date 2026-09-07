// Package crypto implements envelope encryption for secret values.
//
// Every secret version is sealed under its own randomly generated data
// encryption key (DEK). The DEK itself is sealed under a long-lived master key
// that never leaves the process. Two properties fall out of this:
//
//   - Rotating the master key only requires rewrapping the (tiny) DEKs, not
//     re-encrypting every ciphertext in the database.
//   - A compromised single DEK exposes exactly one secret version.
//
// Both layers use AES-256-GCM. The ciphertext layer additionally authenticates
// the secret's identity as associated data, so a stored ciphertext cannot be
// moved from one secret (or environment) to another without detection.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// KeySize is the required length, in bytes, of the master key and of every
// generated data encryption key.
const KeySize = 32

var (
	// ErrInvalidKeySize is returned when a key is not exactly KeySize bytes.
	ErrInvalidKeySize = errors.New("crypto: key must be exactly 32 bytes")
	// ErrDecryptFailed is returned when a ciphertext fails authentication.
	// It is deliberately opaque: callers must not be able to distinguish a
	// tampered ciphertext from a wrong key or mismatched associated data.
	ErrDecryptFailed = errors.New("crypto: decryption failed")
)

// Sealed is the complete on-disk representation of one encrypted value.
// Every field is safe to store in the database; none of them reveal the
// plaintext without the master key.
type Sealed struct {
	// WrappedDEK is the data encryption key sealed under the master key.
	// It carries its own nonce as a prefix.
	WrappedDEK []byte
	// Nonce is the GCM nonce used to seal Ciphertext under the DEK.
	Nonce []byte
	// Ciphertext is the value sealed under the DEK.
	Ciphertext []byte
}

// Keyring encrypts and decrypts values under a master key.
//
// A Keyring is safe for concurrent use: cipher.AEAD is stateless once
// constructed, and every operation generates its own nonce.
type Keyring struct {
	master cipher.AEAD
}

// NewKeyring builds a Keyring from a raw 32-byte master key.
func NewKeyring(masterKey []byte) (*Keyring, error) {
	if len(masterKey) != KeySize {
		return nil, ErrInvalidKeySize
	}
	aead, err := newAEAD(masterKey)
	if err != nil {
		return nil, err
	}
	return &Keyring{master: aead}, nil
}

// NewKeyringFromBase64 builds a Keyring from a base64-encoded master key, the
// form used by the VAULTLY_MASTER_KEY environment variable. Both standard and
// URL-safe alphabets are accepted, with or without padding.
func NewKeyringFromBase64(encoded string) (*Keyring, error) {
	key, err := decodeKey(encoded)
	if err != nil {
		return nil, err
	}
	defer Zero(key)
	return NewKeyring(key)
}

// Encrypt seals plaintext under a fresh DEK and seals that DEK under the
// master key. aad binds the result to a particular secret; the same value must
// be supplied to Decrypt. Use SecretAAD to build it.
//
// plaintext is not modified; callers own zeroing it.
func (k *Keyring) Encrypt(plaintext, aad []byte) (*Sealed, error) {
	dek := make([]byte, KeySize)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("crypto: generate data key: %w", err)
	}
	defer Zero(dek)

	dekAEAD, err := newAEAD(dek)
	if err != nil {
		return nil, err
	}

	nonce, err := newNonce(dekAEAD.NonceSize())
	if err != nil {
		return nil, err
	}
	ciphertext := dekAEAD.Seal(nil, nonce, plaintext, aad)

	wrapped, err := k.wrap(dek)
	if err != nil {
		return nil, err
	}

	return &Sealed{WrappedDEK: wrapped, Nonce: nonce, Ciphertext: ciphertext}, nil
}

// Decrypt unwraps the DEK and opens the ciphertext. aad must match the value
// passed to Encrypt exactly, otherwise ErrDecryptFailed is returned.
func (k *Keyring) Decrypt(sealed *Sealed, aad []byte) ([]byte, error) {
	if sealed == nil {
		return nil, ErrDecryptFailed
	}

	dek, err := k.unwrap(sealed.WrappedDEK)
	if err != nil {
		return nil, err
	}
	defer Zero(dek)

	dekAEAD, err := newAEAD(dek)
	if err != nil {
		return nil, err
	}
	if len(sealed.Nonce) != dekAEAD.NonceSize() {
		return nil, ErrDecryptFailed
	}

	plaintext, err := dekAEAD.Open(nil, sealed.Nonce, sealed.Ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return plaintext, nil
}

// Rewrap re-encrypts a sealed value's DEK under next without touching the
// ciphertext. This is what makes master key rotation cheap: the returned
// Sealed decrypts to the same plaintext under the new keyring, and the
// (potentially large) ciphertext is never rewritten.
//
// The AAD is unchanged by rotation, so it is not needed here.
func (k *Keyring) Rewrap(sealed *Sealed, next *Keyring) (*Sealed, error) {
	if sealed == nil || next == nil {
		return nil, ErrDecryptFailed
	}

	dek, err := k.unwrap(sealed.WrappedDEK)
	if err != nil {
		return nil, err
	}
	defer Zero(dek)

	wrapped, err := next.wrap(dek)
	if err != nil {
		return nil, err
	}

	return &Sealed{
		WrappedDEK: wrapped,
		Nonce:      sealed.Nonce,
		Ciphertext: sealed.Ciphertext,
	}, nil
}

// wrap seals a DEK under the master key, prefixing the nonce so that the
// wrapped key is a single self-contained blob.
func (k *Keyring) wrap(dek []byte) ([]byte, error) {
	nonce, err := newNonce(k.master.NonceSize())
	if err != nil {
		return nil, err
	}
	// Seal appends to nonce, producing nonce||ciphertext in one allocation.
	return k.master.Seal(nonce, nonce, dek, nil), nil
}

// unwrap reverses wrap.
func (k *Keyring) unwrap(wrapped []byte) ([]byte, error) {
	ns := k.master.NonceSize()
	if len(wrapped) < ns+k.master.Overhead() {
		return nil, ErrDecryptFailed
	}
	dek, err := k.master.Open(nil, wrapped[:ns], wrapped[ns:], nil)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	if len(dek) != KeySize {
		Zero(dek)
		return nil, ErrDecryptFailed
	}
	return dek, nil
}

// SecretAAD builds the associated data that binds a ciphertext to one secret
// in one environment. Changing any component invalidates every ciphertext
// written under the old value, which is exactly the intent: a row copied to a
// different environment or renamed to a different key will not decrypt.
//
// The separator is a NUL byte so that component boundaries are unambiguous
// (identifiers and keys cannot contain NUL).
func SecretAAD(projectID, environmentID, key string) []byte {
	aad := make([]byte, 0, len(projectID)+len(environmentID)+len(key)+2)
	aad = append(aad, projectID...)
	aad = append(aad, 0)
	aad = append(aad, environmentID...)
	aad = append(aad, 0)
	aad = append(aad, key...)
	return aad
}

// Zero overwrites b with zeroes. Callers should defer it for any buffer that
// held plaintext or key material, to shorten the window in which that material
// is recoverable from process memory.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// GenerateMasterKey returns a new base64-encoded master key, suitable for
// VAULTLY_MASTER_KEY.
func GenerateMasterKey() (string, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("crypto: generate master key: %w", err)
	}
	defer Zero(key)
	return base64.StdEncoding.EncodeToString(key), nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new gcm: %w", err)
	}
	return aead, nil
}

func newNonce(size int) ([]byte, error) {
	nonce := make([]byte, size)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: generate nonce: %w", err)
	}
	return nonce, nil
}

// decodeKey accepts the four base64 alphabets a user might paste in.
func decodeKey(encoded string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		if key, err := enc.DecodeString(encoded); err == nil {
			return key, nil
		}
	}
	return nil, errors.New("crypto: master key is not valid base64")
}
