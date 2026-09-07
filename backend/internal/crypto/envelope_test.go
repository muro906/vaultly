package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
)

func testKeyring(t *testing.T) *Keyring {
	t.Helper()
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kr, err := NewKeyring(key)
	if err != nil {
		t.Fatalf("new keyring: %v", err)
	}
	return kr
}

func TestNewKeyringRejectsWrongKeySize(t *testing.T) {
	for _, size := range []int{0, 1, 16, 24, 31, 33, 64} {
		if _, err := NewKeyring(make([]byte, size)); !errors.Is(err, ErrInvalidKeySize) {
			t.Errorf("size %d: got %v, want ErrInvalidKeySize", size, err)
		}
	}
}

func TestNewKeyringFromBase64(t *testing.T) {
	raw := make([]byte, KeySize)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Every base64 flavour a user might paste must be accepted.
	for name, encoded := range map[string]string{
		"std":    base64.StdEncoding.EncodeToString(raw),
		"rawStd": base64.RawStdEncoding.EncodeToString(raw),
		"url":    base64.URLEncoding.EncodeToString(raw),
		"rawURL": base64.RawURLEncoding.EncodeToString(raw),
	} {
		if _, err := NewKeyringFromBase64(encoded); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	if _, err := NewKeyringFromBase64("not valid base64!!"); err == nil {
		t.Error("expected error for non-base64 input")
	}
	// Correctly encoded but the wrong length.
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	if _, err := NewKeyringFromBase64(short); !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("short key: got %v, want ErrInvalidKeySize", err)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	kr := testKeyring(t)
	aad := SecretAAD("proj-1", "env-1", "DATABASE_URL")

	cases := map[string][]byte{
		"empty":     {},
		"short":     []byte("hunter2"),
		"unicode":   []byte("pässwörd-🔐-ünïcode"),
		"multiline": []byte("-----BEGIN KEY-----\nabc\ndef\n-----END KEY-----"),
		"large":     bytes.Repeat([]byte("a"), 64*1024),
	}

	for name, plaintext := range cases {
		t.Run(name, func(t *testing.T) {
			sealed, err := kr.Encrypt(plaintext, aad)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			if bytes.Contains(sealed.Ciphertext, plaintext) && len(plaintext) > 0 {
				t.Fatal("ciphertext contains the plaintext")
			}

			got, err := kr.Decrypt(sealed, aad)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("round trip mismatch: got %q, want %q", got, plaintext)
			}
		})
	}
}

func TestEncryptIsNonDeterministic(t *testing.T) {
	kr := testKeyring(t)
	aad := SecretAAD("p", "e", "K")
	plaintext := []byte("same value every time")

	first, err := kr.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	second, err := kr.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Fresh DEK and fresh nonce each time, so nothing may repeat. Otherwise an
	// observer with only database access could tell which secrets share a value.
	if bytes.Equal(first.Ciphertext, second.Ciphertext) {
		t.Error("ciphertext repeated across encryptions")
	}
	if bytes.Equal(first.Nonce, second.Nonce) {
		t.Error("nonce repeated across encryptions")
	}
	if bytes.Equal(first.WrappedDEK, second.WrappedDEK) {
		t.Error("wrapped DEK repeated across encryptions")
	}
}

func TestDecryptRejectsTampering(t *testing.T) {
	kr := testKeyring(t)
	aad := SecretAAD("proj-1", "env-1", "API_KEY")
	plaintext := []byte("super-secret-value")

	seal := func(t *testing.T) *Sealed {
		t.Helper()
		s, err := kr.Encrypt(plaintext, aad)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		return s
	}

	mutations := map[string]func(*Sealed){
		"flip ciphertext bit": func(s *Sealed) { s.Ciphertext[0] ^= 0x01 },
		"flip last byte":      func(s *Sealed) { s.Ciphertext[len(s.Ciphertext)-1] ^= 0x80 },
		"flip nonce bit":      func(s *Sealed) { s.Nonce[0] ^= 0x01 },
		"flip wrapped DEK":    func(s *Sealed) { s.WrappedDEK[len(s.WrappedDEK)-1] ^= 0x01 },
		"truncate ciphertext": func(s *Sealed) { s.Ciphertext = s.Ciphertext[:len(s.Ciphertext)-1] },
		"truncate nonce":      func(s *Sealed) { s.Nonce = s.Nonce[:len(s.Nonce)-1] },
		"empty wrapped DEK":   func(s *Sealed) { s.WrappedDEK = nil },
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			sealed := seal(t)
			mutate(sealed)
			if _, err := kr.Decrypt(sealed, aad); !errors.Is(err, ErrDecryptFailed) {
				t.Fatalf("got %v, want ErrDecryptFailed", err)
			}
		})
	}

	t.Run("nil sealed", func(t *testing.T) {
		if _, err := kr.Decrypt(nil, aad); !errors.Is(err, ErrDecryptFailed) {
			t.Fatalf("got %v, want ErrDecryptFailed", err)
		}
	})
}

func TestDecryptRejectsWrongAAD(t *testing.T) {
	kr := testKeyring(t)
	plaintext := []byte("prod-database-password")
	original := SecretAAD("proj-1", "env-prod", "DB_PASSWORD")

	sealed, err := kr.Encrypt(plaintext, original)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Each of these represents an attacker (or a bug) moving a ciphertext row
	// somewhere it does not belong. All must fail closed.
	wrong := map[string][]byte{
		"different project":     SecretAAD("proj-2", "env-prod", "DB_PASSWORD"),
		"different environment": SecretAAD("proj-1", "env-dev", "DB_PASSWORD"),
		"different key":         SecretAAD("proj-1", "env-prod", "DB_PASSWORD_OLD"),
		"no aad":                nil,
	}

	for name, aad := range wrong {
		t.Run(name, func(t *testing.T) {
			if _, err := kr.Decrypt(sealed, aad); !errors.Is(err, ErrDecryptFailed) {
				t.Fatalf("got %v, want ErrDecryptFailed", err)
			}
		})
	}

	// Sanity check: the correct AAD still works after all those failures.
	if _, err := kr.Decrypt(sealed, original); err != nil {
		t.Fatalf("correct aad: %v", err)
	}
}

func TestSecretAADIsUnambiguous(t *testing.T) {
	// Without a delimiter these two would collide, letting a ciphertext be
	// moved between secrets whose concatenated identifiers happen to match.
	a := SecretAAD("ab", "c", "d")
	b := SecretAAD("a", "bc", "d")
	if bytes.Equal(a, b) {
		t.Fatal("distinct identifier triples produced identical associated data")
	}
}

func TestDecryptWithDifferentMasterKeyFails(t *testing.T) {
	first, second := testKeyring(t), testKeyring(t)
	aad := SecretAAD("p", "e", "K")

	sealed, err := first.Encrypt([]byte("value"), aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := second.Decrypt(sealed, aad); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("got %v, want ErrDecryptFailed", err)
	}
}

func TestRewrapRotatesMasterKey(t *testing.T) {
	old, next := testKeyring(t), testKeyring(t)
	aad := SecretAAD("proj-1", "env-1", "TOKEN")
	plaintext := []byte("value that must survive rotation")

	sealed, err := old.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	rotated, err := old.Rewrap(sealed, next)
	if err != nil {
		t.Fatalf("rewrap: %v", err)
	}

	// The whole point of envelope encryption: the ciphertext is untouched, so
	// rotation is O(size of key material), not O(size of data).
	if !bytes.Equal(rotated.Ciphertext, sealed.Ciphertext) {
		t.Error("rewrap rewrote the ciphertext")
	}
	if !bytes.Equal(rotated.Nonce, sealed.Nonce) {
		t.Error("rewrap changed the nonce")
	}
	if bytes.Equal(rotated.WrappedDEK, sealed.WrappedDEK) {
		t.Error("rewrap did not change the wrapped DEK")
	}

	got, err := next.Decrypt(rotated, aad)
	if err != nil {
		t.Fatalf("decrypt after rotation: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %q, want %q", got, plaintext)
	}

	// The retired key must no longer open the rotated value.
	if _, err := old.Decrypt(rotated, aad); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("old keyring: got %v, want ErrDecryptFailed", err)
	}
}

func TestRewrapWithWrongSourceKeyFails(t *testing.T) {
	owner, stranger, next := testKeyring(t), testKeyring(t), testKeyring(t)
	aad := SecretAAD("p", "e", "K")

	sealed, err := owner.Encrypt([]byte("value"), aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := stranger.Rewrap(sealed, next); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("got %v, want ErrDecryptFailed", err)
	}
}

func TestZero(t *testing.T) {
	b := []byte("sensitive")
	Zero(b)
	for i, c := range b {
		if c != 0 {
			t.Fatalf("byte %d not zeroed: %d", i, c)
		}
	}
	Zero(nil) // must not panic
}

func TestGenerateMasterKey(t *testing.T) {
	first, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(first)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(raw) != KeySize {
		t.Fatalf("got %d bytes, want %d", len(raw), KeySize)
	}

	second, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if first == second {
		t.Fatal("generated the same key twice")
	}

	// The generated key must be directly usable as VAULTLY_MASTER_KEY.
	if _, err := NewKeyringFromBase64(first); err != nil {
		t.Fatalf("generated key rejected: %v", err)
	}
}

func TestKeyringIsSafeForConcurrentUse(t *testing.T) {
	kr := testKeyring(t)
	const goroutines = 32

	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := "SECRET_" + strings.Repeat("X", i)
			aad := SecretAAD("proj", "env", key)
			plaintext := []byte(key + "-value")

			sealed, err := kr.Encrypt(plaintext, aad)
			if err != nil {
				errs <- err
				return
			}
			got, err := kr.Decrypt(sealed, aad)
			if err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(got, plaintext) {
				errs <- errors.New("round trip mismatch under concurrency")
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	key := make([]byte, KeySize)
	rand.Read(key) //nolint:errcheck // rand.Read on a fixed buffer does not fail in practice
	kr, _ := NewKeyring(key)
	aad := SecretAAD("proj", "env", "KEY")
	plaintext := []byte("a-reasonably-sized-secret-value-for-benchmarking")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := kr.Encrypt(plaintext, aad); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key := make([]byte, KeySize)
	rand.Read(key) //nolint:errcheck // rand.Read on a fixed buffer does not fail in practice
	kr, _ := NewKeyring(key)
	aad := SecretAAD("proj", "env", "KEY")
	sealed, _ := kr.Encrypt([]byte("a-reasonably-sized-secret-value-for-benchmarking"), aad)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := kr.Decrypt(sealed, aad); err != nil {
			b.Fatal(err)
		}
	}
}
