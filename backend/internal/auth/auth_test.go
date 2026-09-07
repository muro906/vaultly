package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// --- Passwords -------------------------------------------------------------

func TestHashAndVerifyPassword(t *testing.T) {
	const password = "correct horse battery staple"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if strings.Contains(hash, password) {
		t.Fatal("hash contains the password")
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("unexpected hash format: %s", hash)
	}

	if err := VerifyPassword(password, hash); err != nil {
		t.Errorf("verify correct password: %v", err)
	}
	if err := VerifyPassword("wrong password", hash); !errors.Is(err, ErrMismatchedPassword) {
		t.Errorf("verify wrong password: got %v, want ErrMismatchedPassword", err)
	}
}

func TestHashPasswordIsSalted(t *testing.T) {
	const password = "same password"

	first, err := HashPassword(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	second, err := HashPassword(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	// Without a per-hash salt, identical passwords would be visibly identical
	// in the users table.
	if first == second {
		t.Fatal("hashing the same password twice produced the same hash")
	}
	for _, hash := range []string{first, second} {
		if err := VerifyPassword(password, hash); err != nil {
			t.Errorf("verify: %v", err)
		}
	}
}

func TestVerifyPasswordEdgeCases(t *testing.T) {
	// Empty and very long passwords must both work rather than panic.
	for _, password := range []string{"", strings.Repeat("x", 4096), "üñïçø∂é 🔑"} {
		hash, err := HashPassword(password)
		if err != nil {
			t.Fatalf("hash %q: %v", truncate(password), err)
		}
		if err := VerifyPassword(password, hash); err != nil {
			t.Errorf("verify %q: %v", truncate(password), err)
		}
		if err := VerifyPassword(password+"x", hash); !errors.Is(err, ErrMismatchedPassword) {
			t.Errorf("verify %q with suffix: got %v, want mismatch", truncate(password), err)
		}
	}
}

func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	// A corrupt stored hash must be reported as such, not as a wrong password:
	// otherwise a database problem looks like a user error forever.
	malformed := map[string]string{
		"empty":           "",
		"not phc":         "just-a-string",
		"too few parts":   "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA",
		"wrong algorithm": "$argon2i$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA",
		"bad version":     "$argon2id$v=abc$m=19456,t=2,p=1$c2FsdA$aGFzaA",
		"bad params":      "$argon2id$v=19$m=abc,t=2,p=1$c2FsdA$aGFzaA",
		"zero params":     "$argon2id$v=19$m=0,t=0,p=0$c2FsdA$aGFzaA",
		"bad salt base64": "$argon2id$v=19$m=19456,t=2,p=1$!!!$aGFzaA",
		"bad hash base64": "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$!!!",
		"empty salt":      "$argon2id$v=19$m=19456,t=2,p=1$$aGFzaA",
	}

	for name, hash := range malformed {
		t.Run(name, func(t *testing.T) {
			err := VerifyPassword("password", hash)
			if err == nil {
				t.Fatal("expected an error")
			}
			if errors.Is(err, ErrMismatchedPassword) {
				t.Fatalf("malformed hash reported as a password mismatch: %v", err)
			}
		})
	}
}

func TestVerifyPasswordRejectsIncompatibleVersion(t *testing.T) {
	err := VerifyPassword("password", "$argon2id$v=18$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g")
	if !errors.Is(err, ErrIncompatibleVersion) {
		t.Fatalf("got %v, want ErrIncompatibleVersion", err)
	}
}

func TestNeedsRehash(t *testing.T) {
	current, err := HashPassword("password")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if NeedsRehash(current) {
		t.Error("a freshly created hash must not need rehashing")
	}

	// A hash created under weaker parameters should be upgraded on next login.
	weak := "$argon2id$v=19$m=4096,t=1,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNo"
	if !NeedsRehash(weak) {
		t.Error("a hash with weaker parameters must need rehashing")
	}
	if !NeedsRehash("garbage") {
		t.Error("an unreadable hash must need rehashing")
	}
}

func truncate(s string) string {
	if len(s) > 20 {
		return s[:20] + "..."
	}
	return s
}

// --- Access tokens (JWT) ---------------------------------------------------

func TestIssueAndVerifyToken(t *testing.T) {
	issuer := NewTokenIssuer([]byte(strings.Repeat("k", 32)), 15*time.Minute)
	userID := uuid.New()

	token, expiresAt, err := issuer.Issue(userID, "user@example.com")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !expiresAt.After(time.Now()) {
		t.Error("token expires in the past")
	}

	claims, err := issuer.Verify(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.UserID != userID {
		t.Errorf("UserID = %s, want %s", claims.UserID, userID)
	}
	if claims.Email != "user@example.com" {
		t.Errorf("Email = %q, want user@example.com", claims.Email)
	}
	if claims.Subject != userID.String() {
		t.Errorf("Subject = %q, want %s", claims.Subject, userID)
	}
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	issuer := NewTokenIssuer([]byte(strings.Repeat("k", 32)), time.Minute)

	token, _, err := issuer.Issue(uuid.New(), "user@example.com")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Advance the issuer's clock past expiry rather than sleeping.
	issuer.now = func() time.Time { return time.Now().Add(2 * time.Minute) }

	if _, err := issuer.Verify(token); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

func TestVerifyRejectsWrongSigningKey(t *testing.T) {
	minter := NewTokenIssuer([]byte(strings.Repeat("a", 32)), time.Minute)
	verifier := NewTokenIssuer([]byte(strings.Repeat("b", 32)), time.Minute)

	token, _, err := minter.Issue(uuid.New(), "user@example.com")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := verifier.Verify(token); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

func TestVerifyRejectsUnsignedToken(t *testing.T) {
	secret := []byte(strings.Repeat("k", 32))
	issuer := NewTokenIssuer(secret, time.Minute)

	// The "alg: none" attack: a token whose signature is simply omitted. It
	// must be rejected because the issuer pins HS256.
	claims := Claims{
		UserID: uuid.New(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "vaultly",
			Audience:  jwt.ClaimStrings{"vaultly-api"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).
		SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("build unsigned token: %v", err)
	}

	if _, err := issuer.Verify(unsigned); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("unsigned token accepted: %v", err)
	}
}

func TestVerifyRejectsWrongAudienceAndIssuer(t *testing.T) {
	secret := []byte(strings.Repeat("k", 32))
	issuer := NewTokenIssuer(secret, time.Minute)

	// Correctly signed with our key, but minted for a different service. A
	// token from a sibling system sharing the key must not work here.
	cases := map[string]jwt.RegisteredClaims{
		"wrong audience": {
			Issuer:    "vaultly",
			Audience:  jwt.ClaimStrings{"some-other-api"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		"wrong issuer": {
			Issuer:    "somebody-else",
			Audience:  jwt.ClaimStrings{"vaultly-api"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		"no expiry": {
			Issuer:   "vaultly",
			Audience: jwt.ClaimStrings{"vaultly-api"},
		},
	}

	for name, registered := range cases {
		t.Run(name, func(t *testing.T) {
			token, err := jwt.NewWithClaims(jwt.SigningMethodHS256,
				Claims{UserID: uuid.New(), RegisteredClaims: registered}).SignedString(secret)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if _, err := issuer.Verify(token); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("got %v, want ErrInvalidToken", err)
			}
		})
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	issuer := NewTokenIssuer([]byte(strings.Repeat("k", 32)), time.Minute)

	for _, token := range []string{"", "not.a.token", "a.b.c", "Bearer something"} {
		if _, err := issuer.Verify(token); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("token %q: got %v, want ErrInvalidToken", token, err)
		}
	}
}

// --- Opaque tokens ---------------------------------------------------------

func TestGenerateAccessToken(t *testing.T) {
	token, err := GenerateAccessToken()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if !strings.HasPrefix(token.Plaintext, TokenPrefix+"_") {
		t.Errorf("token %q does not start with the vlt_ marker", token.Plaintext)
	}
	if len(token.Hash) != 32 {
		t.Errorf("hash length = %d, want 32", len(token.Hash))
	}
	// The stored prefix must genuinely be a prefix of the token, so the UI can
	// match a displayed identifier to a real credential.
	if !strings.Contains(token.Plaintext, token.Prefix) {
		t.Errorf("token %q does not contain its prefix %q", token.Plaintext, token.Prefix)
	}
	// The digest must not be derivable from what is stored in plaintext.
	if strings.Contains(string(token.Hash), token.Plaintext) {
		t.Error("hash contains the plaintext")
	}

	parsed, err := ParseTokenPrefix(token.Plaintext)
	if err != nil {
		t.Fatalf("parse prefix: %v", err)
	}
	if parsed != token.Prefix {
		t.Errorf("parsed prefix = %q, want %q", parsed, token.Prefix)
	}
}

func TestGenerateAccessTokenIsUnique(t *testing.T) {
	seen := make(map[string]bool, 500)
	for i := 0; i < 500; i++ {
		token, err := GenerateAccessToken()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if seen[token.Plaintext] {
			t.Fatalf("duplicate token generated after %d iterations", i)
		}
		seen[token.Plaintext] = true
	}
}

func TestHashTokenIsStable(t *testing.T) {
	const plaintext = "vlt_abcdefgh_secret"

	first := HashToken(plaintext)
	second := HashToken(plaintext)

	if !CompareTokenHash(first, second) {
		t.Fatal("hashing the same token twice produced different digests")
	}
	if CompareTokenHash(first, HashToken(plaintext+"x")) {
		t.Fatal("different tokens produced the same digest")
	}
}

func TestParseTokenPrefixRejectsMalformed(t *testing.T) {
	malformed := []string{
		"",
		"vlt",
		"vlt_abcdefgh",
		"xxx_abcdefgh_secret", // wrong marker
		"vlt_short_secret",    // prefix too short
		"vlt_abcdefgh_",       // empty secret
	}

	for _, token := range malformed {
		if _, err := ParseTokenPrefix(token); !errors.Is(err, ErrMalformedToken) {
			t.Errorf("token %q: got %v, want ErrMalformedToken", token, err)
		}
	}

	// The secret half is base64url and may legitimately contain underscores,
	// so parsing must not treat them as extra fields.
	prefix, err := ParseTokenPrefix("vlt_abcdefgh_secret_with_underscores")
	if err != nil {
		t.Fatalf("token with underscores in the secret: %v", err)
	}
	if prefix != "abcdefgh" {
		t.Errorf("prefix = %q, want abcdefgh", prefix)
	}
}

func TestGeneratedTokenPrefixHasNoSeparator(t *testing.T) {
	// The prefix must never contain the field separator, otherwise parsing
	// would attribute part of it to the secret. Hex encoding guarantees this;
	// this test locks the guarantee in.
	for i := 0; i < 200; i++ {
		token, err := GenerateAccessToken()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if strings.Contains(token.Prefix, "_") {
			t.Fatalf("prefix %q contains the field separator", token.Prefix)
		}
		parsed, err := ParseTokenPrefix(token.Plaintext)
		if err != nil {
			t.Fatalf("parse %q: %v", token.Plaintext, err)
		}
		if parsed != token.Prefix {
			t.Fatalf("parsed prefix %q, want %q (token %q)", parsed, token.Prefix, token.Plaintext)
		}
	}
}

func TestGenerateRefreshToken(t *testing.T) {
	first, err := GenerateRefreshToken()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	second, err := GenerateRefreshToken()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if first.Plaintext == second.Plaintext {
		t.Fatal("generated the same refresh token twice")
	}
	if len(first.Hash) != 32 {
		t.Errorf("hash length = %d, want 32", len(first.Hash))
	}
	if !CompareTokenHash(first.Hash, HashToken(first.Plaintext)) {
		t.Error("stored hash does not match a fresh hash of the plaintext")
	}
}

func TestCompareTokenHash(t *testing.T) {
	a := HashToken("token-a")
	b := HashToken("token-b")

	if !CompareTokenHash(a, a) {
		t.Error("identical digests must compare equal")
	}
	if CompareTokenHash(a, b) {
		t.Error("different digests must not compare equal")
	}
	if CompareTokenHash(a, nil) {
		t.Error("a digest must not equal nil")
	}
	if CompareTokenHash(a, a[:16]) {
		t.Error("a digest must not equal a truncation of itself")
	}
}
