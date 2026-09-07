package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	// issuer identifies tokens minted by this service.
	issuer = "vaultly"
	// audience narrows tokens to the API, so a token minted for some other
	// purpose under the same key could not be replayed here.
	audience = "vaultly-api"
)

var (
	// ErrInvalidToken means the token is malformed, expired, or not signed by
	// this server. It is deliberately a single error: distinguishing the cases
	// to a caller would tell an attacker which part of a forgery to fix.
	ErrInvalidToken = errors.New("auth: invalid token")
)

// Claims is the payload of an access token.
type Claims struct {
	UserID uuid.UUID `json:"uid"`
	Email  string    `json:"email"`
	jwt.RegisteredClaims
}

// TokenIssuer mints and verifies short-lived access tokens.
type TokenIssuer struct {
	secret []byte
	ttl    time.Duration
	// now is injectable so tests can exercise expiry without sleeping.
	now func() time.Time
}

// NewTokenIssuer builds a TokenIssuer signing with secret.
func NewTokenIssuer(secret []byte, ttl time.Duration) *TokenIssuer {
	return &TokenIssuer{secret: secret, ttl: ttl, now: time.Now}
}

// Issue mints a signed access token for the user.
func (t *TokenIssuer) Issue(userID uuid.UUID, email string) (string, time.Time, error) {
	now := t.now()
	expiresAt := now.Add(t.ttl)

	claims := Claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			ID:        uuid.NewString(),
		},
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(t.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: sign token: %w", err)
	}
	return signed, expiresAt, nil
}

// Verify parses and validates a token, returning its claims.
func (t *TokenIssuer) Verify(tokenString string) (*Claims, error) {
	claims := &Claims{}

	_, err := jwt.ParseWithClaims(tokenString, claims,
		func(token *jwt.Token) (any, error) {
			// Pinning the algorithm is what prevents the classic "alg: none"
			// and RS256-to-HS256 confusion attacks.
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method %v", token.Header["alg"])
			}
			return t.secret, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(t.now),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if claims.UserID == uuid.Nil {
		return nil, ErrInvalidToken
	}
	return claims, nil
}
