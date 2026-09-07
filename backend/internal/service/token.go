package service

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"vaultly/backend/internal/auth"
	"vaultly/backend/internal/db/sqlcgen"
	"vaultly/backend/internal/domain"
)

// Rate limit bounds for a token, in requests per minute.
const (
	defaultRateLimitRPM = 60
	maxRateLimitRPM     = 10_000
)

// TokenService mints, lists and revokes machine access tokens.
type TokenService struct {
	store    *Store
	authz    *Authorizer
	secrets  *SecretService
	projects *ProjectService
	audit    *AuditRecorder
}

// NewTokenService builds a TokenService.
func NewTokenService(store *Store, authz *Authorizer, secrets *SecretService, projects *ProjectService, audit *AuditRecorder) *TokenService {
	return &TokenService{store: store, authz: authz, secrets: secrets, projects: projects, audit: audit}
}

// CreateTokenInput is the payload for minting a token.
type CreateTokenInput struct {
	ProjectID     uuid.UUID
	EnvironmentID uuid.UUID
	Name          string
	Scopes        []domain.TokenScope
	// IPAllowlist restricts which addresses may use the token. Entries may be
	// bare addresses or CIDR blocks. Empty means any address.
	IPAllowlist  []string
	RateLimitRPM int32
	ExpiresAt    *time.Time
	Actor        Actor
}

// Create mints a token scoped to one project and environment.
//
// The plaintext token is returned exactly once, on this response. Only its
// digest is stored, so a lost token cannot be recovered and must be replaced.
func (s *TokenService) Create(ctx context.Context, userID uuid.UUID, in CreateTokenInput) (*domain.AccessToken, error) {
	scope, err := s.authz.RequireProjectRole(ctx, userID, in.ProjectID, domain.RoleAdmin)
	if err != nil {
		return nil, err
	}

	// The environment must belong to the project the token is scoped to,
	// otherwise a token could be pointed at another project's environment.
	environment, err := s.projects.resolveEnvironment(ctx, in.ProjectID, in.EnvironmentID)
	if err != nil {
		return nil, err
	}

	v := &domain.ValidationError{}
	name := validateName(v, "name", in.Name)

	if len(in.Scopes) == 0 {
		v.Add("scopes", "at least one scope is required")
	}
	scopes := make([]string, 0, len(in.Scopes))
	for _, tokenScope := range in.Scopes {
		if !tokenScope.Valid() {
			v.Add("scopes", fmt.Sprintf("%q is not a recognised scope", tokenScope))
			continue
		}
		scopes = append(scopes, string(tokenScope))
	}

	allowlist, err := ParseIPAllowlist(in.IPAllowlist)
	if err != nil {
		v.Add("ipAllowlist", err.Error())
	}

	rateLimit := in.RateLimitRPM
	if rateLimit == 0 {
		rateLimit = defaultRateLimitRPM
	}
	if rateLimit < 1 || rateLimit > maxRateLimitRPM {
		v.Add("rateLimitRpm", fmt.Sprintf("must be between 1 and %d", maxRateLimitRPM))
	}

	if in.ExpiresAt != nil && !in.ExpiresAt.After(time.Now()) {
		v.Add("expiresAt", "must be in the future")
	}

	if err := v.ErrorOrNil(); err != nil {
		return nil, err
	}

	generated, err := auth.GenerateAccessToken()
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	allowlistText := make([]string, 0, len(allowlist))
	for _, prefix := range allowlist {
		allowlistText = append(allowlistText, prefix.String())
	}

	row, err := s.store.Queries().CreateAccessToken(ctx, sqlcgen.CreateAccessTokenParams{
		ProjectID:     in.ProjectID,
		EnvironmentID: in.EnvironmentID,
		Name:          name,
		TokenHash:     generated.Hash,
		Prefix:        generated.Prefix,
		Scopes:        scopes,
		IpAllowlist:   allowlistText,
		RateLimitRpm:  rateLimit,
		ExpiresAt:     in.ExpiresAt,
		CreatedBy:     &userID,
	})
	if err != nil {
		return nil, translateDBError(err, "create access token")
	}

	s.audit.Record(Event{
		WorkspaceID:  scope.WorkspaceID,
		Actor:        in.Actor,
		Action:       domain.ActionTokenCreated,
		ResourceType: "token",
		ResourceID:   &row.ID,
		Metadata: map[string]any{
			"name":        name,
			"prefix":      generated.Prefix,
			"environment": environment.Name,
			"scopes":      scopes,
		},
	})

	token := accessTokenFromRow(accessTokenRow{
		ID:            row.ID,
		ProjectID:     row.ProjectID,
		EnvironmentID: row.EnvironmentID,
		Name:          row.Name,
		Prefix:        row.Prefix,
		Scopes:        row.Scopes,
		IpAllowlist:   row.IpAllowlist,
		RateLimitRpm:  row.RateLimitRpm,
		ExpiresAt:     row.ExpiresAt,
		RevokedAt:     row.RevokedAt,
		LastUsedAt:    row.LastUsedAt,
		CreatedAt:     row.CreatedAt,
		CreatedBy:     row.CreatedBy,
	})
	token.Plaintext = generated.Plaintext
	return token, nil
}

// List returns a project's tokens. Digests are never included.
func (s *TokenService) List(ctx context.Context, userID, projectID uuid.UUID) ([]domain.AccessToken, error) {
	if _, err := s.authz.RequireProjectRole(ctx, userID, projectID, domain.RoleAdmin); err != nil {
		return nil, err
	}

	rows, err := s.store.Queries().ListAccessTokens(ctx, projectID)
	if err != nil {
		return nil, translateDBError(err, "list access tokens")
	}

	tokens := make([]domain.AccessToken, 0, len(rows))
	for _, row := range rows {
		tokens = append(tokens, *accessTokenFromRow(accessTokenRow{
			ID:            row.ID,
			ProjectID:     row.ProjectID,
			EnvironmentID: row.EnvironmentID,
			Name:          row.Name,
			Prefix:        row.Prefix,
			Scopes:        row.Scopes,
			IpAllowlist:   row.IpAllowlist,
			RateLimitRpm:  row.RateLimitRpm,
			ExpiresAt:     row.ExpiresAt,
			RevokedAt:     row.RevokedAt,
			LastUsedAt:    row.LastUsedAt,
			CreatedAt:     row.CreatedAt,
			CreatedBy:     row.CreatedBy,
		}))
	}
	return tokens, nil
}

// Revoke disables a token immediately.
func (s *TokenService) Revoke(ctx context.Context, userID, tokenID uuid.UUID, actor Actor) error {
	scope, err := s.authz.RequireTokenRole(ctx, userID, tokenID, domain.RoleAdmin)
	if err != nil {
		return err
	}

	if _, err := s.store.Queries().RevokeAccessToken(ctx, tokenID); err != nil {
		if isNoRows(err) {
			// Already revoked. The desired state holds, so this is a success.
			return nil
		}
		return translateDBError(err, "revoke access token")
	}

	s.audit.Record(Event{
		WorkspaceID:  scope.WorkspaceID,
		Actor:        actor,
		Action:       domain.ActionTokenRevoked,
		ResourceType: "token",
		ResourceID:   &tokenID,
	})
	return nil
}

// AuthenticatedToken is a validated machine credential together with the
// workspace it belongs to.
type AuthenticatedToken struct {
	Token       domain.AccessToken
	WorkspaceID uuid.UUID
}

// Authenticate validates a presented token string.
//
// Checks run in order of cost: shape, then digest lookup, then revocation and
// expiry, then the IP allowlist. Rate limiting is applied by the middleware
// once the token is known, since the limit is per token.
func (s *TokenService) Authenticate(ctx context.Context, plaintext string, clientIP netip.Addr) (*AuthenticatedToken, error) {
	if _, err := auth.ParseTokenPrefix(plaintext); err != nil {
		return nil, domain.ErrUnauthenticated
	}

	row, err := s.store.Queries().GetAccessTokenByHash(ctx, auth.HashToken(plaintext))
	if err != nil {
		if isNoRows(err) {
			return nil, domain.ErrUnauthenticated
		}
		return nil, translateDBError(err, "look up access token")
	}

	token := accessTokenFromRow(accessTokenRow{
		ID:            row.ID,
		ProjectID:     row.ProjectID,
		EnvironmentID: row.EnvironmentID,
		Name:          row.Name,
		Prefix:        row.Prefix,
		Scopes:        row.Scopes,
		IpAllowlist:   row.IpAllowlist,
		RateLimitRpm:  row.RateLimitRpm,
		ExpiresAt:     row.ExpiresAt,
		RevokedAt:     row.RevokedAt,
		LastUsedAt:    row.LastUsedAt,
		CreatedAt:     row.CreatedAt,
		CreatedBy:     row.CreatedBy,
	})

	if !token.Active(time.Now()) {
		return nil, domain.ErrUnauthenticated
	}

	// A revoked or expired token is unauthenticated, but a live token from the
	// wrong network is forbidden: the credential is real, the origin is not.
	if !token.AllowsIP(clientIP) {
		return nil, fmt.Errorf("address %s is not in this token's allowlist: %w", clientIP, domain.ErrForbidden)
	}

	return &AuthenticatedToken{Token: *token, WorkspaceID: row.WorkspaceID}, nil
}

// Touch records that a token was used. Failures are the caller's to ignore:
// this is bookkeeping, not authorisation.
func (s *TokenService) Touch(ctx context.Context, tokenID uuid.UUID) error {
	return s.store.Queries().TouchAccessToken(ctx, tokenID)
}

// PullSecrets returns every current value in the token's environment.
//
// This is the CI/CD entry point. The token's own scope determines what it can
// reach, so there is no user and no role involved.
func (s *TokenService) PullSecrets(ctx context.Context, token *AuthenticatedToken, actor Actor) (map[string]string, error) {
	if !token.Token.HasScope(domain.ScopeSecretsRead) {
		return nil, fmt.Errorf("token lacks the %s scope: %w", domain.ScopeSecretsRead, domain.ErrForbidden)
	}

	resolved, err := s.secrets.resolveEnvironmentValues(ctx, token.Token.ProjectID, token.Token.EnvironmentID)
	if err != nil {
		return nil, err
	}

	values := make(map[string]string, len(resolved))
	keys := make([]string, 0, len(resolved))
	for _, secret := range resolved {
		values[secret.Key] = secret.Value
		keys = append(keys, secret.Key)
	}

	s.audit.Record(Event{
		WorkspaceID:  token.WorkspaceID,
		Actor:        actor,
		Action:       domain.ActionSecretsPulled,
		ResourceType: "environment",
		ResourceID:   &token.Token.EnvironmentID,
		Metadata:     map[string]any{"count": len(values), "keys": keys},
	})

	return values, nil
}

// ParseIPAllowlist converts user-supplied entries into prefixes. A bare
// address is treated as a single-host prefix, so "203.0.113.4" and
// "203.0.113.4/32" mean the same thing.
func ParseIPAllowlist(entries []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(entries))

	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}

		if strings.Contains(entry, "/") {
			prefix, err := netip.ParsePrefix(entry)
			if err != nil {
				return nil, fmt.Errorf("%q is not a valid CIDR block", entry)
			}
			// Masking discards host bits, so 10.0.0.5/8 is stored as 10.0.0.0/8
			// and matches the range the user meant.
			prefixes = append(prefixes, prefix.Masked())
			continue
		}

		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, fmt.Errorf("%q is not a valid IP address or CIDR block", entry)
		}
		addr = addr.Unmap()
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}

	return prefixes, nil
}

// accessTokenRow is the shape shared by the several generated row types for
// tokens, so they can be converted in one place.
type accessTokenRow struct {
	ID            uuid.UUID
	ProjectID     uuid.UUID
	EnvironmentID uuid.UUID
	Name          string
	Prefix        string
	Scopes        []string
	IpAllowlist   []string
	RateLimitRpm  int32
	ExpiresAt     *time.Time
	RevokedAt     *time.Time
	LastUsedAt    *time.Time
	CreatedAt     time.Time
	CreatedBy     *uuid.UUID
}

func accessTokenFromRow(row accessTokenRow) *domain.AccessToken {
	scopes := make([]domain.TokenScope, 0, len(row.Scopes))
	for _, scope := range row.Scopes {
		scopes = append(scopes, domain.TokenScope(scope))
	}

	// Stored entries were validated on the way in, so anything unparseable
	// here means the row was tampered with. Such an entry is dropped rather
	// than widening the allowlist by accident.
	allowlist := make([]netip.Prefix, 0, len(row.IpAllowlist))
	for _, entry := range row.IpAllowlist {
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			allowlist = append(allowlist, prefix.Masked())
		}
	}

	return &domain.AccessToken{
		ID:            row.ID,
		ProjectID:     row.ProjectID,
		EnvironmentID: row.EnvironmentID,
		Name:          row.Name,
		Prefix:        row.Prefix,
		Scopes:        scopes,
		IPAllowlist:   allowlist,
		RateLimitRPM:  row.RateLimitRpm,
		ExpiresAt:     row.ExpiresAt,
		RevokedAt:     row.RevokedAt,
		LastUsedAt:    row.LastUsedAt,
		CreatedAt:     row.CreatedAt,
		CreatedBy:     row.CreatedBy,
	}
}
