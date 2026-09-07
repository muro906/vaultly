package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"vaultly/backend/internal/auth"
	"vaultly/backend/internal/db/sqlcgen"
	"vaultly/backend/internal/domain"
)

// ErrInvalidCredentials is returned for any failed login.
//
// It is one error for both an unknown email and a wrong password on purpose:
// telling them apart would turn the login endpoint into an account
// enumeration oracle.
var ErrInvalidCredentials = errors.New("invalid email or password")

// Session is the result of a successful authentication.
type Session struct {
	User        domain.User
	AccessToken string
	// AccessExpiresAt lets the client refresh before the token dies rather
	// than after a failed request.
	AccessExpiresAt time.Time
	// RefreshToken is delivered to the browser as an httpOnly cookie and is
	// never exposed to page scripts.
	RefreshToken     string
	RefreshExpiresAt time.Time
}

// AuthService handles registration, login and session lifecycle.
type AuthService struct {
	store      *Store
	issuer     *auth.TokenIssuer
	audit      *AuditRecorder
	logger     *slog.Logger
	refreshTTL time.Duration
}

// NewAuthService builds an AuthService.
func NewAuthService(store *Store, issuer *auth.TokenIssuer, audit *AuditRecorder, logger *slog.Logger, refreshTTL time.Duration) *AuthService {
	return &AuthService{
		store:      store,
		issuer:     issuer,
		audit:      audit,
		logger:     logger,
		refreshTTL: refreshTTL,
	}
}

// RegisterInput is the payload for creating an account.
type RegisterInput struct {
	Email    string
	Password string
	Name     string
	Actor    Actor
}

// Register creates a user together with a personal workspace.
//
// The workspace is created in the same transaction as the user: an account
// with nowhere to put anything would be a broken state, and rolling both back
// together avoids it.
func (s *AuthService) Register(ctx context.Context, in RegisterInput) (*Session, error) {
	v := &domain.ValidationError{}
	email := validateEmail(v, in.Email)
	validatePassword(v, in.Password)
	name := validateName(v, "name", in.Name)
	if err := v.ErrorOrNil(); err != nil {
		return nil, err
	}

	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		return nil, fmt.Errorf("register: hash password: %w", err)
	}

	var user domain.User
	var workspaceID uuid.UUID

	err = s.store.InTx(ctx, func(q *sqlcgen.Queries) error {
		created, err := q.CreateUser(ctx, sqlcgen.CreateUserParams{
			Email:        email,
			PasswordHash: hash,
			Name:         name,
		})
		if err != nil {
			return translateDBError(err, "create user")
		}

		user = domain.User{
			ID:        created.ID,
			Email:     created.Email,
			Name:      created.Name,
			CreatedAt: created.CreatedAt,
			UpdatedAt: created.UpdatedAt,
		}

		// Slugs are globally unique, so a personal workspace derives its slug
		// from the user id rather than the name, which would collide for any
		// two people called the same thing.
		workspace, err := q.CreateWorkspace(ctx, sqlcgen.CreateWorkspaceParams{
			Name:    defaultWorkspaceName(name),
			Slug:    fmt.Sprintf("ws-%s", created.ID.String()[:8]),
			OwnerID: created.ID,
		})
		if err != nil {
			return translateDBError(err, "create workspace")
		}
		workspaceID = workspace.ID

		return translateDBError(q.AddWorkspaceMember(ctx, sqlcgen.AddWorkspaceMemberParams{
			WorkspaceID: workspace.ID,
			UserID:      created.ID,
			Role:        string(domain.RoleOwner),
		}), "add workspace member")
	})
	if err != nil {
		if errors.Is(err, domain.ErrConflict) {
			// The only unique constraint a registration can hit is the email.
			return nil, domain.NewValidationError("email", "is already registered")
		}
		return nil, err
	}

	actor := in.Actor
	actor.UserID = &user.ID
	s.audit.Record(Event{
		WorkspaceID:  workspaceID,
		Actor:        actor,
		Action:       domain.ActionUserRegistered,
		ResourceType: "user",
		ResourceID:   &user.ID,
		Metadata:     map[string]any{"email": user.Email},
	})

	return s.newSession(ctx, user, actor)
}

// LoginInput is the payload for authenticating.
type LoginInput struct {
	Email    string
	Password string
	Actor    Actor
}

// Login authenticates a user and starts a session.
func (s *AuthService) Login(ctx context.Context, in LoginInput) (*Session, error) {
	email := strings.ToLower(strings.TrimSpace(in.Email))

	record, err := s.store.Queries().GetUserByEmail(ctx, email)
	if err != nil {
		if isNoRows(err) {
			// Hash a dummy password anyway so that an unknown address takes
			// the same time as a known one. Without this, response latency
			// alone reveals which addresses are registered.
			_, _ = auth.HashPassword(in.Password)
			return nil, ErrInvalidCredentials
		}
		return nil, translateDBError(err, "look up user")
	}

	if err := auth.VerifyPassword(in.Password, record.PasswordHash); err != nil {
		if !errors.Is(err, auth.ErrMismatchedPassword) {
			// A hash we cannot read is an operational problem, not a wrong
			// password, and would otherwise lock the user out silently.
			s.logger.Error("stored password hash is unusable",
				slog.String("user_id", record.ID.String()),
				slog.String("error", err.Error()))
		}
		return nil, ErrInvalidCredentials
	}

	user := domain.User{
		ID:        record.ID,
		Email:     record.Email,
		Name:      record.Name,
		CreatedAt: record.CreatedAt,
		UpdatedAt: record.UpdatedAt,
	}

	actor := in.Actor
	actor.UserID = &user.ID

	// Record the login against every workspace the user belongs to, so it is
	// visible to each team whose secrets this session can now reach.
	s.recordAcrossWorkspaces(ctx, user.ID, actor, domain.ActionUserLoggedIn, "user", &user.ID, nil)

	return s.newSession(ctx, user, actor)
}

// Refresh exchanges a refresh token for a new session.
//
// The presented token is revoked and a new one issued in the same transaction.
// That rotation means a stolen token stops working as soon as the legitimate
// client next refreshes.
func (s *AuthService) Refresh(ctx context.Context, refreshToken string, actor Actor) (*Session, error) {
	hash := auth.HashToken(refreshToken)

	stored, err := s.store.Queries().GetActiveRefreshToken(ctx, hash)
	if err != nil {
		if isNoRows(err) {
			return nil, domain.ErrUnauthenticated
		}
		return nil, translateDBError(err, "look up refresh token")
	}

	record, err := s.store.Queries().GetUserByID(ctx, stored.UserID)
	if err != nil {
		if isNoRows(err) {
			return nil, domain.ErrUnauthenticated
		}
		return nil, translateDBError(err, "look up user")
	}

	user := domain.User{
		ID:        record.ID,
		Email:     record.Email,
		Name:      record.Name,
		CreatedAt: record.CreatedAt,
		UpdatedAt: record.UpdatedAt,
	}

	next, err := auth.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("refresh: generate token: %w", err)
	}
	expiresAt := time.Now().Add(s.refreshTTL)

	err = s.store.InTx(ctx, func(q *sqlcgen.Queries) error {
		if err := q.RevokeRefreshToken(ctx, hash); err != nil {
			return translateDBError(err, "revoke refresh token")
		}
		_, err := q.CreateRefreshToken(ctx, refreshTokenParams(user.ID, next.Hash, expiresAt, actor))
		return translateDBError(err, "create refresh token")
	})
	if err != nil {
		return nil, err
	}

	accessToken, accessExpiresAt, err := s.issuer.Issue(user.ID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("refresh: issue access token: %w", err)
	}

	return &Session{
		User:             user,
		AccessToken:      accessToken,
		AccessExpiresAt:  accessExpiresAt,
		RefreshToken:     next.Plaintext,
		RefreshExpiresAt: expiresAt,
	}, nil
}

// Logout revokes a refresh token. It is intentionally forgiving: logging out
// with a token that is already gone is a success, since the desired end state
// has been reached.
func (s *AuthService) Logout(ctx context.Context, refreshToken string, actor Actor) error {
	if refreshToken == "" {
		return nil
	}

	hash := auth.HashToken(refreshToken)

	stored, err := s.store.Queries().GetActiveRefreshToken(ctx, hash)
	if err != nil && !isNoRows(err) {
		return translateDBError(err, "look up refresh token")
	}

	if err := s.store.Queries().RevokeRefreshToken(ctx, hash); err != nil {
		return translateDBError(err, "revoke refresh token")
	}

	if err == nil {
		logoutActor := actor
		logoutActor.UserID = &stored.UserID
		s.recordAcrossWorkspaces(ctx, stored.UserID, logoutActor,
			domain.ActionUserLoggedOut, "user", &stored.UserID, nil)
	}
	return nil
}

// LogoutAll revokes every session for a user, for use after a password change
// or a suspected compromise.
func (s *AuthService) LogoutAll(ctx context.Context, userID uuid.UUID) error {
	return translateDBError(
		s.store.Queries().RevokeAllUserRefreshTokens(ctx, userID),
		"revoke all refresh tokens")
}

// Me returns the authenticated user.
func (s *AuthService) Me(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	record, err := s.store.Queries().GetUserByID(ctx, userID)
	if err != nil {
		if isNoRows(err) {
			return nil, domain.ErrNotFound
		}
		return nil, translateDBError(err, "look up user")
	}
	return &domain.User{
		ID:        record.ID,
		Email:     record.Email,
		Name:      record.Name,
		CreatedAt: record.CreatedAt,
		UpdatedAt: record.UpdatedAt,
	}, nil
}

// newSession issues an access token and a fresh refresh token.
func (s *AuthService) newSession(ctx context.Context, user domain.User, actor Actor) (*Session, error) {
	accessToken, accessExpiresAt, err := s.issuer.Issue(user.ID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("issue access token: %w", err)
	}

	refresh, err := auth.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}
	refreshExpiresAt := time.Now().Add(s.refreshTTL)

	if _, err := s.store.Queries().CreateRefreshToken(ctx,
		refreshTokenParams(user.ID, refresh.Hash, refreshExpiresAt, actor)); err != nil {
		return nil, translateDBError(err, "create refresh token")
	}

	return &Session{
		User:             user,
		AccessToken:      accessToken,
		AccessExpiresAt:  accessExpiresAt,
		RefreshToken:     refresh.Plaintext,
		RefreshExpiresAt: refreshExpiresAt,
	}, nil
}

func refreshTokenParams(userID uuid.UUID, hash []byte, expiresAt time.Time, actor Actor) sqlcgen.CreateRefreshTokenParams {
	params := sqlcgen.CreateRefreshTokenParams{
		UserID:    userID,
		TokenHash: hash,
		ExpiresAt: expiresAt,
		UserAgent: actor.UserAgent,
	}
	if actor.IP.IsValid() {
		addr := actor.IP.Unmap()
		params.IpAddress = &addr
	}
	return params
}

// recordAcrossWorkspaces writes one audit entry per workspace the user belongs
// to. Account-level events have no single workspace, but they are relevant to
// every team the user can reach.
func (s *AuthService) recordAcrossWorkspaces(ctx context.Context, userID uuid.UUID, actor Actor, action, resourceType string, resourceID *uuid.UUID, metadata map[string]any) {
	workspaces, err := s.store.Queries().ListWorkspacesForUser(ctx, userID)
	if err != nil {
		s.logger.Warn("could not resolve workspaces for audit entry",
			slog.String("action", action),
			slog.String("error", err.Error()))
		return
	}
	for _, workspace := range workspaces {
		s.audit.Record(Event{
			WorkspaceID:  workspace.ID,
			Actor:        actor,
			Action:       action,
			ResourceType: resourceType,
			ResourceID:   resourceID,
			Metadata:     metadata,
		})
	}
}

// defaultWorkspaceName names the workspace created alongside a new account.
func defaultWorkspaceName(name string) string {
	if name == "" {
		return "Personal workspace"
	}
	return name + "'s workspace"
}
