package http

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"vaultly/backend/internal/domain"
	"vaultly/backend/internal/service"
)

// TokenHandler serves access token management and the CI/CD pull endpoint.
type TokenHandler struct {
	tokens *service.TokenService
}

// NewTokenHandler builds a TokenHandler.
func NewTokenHandler(tokens *service.TokenService) *TokenHandler {
	return &TokenHandler{tokens: tokens}
}

type createTokenRequest struct {
	EnvironmentID string     `json:"environmentId"`
	Name          string     `json:"name"`
	Scopes        []string   `json:"scopes"`
	IPAllowlist   []string   `json:"ipAllowlist"`
	RateLimitRPM  int32      `json:"rateLimitRpm"`
	ExpiresAt     *time.Time `json:"expiresAt"`
}

// Create mints a token. The response carries the plaintext token, which is the
// only time it is ever available.
func (h *TokenHandler) Create(c *gin.Context) {
	projectID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	var req createTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondValidation(c, "body", "must be a valid JSON object")
		return
	}

	environmentID, ok := parseUUID(c, "environmentId", req.EnvironmentID)
	if !ok {
		return
	}

	scopes := make([]domain.TokenScope, 0, len(req.Scopes))
	for _, scope := range req.Scopes {
		scopes = append(scopes, domain.TokenScope(scope))
	}

	token, err := h.tokens.Create(c.Request.Context(), UserID(c), service.CreateTokenInput{
		ProjectID:     projectID,
		EnvironmentID: environmentID,
		Name:          req.Name,
		Scopes:        scopes,
		IPAllowlist:   req.IPAllowlist,
		RateLimitRPM:  req.RateLimitRPM,
		ExpiresAt:     req.ExpiresAt,
		Actor:         actorFrom(c),
	})
	if err != nil {
		respondError(c, err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"token": token,
		// Stated in the response because the UI must warn before the user
		// navigates away and loses the value permanently.
		"warning": "This token is shown only once. Store it now; it cannot be retrieved later.",
	})
}

// List returns a project's tokens without their secrets.
func (h *TokenHandler) List(c *gin.Context) {
	projectID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	tokens, err := h.tokens.List(c.Request.Context(), UserID(c), projectID)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"tokens": tokens})
}

// Revoke disables a token.
func (h *TokenHandler) Revoke(c *gin.Context) {
	tokenID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	if err := h.tokens.Revoke(c.Request.Context(), UserID(c), tokenID, actorFrom(c)); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// PullSecrets returns the token's environment as a set of key/value pairs.
//
// This is what a CI job calls. It supports two shapes: JSON by default, and
// dotenv when asked for, so a pipeline can write the response straight to a
// .env file without post-processing.
func (h *TokenHandler) PullSecrets(c *gin.Context) {
	token := TokenFrom(c)
	if token == nil {
		respondError(c, domain.ErrUnauthenticated)
		return
	}

	values, err := h.tokens.PullSecrets(c.Request.Context(), token, actorFrom(c))
	if err != nil {
		respondError(c, err)
		return
	}

	if strings.EqualFold(c.Query("format"), "dotenv") {
		c.Header("Content-Type", "text/plain; charset=utf-8")
		c.String(http.StatusOK, "%s", dotenv(values))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"environmentId": token.Token.EnvironmentID,
		"secrets":       values,
	})
}

// dotenv renders values as a .env file.
//
// Every value is single-quoted with embedded quotes escaped, because secrets
// routinely contain spaces, "#" and "$". Without quoting, a shell sourcing the
// file would perform substitution on a password.
func dotenv(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	// Sorted so that the output is stable and diffable between runs.
	sort.Strings(keys)

	var buf strings.Builder
	for _, key := range keys {
		escaped := strings.ReplaceAll(values[key], `'`, `'\''`)
		fmt.Fprintf(&buf, "%s='%s'\n", key, escaped)
	}
	return buf.String()
}

// parseUUID validates a UUID taken from a request body.
func parseUUID(c *gin.Context, field, raw string) (uuid.UUID, bool) {
	if raw == "" {
		respondValidation(c, field, "is required")
		return uuid.Nil, false
	}
	parsed, err := uuid.Parse(raw)
	if err != nil {
		respondValidation(c, field, "must be a valid identifier")
		return uuid.Nil, false
	}
	return parsed, true
}
