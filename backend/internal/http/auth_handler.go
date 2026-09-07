package http

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"vaultly/backend/internal/domain"
	"vaultly/backend/internal/service"
)

// Session cookie names.
const (
	// accessCookieName holds the short-lived access token. It is httpOnly so
	// page scripts cannot read it, which keeps the credential out of reach of
	// any cross-site scripting bug in the frontend.
	accessCookieName = "vaultly_access"
	// refreshCookieName holds the long-lived refresh token. Its path is
	// narrowed to the endpoints that need it, so it is not sent on every
	// request.
	refreshCookieName = "vaultly_refresh"
	refreshCookiePath = "/api/v1/auth"
)

// AuthHandler serves registration, login and session endpoints.
type AuthHandler struct {
	auth   *service.AuthService
	secure bool
}

// NewAuthHandler builds an AuthHandler. secure marks cookies Secure, which
// must be on in production and off for plain-HTTP local development.
func NewAuthHandler(auth *service.AuthService, secure bool) *AuthHandler {
	return &AuthHandler{auth: auth, secure: secure}
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// sessionResponse is what the client receives after authenticating.
//
// It deliberately omits both tokens: the access and refresh tokens travel only
// as httpOnly cookies, so a script on the page can never read them. The expiry
// is included so the client knows when to refresh.
type sessionResponse struct {
	User      domain.User `json:"user"`
	ExpiresAt time.Time   `json:"expiresAt"`
}

// Register creates an account and starts a session.
func (h *AuthHandler) Register(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondValidation(c, "body", "must be a valid JSON object")
		return
	}

	session, err := h.auth.Register(c.Request.Context(), service.RegisterInput{
		Email:    req.Email,
		Password: req.Password,
		Name:     req.Name,
		Actor:    actorFrom(c),
	})
	if err != nil {
		respondError(c, err)
		return
	}

	h.setSessionCookies(c, session)
	c.JSON(http.StatusCreated, sessionResponse{User: session.User, ExpiresAt: session.AccessExpiresAt})
}

// Login authenticates and starts a session.
func (h *AuthHandler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondValidation(c, "body", "must be a valid JSON object")
		return
	}

	session, err := h.auth.Login(c.Request.Context(), service.LoginInput{
		Email:    req.Email,
		Password: req.Password,
		Actor:    actorFrom(c),
	})
	if err != nil {
		respondError(c, err)
		return
	}

	h.setSessionCookies(c, session)
	c.JSON(http.StatusOK, sessionResponse{User: session.User, ExpiresAt: session.AccessExpiresAt})
}

// Refresh exchanges the refresh cookie for a new session.
func (h *AuthHandler) Refresh(c *gin.Context) {
	refreshToken, err := c.Cookie(refreshCookieName)
	if err != nil || refreshToken == "" {
		respondError(c, domain.ErrUnauthenticated)
		return
	}

	session, err := h.auth.Refresh(c.Request.Context(), refreshToken, actorFrom(c))
	if err != nil {
		// The refresh token is spent or invalid, so clear the cookies rather
		// than leaving the browser to retry with a credential that can never
		// work again.
		h.clearSessionCookies(c)
		respondError(c, err)
		return
	}

	h.setSessionCookies(c, session)
	c.JSON(http.StatusOK, sessionResponse{User: session.User, ExpiresAt: session.AccessExpiresAt})
}

// Logout revokes the session and clears its cookies.
func (h *AuthHandler) Logout(c *gin.Context) {
	refreshToken, _ := c.Cookie(refreshCookieName)

	// The cookies are cleared regardless of what the server makes of the
	// token, so that logging out always leaves the browser signed out.
	defer h.clearSessionCookies(c)

	if err := h.auth.Logout(c.Request.Context(), refreshToken, actorFrom(c)); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// Me returns the authenticated user.
func (h *AuthHandler) Me(c *gin.Context) {
	user, err := h.auth.Me(c.Request.Context(), UserID(c))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": user})
}

// setSessionCookies writes both session cookies.
func (h *AuthHandler) setSessionCookies(c *gin.Context, session *service.Session) {
	// SameSite=Lax rather than Strict: the session must survive a user
	// following a link into the app, and the API is not cross-site from the
	// frontend's point of view.
	c.SetSameSite(http.SameSiteLaxMode)

	c.SetCookie(
		accessCookieName,
		session.AccessToken,
		int(time.Until(session.AccessExpiresAt).Seconds()),
		"/",
		"",
		h.secure,
		true, // httpOnly
	)

	c.SetCookie(
		refreshCookieName,
		session.RefreshToken,
		int(time.Until(session.RefreshExpiresAt).Seconds()),
		refreshCookiePath,
		"",
		h.secure,
		true,
	)
}

// clearSessionCookies expires both cookies. The path and flags must match how
// they were set, or the browser keeps the originals.
func (h *AuthHandler) clearSessionCookies(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(accessCookieName, "", -1, "/", "", h.secure, true)
	c.SetCookie(refreshCookieName, "", -1, refreshCookiePath, "", h.secure, true)
}

// detachedContext returns a context that outlives the request, for bookkeeping
// that must not be cancelled when the client disconnects.
func detachedContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}
