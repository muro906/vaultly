package http

import (
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"vaultly/backend/internal/auth"
	"vaultly/backend/internal/domain"
	"vaultly/backend/internal/ratelimit"
	"vaultly/backend/internal/service"
)

// Keys under which the middleware stores values on the request context.
const (
	ctxRequestID = "vaultly.request_id"
	ctxLogger    = "vaultly.logger"
	ctxUserID    = "vaultly.user_id"
	ctxUserEmail = "vaultly.user_email"
	ctxToken     = "vaultly.token"
	ctxClientIP  = "vaultly.client_ip"
)

// RequestID assigns every request an identifier, echoes it in a header and
// puts it on the context so logs and error responses can be correlated.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader("X-Request-ID")
		if id == "" {
			id = uuid.NewString()
		}
		c.Set(ctxRequestID, id)
		c.Header("X-Request-ID", id)
		c.Next()
	}
}

// RealIP resolves the client address once, per the trust-proxy setting, and
// stores it for the allowlist and rate-limiting middleware.
//
// X-Forwarded-For is only consulted when the server is explicitly configured
// to sit behind a proxy. Trusting it unconditionally would let any client
// forge its own source address and walk straight through an IP allowlist.
func RealIP(trustProxy bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(ctxClientIP, resolveClientIP(c, trustProxy))
		c.Next()
	}
}

func resolveClientIP(c *gin.Context, trustProxy bool) netip.Addr {
	if trustProxy {
		// The left-most entry is the original client; the rest are proxies.
		if forwarded := c.GetHeader("X-Forwarded-For"); forwarded != "" {
			first, _, _ := strings.Cut(forwarded, ",")
			if addr, err := netip.ParseAddr(strings.TrimSpace(first)); err == nil {
				return addr.Unmap()
			}
		}
		if real := strings.TrimSpace(c.GetHeader("X-Real-IP")); real != "" {
			if addr, err := netip.ParseAddr(real); err == nil {
				return addr.Unmap()
			}
		}
	}

	host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	if err != nil {
		host = c.Request.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

// Logger logs one line per request and attaches a request-scoped logger.
func Logger(base *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		logger := base.With(
			slog.String("request_id", requestIDFrom(c)),
			slog.String("method", c.Request.Method),
			slog.String("path", c.Request.URL.Path),
		)
		c.Set(ctxLogger, logger)

		c.Next()

		status := c.Writer.Status()
		attrs := []any{
			slog.Int("status", status),
			slog.Duration("duration", time.Since(start)),
		}
		if ip := ClientIP(c); ip.IsValid() {
			attrs = append(attrs, slog.String("client_ip", ip.String()))
		}

		// Server faults are the operator's problem; client errors are noise at
		// info level but useful when debugging, so they sit in between.
		switch {
		case status >= 500:
			logger.Error("request completed", attrs...)
		case status >= 400:
			logger.Warn("request completed", attrs...)
		default:
			logger.Info("request completed", attrs...)
		}
	}
}

// Recovery turns a panic into a 500 rather than dropping the connection, and
// logs the panic with its request id.
func Recovery(base *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if recovered := recover(); recovered != nil {
				base.Error("panic recovered",
					slog.String("request_id", requestIDFrom(c)),
					slog.String("path", c.Request.URL.Path),
					slog.Any("panic", recovered))

				c.AbortWithStatusJSON(http.StatusInternalServerError, ErrorResponse{
					Error:     "an unexpected error occurred",
					RequestID: requestIDFrom(c),
				})
			}
		}()
		c.Next()
	}
}

// CORS allows the configured browser origins to make credentialed requests.
//
// Origins are matched exactly against an allowlist and echoed back, because
// Allow-Credentials cannot be combined with a wildcard. An unrecognised origin
// simply gets no CORS headers, which the browser then blocks.
func CORS(allowedOrigins []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		if origin != "" && slices.Contains(allowedOrigins, origin) {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")
			c.Header("Access-Control-Max-Age", "600")
			// The response body depends on the request's Origin, so caches must
			// not serve one origin's response to another.
			c.Header("Vary", "Origin")
		}

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// SecurityHeaders sets conservative defaults. The API returns only JSON, so it
// can afford to forbid framing and content sniffing outright.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "no-referrer")
		// Secret values must never be written to a shared cache.
		c.Header("Cache-Control", "no-store")
		c.Next()
	}
}

// RequireUser authenticates a human caller.
//
// The access token is read from the session cookie first and the Authorization
// header second. The cookie is how the Next.js server talks to this API; the
// header exists for direct API use and for tests.
func RequireUser(issuer *auth.TokenIssuer) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := accessTokenFromRequest(c)
		if token == "" {
			respondError(c, domain.ErrUnauthenticated)
			return
		}

		claims, err := issuer.Verify(token)
		if err != nil {
			respondError(c, domain.ErrUnauthenticated)
			return
		}

		c.Set(ctxUserID, claims.UserID)
		c.Set(ctxUserEmail, claims.Email)
		c.Next()
	}
}

// RequireToken authenticates a machine caller presenting a vlt_ access token.
//
// It also enforces the token's IP allowlist and its per-token rate limit, both
// of which are properties of the credential rather than of the route.
func RequireToken(tokens *service.TokenService, limiter *ratelimit.Limiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		plaintext := bearerToken(c)
		if plaintext == "" {
			respondError(c, domain.ErrUnauthenticated)
			return
		}

		clientIP := ClientIP(c)

		authenticated, err := tokens.Authenticate(c.Request.Context(), plaintext, clientIP)
		if err != nil {
			respondError(c, err)
			return
		}

		// Rate limiting comes after authentication so the limit is charged to
		// a specific token rather than to whoever is guessing at credentials.
		allowed, retryAfter := limiter.Reserve(
			authenticated.Token.ID.String(),
			int(authenticated.Token.RateLimitRPM),
		)
		if !allowed {
			c.Header("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
			respondError(c, domain.ErrRateLimited)
			return
		}

		c.Set(ctxToken, authenticated)

		// Recorded after the handler runs, and detached from the request
		// context, so that bookkeeping never fails or delays the response.
		defer func() {
			go func() {
				ctx, cancel := detachedContext(5 * time.Second)
				defer cancel()
				_ = tokens.Touch(ctx, authenticated.Token.ID)
			}()
		}()

		c.Next()
	}
}

// RequireScope rejects a machine caller whose token lacks a scope.
func RequireScope(scope domain.TokenScope) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := TokenFrom(c)
		if token == nil {
			respondError(c, domain.ErrUnauthenticated)
			return
		}
		if !token.Token.HasScope(scope) {
			respondError(c, domain.ErrForbidden)
			return
		}
		c.Next()
	}
}

// --- Context accessors -----------------------------------------------------

func requestIDFrom(c *gin.Context) string {
	if id, ok := c.Get(ctxRequestID); ok {
		if s, ok := id.(string); ok {
			return s
		}
	}
	return ""
}

func loggerFrom(c *gin.Context) *slog.Logger {
	if logger, ok := c.Get(ctxLogger); ok {
		if l, ok := logger.(*slog.Logger); ok {
			return l
		}
	}
	return nil
}

// UserID returns the authenticated user, or uuid.Nil when there is none.
func UserID(c *gin.Context) uuid.UUID {
	if id, ok := c.Get(ctxUserID); ok {
		if u, ok := id.(uuid.UUID); ok {
			return u
		}
	}
	return uuid.Nil
}

// TokenFrom returns the authenticated machine token, or nil.
func TokenFrom(c *gin.Context) *service.AuthenticatedToken {
	if token, ok := c.Get(ctxToken); ok {
		if t, ok := token.(*service.AuthenticatedToken); ok {
			return t
		}
	}
	return nil
}

// ClientIP returns the resolved client address.
func ClientIP(c *gin.Context) netip.Addr {
	if addr, ok := c.Get(ctxClientIP); ok {
		if a, ok := addr.(netip.Addr); ok {
			return a
		}
	}
	return netip.Addr{}
}

// actorFrom builds the audit actor for the current request, so that every
// recorded action carries who did it and from where.
func actorFrom(c *gin.Context) service.Actor {
	actor := service.Actor{
		IP:        ClientIP(c),
		UserAgent: c.Request.UserAgent(),
	}
	if userID := UserID(c); userID != uuid.Nil {
		actor.UserID = &userID
	}
	if token := TokenFrom(c); token != nil {
		id := token.Token.ID
		actor.TokenID = &id
	}
	return actor
}

// --- Helpers ---------------------------------------------------------------

func accessTokenFromRequest(c *gin.Context) string {
	if cookie, err := c.Cookie(accessCookieName); err == nil && cookie != "" {
		return cookie
	}
	return bearerToken(c)
}

func bearerToken(c *gin.Context) string {
	header := c.GetHeader("Authorization")
	if header == "" {
		return ""
	}
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}
