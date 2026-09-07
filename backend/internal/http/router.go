package http

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"vaultly/backend/internal/auth"
	"vaultly/backend/internal/config"
	"vaultly/backend/internal/domain"
	"vaultly/backend/internal/ratelimit"
	"vaultly/backend/internal/service"
)

// Services bundles everything the router needs.
type Services struct {
	Auth       *service.AuthService
	Workspaces *service.WorkspaceService
	Projects   *service.ProjectService
	Secrets    *service.SecretService
	Promotion  *service.PromotionService
	Tokens     *service.TokenService
	Audit      *service.AuditService
}

// RouterDeps carries the collaborators the router wires together.
type RouterDeps struct {
	Config   *config.Config
	Services Services
	Issuer   *auth.TokenIssuer
	Limiter  *ratelimit.Limiter
	Pool     *pgxpool.Pool
	Logger   *slog.Logger
}

// NewRouter builds the HTTP router.
func NewRouter(deps RouterDeps) *gin.Engine {
	if deps.Config.Environment.IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	}

	// The default engine installs gin's own logger and recovery; this server
	// uses structured equivalents instead, so it starts from a bare engine.
	router := gin.New()

	// Gin's own proxy trust is disabled because RealIP resolves the client
	// address explicitly, according to the configured policy.
	_ = router.SetTrustedProxies(nil)

	router.Use(
		RequestID(),
		RealIP(deps.Config.TrustProxy),
		Logger(deps.Logger),
		Recovery(deps.Logger),
		SecurityHeaders(),
		CORS(deps.Config.CORSAllowedOrigins),
	)

	registerHealth(router, deps.Pool)

	secureCookies := deps.Config.Environment.IsProduction()
	authHandler := NewAuthHandler(deps.Services.Auth, secureCookies)
	workspaceHandler := NewWorkspaceHandler(deps.Services.Workspaces)
	projectHandler := NewProjectHandler(deps.Services.Projects)
	secretHandler := NewSecretHandler(deps.Services.Secrets, deps.Services.Promotion)
	tokenHandler := NewTokenHandler(deps.Services.Tokens)
	auditHandler := NewAuditHandler(deps.Services.Audit)

	v1 := router.Group("/api/v1")

	// --- Public authentication endpoints ---------------------------------
	authGroup := v1.Group("/auth")
	{
		authGroup.POST("/register", authHandler.Register)
		authGroup.POST("/login", authHandler.Login)
		authGroup.POST("/refresh", authHandler.Refresh)
		authGroup.POST("/logout", authHandler.Logout)
		authGroup.GET("/me", RequireUser(deps.Issuer), authHandler.Me)
	}

	// --- Human endpoints --------------------------------------------------
	user := v1.Group("")
	user.Use(RequireUser(deps.Issuer))
	{
		workspaces := user.Group("/workspaces")
		{
			workspaces.GET("", workspaceHandler.List)
			workspaces.POST("", workspaceHandler.Create)
			workspaces.GET("/:id", workspaceHandler.Get)

			workspaces.GET("/:id/members", workspaceHandler.ListMembers)
			workspaces.POST("/:id/members", workspaceHandler.AddMember)
			workspaces.PATCH("/:id/members/:memberId", workspaceHandler.UpdateMember)
			workspaces.DELETE("/:id/members/:memberId", workspaceHandler.RemoveMember)

			workspaces.GET("/:id/projects", projectHandler.List)
			workspaces.POST("/:id/projects", projectHandler.Create)

			workspaces.GET("/:id/audit-logs", auditHandler.List)
			workspaces.GET("/:id/audit-actions", auditHandler.Actions)
		}

		projects := user.Group("/projects")
		{
			projects.GET("/:id", projectHandler.Get)
			projects.PATCH("/:id", projectHandler.Update)
			projects.DELETE("/:id", projectHandler.Delete)

			projects.GET("/:id/environments", projectHandler.ListEnvironments)
			projects.POST("/:id/environments", projectHandler.CreateEnvironment)

			projects.POST("/:id/promote", secretHandler.Promote)

			projects.GET("/:id/tokens", tokenHandler.List)
			projects.POST("/:id/tokens", tokenHandler.Create)
		}

		environments := user.Group("/environments")
		{
			environments.GET("/:id", projectHandler.GetEnvironment)
			environments.GET("/:id/secrets", secretHandler.List)
			environments.POST("/:id/secrets", secretHandler.Create)
		}

		secrets := user.Group("/secrets")
		{
			secrets.GET("/:id", secretHandler.Get)
			secrets.PUT("/:id", secretHandler.Update)
			secrets.PATCH("/:id", secretHandler.UpdateDescription)
			secrets.DELETE("/:id", secretHandler.Delete)

			// Revealing a value is a separate, individually audited request,
			// which is why it is a route of its own rather than a query
			// parameter on the secret.
			secrets.GET("/:id/reveal", secretHandler.Reveal)
			secrets.GET("/:id/versions", secretHandler.ListVersions)
			secrets.GET("/:id/versions/:version", secretHandler.RevealVersion)
			secrets.POST("/:id/versions/:version/rollback", secretHandler.Rollback)
		}

		user.DELETE("/tokens/:id", tokenHandler.Revoke)
	}

	// --- Machine endpoints ------------------------------------------------
	// Authenticated by a vlt_ token rather than a session, with the token's
	// own IP allowlist and rate limit enforced by the middleware.
	cicd := v1.Group("/cicd")
	cicd.Use(RequireToken(deps.Services.Tokens, deps.Limiter))
	{
		cicd.GET("/secrets", RequireScope(domain.ScopeSecretsRead), tokenHandler.PullSecrets)
	}

	router.NoRoute(func(c *gin.Context) {
		respondError(c, domain.ErrNotFound)
	})

	return router
}

// registerHealth adds the liveness and readiness endpoints.
func registerHealth(router *gin.Engine, pool *pgxpool.Pool) {
	// Liveness: the process is up. It must not touch the database, or a brief
	// database blip would get the container killed rather than just marked
	// unready.
	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Readiness: the process can actually serve traffic.
	router.GET("/readyz", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()

		if err := pool.Ping(ctx); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "unavailable",
				"reason": "database unreachable",
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})
}
