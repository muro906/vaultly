//go:build integration

// Package integration exercises the API end to end against a real PostgreSQL
// instance and a real HTTP router.
//
// These tests are behind the "integration" build tag so that `go test ./...`
// stays fast and dependency-free. Run them with:
//
//	go test -tags=integration ./...
//
// A throwaway PostgreSQL container is started automatically. Set
// VAULTLY_TEST_DATABASE_URL to point at an existing database instead, which is
// what CI does when it already provides one as a service.
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"vaultly/backend/internal/auth"
	"vaultly/backend/internal/config"
	"vaultly/backend/internal/crypto"
	"vaultly/backend/internal/db"
	vaultlyhttp "vaultly/backend/internal/http"
	"vaultly/backend/internal/ratelimit"
	"vaultly/backend/internal/service"
)

// The container is started once for the whole package: standing one up per
// test would dominate the runtime, and each test isolates itself by using
// fresh accounts rather than a fresh database.
var (
	sharedURL  string
	sharedOnce sync.Once
	sharedErr  error
)

func databaseURL(t *testing.T) string {
	t.Helper()

	sharedOnce.Do(func() {
		if url := os.Getenv("VAULTLY_TEST_DATABASE_URL"); url != "" {
			sharedURL = url
			return
		}
		sharedURL, sharedErr = startPostgres()
	})

	if sharedErr != nil {
		t.Skipf("no test database available: %v "+
			"(start Docker, or set VAULTLY_TEST_DATABASE_URL)", sharedErr)
	}
	return sharedURL
}

func startPostgres() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("vaultly_test"),
		tcpostgres.WithUsername("vaultly"),
		tcpostgres.WithPassword("vaultly"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(2*time.Minute),
		),
	)
	if err != nil {
		return "", err
	}

	return container.ConnectionString(ctx, "sslmode=disable")
}

// harness is a fully wired server backed by a real database.
type harness struct {
	t      *testing.T
	server *httptest.Server
	pool   *pgxpool.Pool
	audit  *service.AuditRecorder
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	gin.SetMode(gin.TestMode)

	url := databaseURL(t)
	ctx := context.Background()

	if err := db.Migrate(url); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	pool, err := db.NewPool(ctx, url, db.DefaultPoolConfig())
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}

	masterKey, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatalf("generate master key: %v", err)
	}
	keyring, err := crypto.NewKeyringFromBase64(masterKey)
	if err != nil {
		t.Fatalf("build keyring: %v", err)
	}

	// Discard logs so a failing test's output is its own assertions.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	store := service.NewStore(pool)
	authz := service.NewAuthorizer(store)

	// Flushed aggressively so a test can assert on the audit log without
	// waiting a second for the default interval.
	audit := service.NewAuditRecorder(store, logger, service.AuditConfig{
		FlushSize:     1,
		FlushInterval: 10 * time.Millisecond,
	})

	limiter := ratelimit.New(ratelimit.Config{Burst: 3})
	issuer := auth.NewTokenIssuer([]byte(strings.Repeat("k", 48)), 15*time.Minute)

	secrets := service.NewSecretService(store, authz, keyring, audit)
	projects := service.NewProjectService(store, authz, audit)

	router := vaultlyhttp.NewRouter(vaultlyhttp.RouterDeps{
		Config: &config.Config{
			Environment:        config.EnvTest,
			CORSAllowedOrigins: []string{"http://localhost:3000"},
			TrustProxy:         false,
		},
		Services: vaultlyhttp.Services{
			Auth:       service.NewAuthService(store, issuer, audit, logger, time.Hour),
			Workspaces: service.NewWorkspaceService(store, authz, audit),
			Projects:   projects,
			Secrets:    secrets,
			Promotion:  service.NewPromotionService(store, authz, secrets, projects, keyring, audit),
			Tokens:     service.NewTokenService(store, authz, secrets, projects, audit),
			Audit:      service.NewAuditService(store, authz),
		},
		Issuer:  issuer,
		Limiter: limiter,
		Pool:    pool,
		Logger:  logger,
	})

	server := httptest.NewServer(router)

	h := &harness{t: t, server: server, pool: pool, audit: audit}
	t.Cleanup(func() {
		server.Close()
		audit.Close()
		limiter.Close()
		pool.Close()
	})
	return h
}

// waitForAudit gives the background writer a moment to drain, since audit
// writes are deliberately off the request path.
func (h *harness) waitForAudit() {
	time.Sleep(150 * time.Millisecond)
}

// client is an API client that keeps its own cookies, so several clients in
// one test act as genuinely different users.
type client struct {
	t       *testing.T
	base    string
	cookies map[string]string
	bearer  string
}

func (h *harness) client() *client {
	return &client{t: h.t, base: h.server.URL, cookies: map[string]string{}}
}

// do issues a request and decodes the JSON response body.
func (c *client) do(method, path string, body any) (int, map[string]any) {
	c.t.Helper()

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			c.t.Fatalf("encode body: %v", err)
		}
		reader = strings.NewReader(string(encoded))
	}

	req, err := http.NewRequest(method, c.base+path, reader)
	if err != nil {
		c.t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for name, value := range c.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()

	for _, cookie := range resp.Cookies() {
		if cookie.MaxAge < 0 {
			delete(c.cookies, cookie.Name)
			continue
		}
		c.cookies[cookie.Name] = cookie.Value
	}

	raw, _ := io.ReadAll(resp.Body)
	decoded := map[string]any{}
	if len(raw) > 0 {
		// A non-JSON body (the dotenv rendering) is returned under a known key
		// so tests can still assert on it.
		if err := json.Unmarshal(raw, &decoded); err != nil {
			decoded = map[string]any{"_raw": string(raw)}
		}
	}
	return resp.StatusCode, decoded
}

// mustDo fails the test unless the response has the expected status.
func (c *client) mustDo(method, path string, body any, wantStatus int) map[string]any {
	c.t.Helper()
	status, decoded := c.do(method, path, body)
	if status != wantStatus {
		c.t.Fatalf("%s %s: status %d, want %d (body: %v)", method, path, status, wantStatus, decoded)
	}
	return decoded
}

// registerUser creates an account and leaves the client authenticated as it.
func (c *client) registerUser(email string) map[string]any {
	c.t.Helper()
	return c.mustDo(http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":    email,
		"password": "a-sufficiently-long-password",
		"name":     "Test User",
	}, http.StatusCreated)
}

// uniqueEmail keeps accounts from colliding across tests sharing a database.
func uniqueEmail(prefix string) string {
	return fmt.Sprintf("%s-%d@example.com", prefix, time.Now().UnixNano())
}

// --- Small navigation helpers ----------------------------------------------

func dig(t *testing.T, m map[string]any, path ...string) any {
	t.Helper()
	var current any = m
	for _, key := range path {
		asMap, ok := current.(map[string]any)
		if !ok {
			t.Fatalf("cannot descend into %q: not an object (%T)", key, current)
		}
		current, ok = asMap[key]
		if !ok {
			t.Fatalf("key %q not present in %v", key, asMap)
		}
	}
	return current
}

func digString(t *testing.T, m map[string]any, path ...string) string {
	t.Helper()
	value, ok := dig(t, m, path...).(string)
	if !ok {
		t.Fatalf("value at %v is not a string", path)
	}
	return value
}

func digFloat(t *testing.T, m map[string]any, path ...string) float64 {
	t.Helper()
	value, ok := dig(t, m, path...).(float64)
	if !ok {
		t.Fatalf("value at %v is not a number", path)
	}
	return value
}

func digSlice(t *testing.T, m map[string]any, path ...string) []any {
	t.Helper()
	value, ok := dig(t, m, path...).([]any)
	if !ok {
		t.Fatalf("value at %v is not an array", path)
	}
	return value
}

// firstWorkspaceID returns the workspace created alongside the account.
func (c *client) firstWorkspaceID() string {
	c.t.Helper()
	body := c.mustDo(http.MethodGet, "/api/v1/workspaces", nil, http.StatusOK)
	workspaces := digSlice(c.t, body, "workspaces")
	if len(workspaces) == 0 {
		c.t.Fatal("no workspace was created with the account")
	}
	return workspaces[0].(map[string]any)["id"].(string)
}

// newProject creates a project and returns its id along with its environments
// keyed by name.
func (c *client) newProject(workspaceID, name string) (string, map[string]string) {
	c.t.Helper()

	body := c.mustDo(http.MethodPost, "/api/v1/workspaces/"+workspaceID+"/projects",
		map[string]any{"name": name}, http.StatusCreated)
	projectID := digString(c.t, body, "project", "id")

	envBody := c.mustDo(http.MethodGet, "/api/v1/projects/"+projectID+"/environments", nil, http.StatusOK)
	environments := map[string]string{}
	for _, raw := range digSlice(c.t, envBody, "environments") {
		env := raw.(map[string]any)
		environments[env["name"].(string)] = env["id"].(string)
	}
	return projectID, environments
}

// createSecret stores a secret and returns its id.
func (c *client) createSecret(environmentID, key, value string) string {
	c.t.Helper()
	body := c.mustDo(http.MethodPost, "/api/v1/environments/"+environmentID+"/secrets",
		map[string]any{"key": key, "value": value}, http.StatusCreated)
	return digString(c.t, body, "secret", "id")
}
