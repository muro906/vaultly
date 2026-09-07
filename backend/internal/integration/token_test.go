//go:build integration

package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// mintToken creates an access token and returns its plaintext and id.
func mintToken(t *testing.T, c *client, projectID, environmentID string, overrides map[string]any) (string, string) {
	t.Helper()

	body := map[string]any{
		"environmentId": environmentID,
		"name":          "ci",
		"scopes":        []string{"secrets:read"},
	}
	for key, value := range overrides {
		body[key] = value
	}

	created := c.mustDo(http.MethodPost, "/api/v1/projects/"+projectID+"/tokens", body, http.StatusCreated)
	return digString(t, created, "token", "plaintext"), digString(t, created, "token", "id")
}

func TestAccessTokenPullsSecrets(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	c.registerUser(uniqueEmail("token"))

	projectID, environments := c.newProject(c.firstWorkspaceID(), "Tokens")
	dev := environments["development"]
	c.createSecret(dev, "ALPHA", "alpha-value")
	c.createSecret(dev, "BETA", "beta value with spaces")

	plaintext, tokenID := mintToken(t, c, projectID, dev, nil)

	if !strings.HasPrefix(plaintext, "vlt_") {
		t.Errorf("token %q does not carry the vlt_ marker", plaintext)
	}

	// The plaintext is shown once and never again.
	listed := digSlice(t, c.mustDo(http.MethodGet,
		"/api/v1/projects/"+projectID+"/tokens", nil, http.StatusOK), "tokens")
	for _, raw := range listed {
		if value, present := raw.(map[string]any)["plaintext"]; present && value != "" {
			t.Error("listing tokens returned a plaintext token")
		}
	}

	// Only the digest is stored, so the token itself must not be in the table.
	var matches int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM access_tokens WHERE token_hash = $1::bytea`,
		[]byte(plaintext)).Scan(&matches); err != nil {
		t.Fatalf("query: %v", err)
	}
	if matches != 0 {
		t.Error("the raw token was stored rather than its digest")
	}

	machine := h.client()
	machine.bearer = plaintext

	pulled := machine.mustDo(http.MethodGet, "/api/v1/cicd/secrets", nil, http.StatusOK)
	secrets, ok := dig(t, pulled, "secrets").(map[string]any)
	if !ok {
		t.Fatalf("secrets is not an object: %v", pulled)
	}
	if secrets["ALPHA"] != "alpha-value" {
		t.Errorf("ALPHA = %v, want alpha-value", secrets["ALPHA"])
	}

	// The dotenv rendering must quote values, or a shell sourcing the file
	// would split on the space and substitute on any $ or #.
	dotenv := h.client()
	dotenv.bearer = plaintext
	rendered := dotenv.mustDo(http.MethodGet, "/api/v1/cicd/secrets?format=dotenv", nil, http.StatusOK)
	raw, _ := rendered["_raw"].(string)
	if !strings.Contains(raw, `BETA='beta value with spaces'`) {
		t.Errorf("dotenv output did not quote the value:\n%s", raw)
	}

	// Revoking takes effect immediately.
	c.mustDo(http.MethodDelete, "/api/v1/tokens/"+tokenID, nil, http.StatusNoContent)
	if status, _ := machine.do(http.MethodGet, "/api/v1/cicd/secrets", nil); status != http.StatusUnauthorized {
		t.Errorf("after revoke: status %d, want 401", status)
	}
}

func TestAccessTokenScopeIsEnforced(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	c.registerUser(uniqueEmail("scope"))

	projectID, environments := c.newProject(c.firstWorkspaceID(), "Scopes")
	dev := environments["development"]
	c.createSecret(dev, "ALPHA", "alpha-value")

	// A write-only token must not be able to read.
	plaintext, _ := mintToken(t, c, projectID, dev, map[string]any{
		"scopes": []string{"secrets:write"},
	})

	machine := h.client()
	machine.bearer = plaintext
	if status, _ := machine.do(http.MethodGet, "/api/v1/cicd/secrets", nil); status != http.StatusForbidden {
		t.Errorf("write-only token reading secrets: status %d, want 403", status)
	}
}

func TestAccessTokenIsScopedToOneEnvironment(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	c.registerUser(uniqueEmail("envscope"))

	projectID, environments := c.newProject(c.firstWorkspaceID(), "Env Scope")
	c.createSecret(environments["development"], "DEV_ONLY", "dev-value")
	c.createSecret(environments["staging"], "STAGING_ONLY", "staging-value")

	plaintext, _ := mintToken(t, c, projectID, environments["staging"], nil)

	machine := h.client()
	machine.bearer = plaintext
	pulled := machine.mustDo(http.MethodGet, "/api/v1/cicd/secrets", nil, http.StatusOK)

	secrets := dig(t, pulled, "secrets").(map[string]any)
	if _, present := secrets["DEV_ONLY"]; present {
		t.Error("a staging-scoped token returned a development secret")
	}
	if secrets["STAGING_ONLY"] != "staging-value" {
		t.Errorf("STAGING_ONLY = %v, want staging-value", secrets["STAGING_ONLY"])
	}
}

func TestAccessTokenIPAllowlist(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	c.registerUser(uniqueEmail("allowlist"))

	projectID, environments := c.newProject(c.firstWorkspaceID(), "Allowlist")
	dev := environments["development"]
	c.createSecret(dev, "ALPHA", "alpha-value")

	// Requests arrive from loopback, so a documentation range excludes us.
	excluded, _ := mintToken(t, c, projectID, dev, map[string]any{
		"ipAllowlist": []string{"198.51.100.0/24"},
	})
	blocked := h.client()
	blocked.bearer = excluded
	if status, _ := blocked.do(http.MethodGet, "/api/v1/cicd/secrets", nil); status != http.StatusForbidden {
		t.Errorf("token from a disallowed address: status %d, want 403", status)
	}

	// Loopback is covered by these entries, so the same request now succeeds.
	included, _ := mintToken(t, c, projectID, dev, map[string]any{
		"ipAllowlist": []string{"127.0.0.1/32", "::1/128"},
	})
	permitted := h.client()
	permitted.bearer = included
	permitted.mustDo(http.MethodGet, "/api/v1/cicd/secrets", nil, http.StatusOK)

	// An empty allowlist means any address.
	anywhere, _ := mintToken(t, c, projectID, dev, nil)
	open := h.client()
	open.bearer = anywhere
	open.mustDo(http.MethodGet, "/api/v1/cicd/secrets", nil, http.StatusOK)
}

func TestAccessTokenRateLimit(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	c.registerUser(uniqueEmail("ratelimit"))

	projectID, environments := c.newProject(c.firstWorkspaceID(), "Rate Limit")
	dev := environments["development"]
	c.createSecret(dev, "ALPHA", "alpha-value")

	// One request per minute with the harness burst of 3: the fourth request
	// in quick succession must be refused.
	plaintext, _ := mintToken(t, c, projectID, dev, map[string]any{"rateLimitRpm": 1})

	machine := h.client()
	machine.bearer = plaintext

	var allowed, limited int
	for i := 0; i < 8; i++ {
		status, _ := machine.do(http.MethodGet, "/api/v1/cicd/secrets", nil)
		switch status {
		case http.StatusOK:
			allowed++
		case http.StatusTooManyRequests:
			limited++
		default:
			t.Fatalf("unexpected status %d", status)
		}
	}

	if allowed == 0 {
		t.Error("every request was rate limited")
	}
	if limited == 0 {
		t.Error("no request was rate limited despite a 1 rpm token")
	}
}

func TestExpiredTokenIsRejected(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	c.registerUser(uniqueEmail("expiry"))

	projectID, environments := c.newProject(c.firstWorkspaceID(), "Expiry")

	// An expiry in the past must be refused at creation rather than minted and
	// then silently useless.
	status, _ := c.do(http.MethodPost, "/api/v1/projects/"+projectID+"/tokens", map[string]any{
		"environmentId": environments["development"],
		"name":          "already-expired",
		"scopes":        []string{"secrets:read"},
		"expiresAt":     time.Now().Add(-time.Hour).Format(time.RFC3339),
	})
	if status != http.StatusBadRequest {
		t.Errorf("creating a token expiring in the past: status %d, want 400", status)
	}
}

func TestAuditLogRecordsReadsAndWrites(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	c.registerUser(uniqueEmail("audit"))

	workspaceID := c.firstWorkspaceID()
	projectID, environments := c.newProject(workspaceID, "Audited")
	dev := environments["development"]

	secretID := c.createSecret(dev, "AUDITED_KEY", "value")
	c.mustDo(http.MethodGet, "/api/v1/secrets/"+secretID+"/reveal", nil, http.StatusOK)
	c.mustDo(http.MethodPut, "/api/v1/secrets/"+secretID,
		map[string]any{"value": "changed"}, http.StatusOK)

	plaintext, _ := mintToken(t, c, projectID, dev, nil)
	machine := h.client()
	machine.bearer = plaintext
	machine.mustDo(http.MethodGet, "/api/v1/cicd/secrets", nil, http.StatusOK)

	h.waitForAudit()

	page := c.mustDo(http.MethodGet,
		"/api/v1/workspaces/"+workspaceID+"/audit-logs?limit=100", nil, http.StatusOK)

	actions := map[string]bool{}
	var byToken, byUser int
	for _, raw := range digSlice(t, page, "entries") {
		entry := raw.(map[string]any)
		actions[entry["action"].(string)] = true
		if name, present := entry["actorTokenName"]; present && name != "" {
			byToken++
		}
		if email, present := entry["actorEmail"]; present && email != "" {
			byUser++
		}
	}

	// Reads must be recorded, not just writes: "who accessed what" is the
	// question the log exists to answer.
	for _, want := range []string{
		"user.registered", "project.created", "secret.created",
		"secret.read", "secret.updated", "token.created", "secrets.pulled",
	} {
		if !actions[want] {
			t.Errorf("audit log is missing the %q action (saw %v)", want, keysOf(actions))
		}
	}
	if byToken == 0 {
		t.Error("no audit entry was attributed to a machine token")
	}
	if byUser == 0 {
		t.Error("no audit entry was attributed to a user")
	}
}

func TestAuditLogPaginationDoesNotRepeatEntries(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	c.registerUser(uniqueEmail("paging"))

	workspaceID := c.firstWorkspaceID()
	_, environments := c.newProject(workspaceID, "Paging")
	dev := environments["development"]

	for i := 0; i < 12; i++ {
		c.createSecret(dev, "KEY_"+string(rune('A'+i)), "value")
	}
	h.waitForAudit()

	seen := map[string]bool{}
	cursor := ""

	for page := 0; page < 6; page++ {
		path := "/api/v1/workspaces/" + workspaceID + "/audit-logs?limit=5"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		body := c.mustDo(http.MethodGet, path, nil, http.StatusOK)

		entries := digSlice(t, body, "entries")
		for _, raw := range entries {
			id := raw.(map[string]any)["id"].(string)
			if seen[id] {
				t.Fatalf("entry %s was returned on more than one page", id)
			}
			seen[id] = true
		}

		next, _ := body["nextCursor"].(string)
		if next == "" {
			break
		}
		cursor = next
	}

	if len(seen) < 13 {
		t.Errorf("paged through %d entries, want at least 13", len(seen))
	}
}

func TestMalformedCursorIsRejected(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	c.registerUser(uniqueEmail("cursor"))
	workspaceID := c.firstWorkspaceID()

	// A broken cursor must surface as an error rather than silently paging
	// from the beginning, which would hide a client bug.
	status, _ := c.do(http.MethodGet,
		"/api/v1/workspaces/"+workspaceID+"/audit-logs?cursor=not-a-real-cursor", nil)
	if status != http.StatusBadRequest {
		t.Errorf("status %d, want 400", status)
	}
}

func keysOf(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}
