//go:build integration

package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestAuthFlow(t *testing.T) {
	h := newHarness(t)
	c := h.client()

	email := uniqueEmail("auth")
	body := c.registerUser(email)
	if got := digString(t, body, "user", "email"); got != email {
		t.Errorf("email = %q, want %q", got, email)
	}

	// The session must travel only as cookies. A token in the JSON body would
	// be readable by page scripts, which is exactly what this design avoids.
	if _, present := body["accessToken"]; present {
		t.Error("registration response leaked an access token in its body")
	}
	if _, present := body["refreshToken"]; present {
		t.Error("registration response leaked a refresh token in its body")
	}

	me := c.mustDo(http.MethodGet, "/api/v1/auth/me", nil, http.StatusOK)
	if got := digString(t, me, "user", "email"); got != email {
		t.Errorf("me email = %q, want %q", got, email)
	}

	// Refresh must rotate: the old refresh token stops working afterwards.
	previousRefresh := c.cookies["vaultly_refresh"]
	c.mustDo(http.MethodPost, "/api/v1/auth/refresh", nil, http.StatusOK)
	if c.cookies["vaultly_refresh"] == previousRefresh {
		t.Error("refresh did not rotate the refresh token")
	}

	stale := h.client()
	stale.cookies["vaultly_refresh"] = previousRefresh
	if status, _ := stale.do(http.MethodPost, "/api/v1/auth/refresh", nil); status != http.StatusUnauthorized {
		t.Errorf("replaying a spent refresh token: status %d, want 401", status)
	}

	c.mustDo(http.MethodPost, "/api/v1/auth/logout", nil, http.StatusNoContent)
	if status, _ := c.do(http.MethodGet, "/api/v1/auth/me", nil); status != http.StatusUnauthorized {
		t.Errorf("after logout: status %d, want 401", status)
	}
}

func TestRegistrationRejectsDuplicateEmail(t *testing.T) {
	h := newHarness(t)
	email := uniqueEmail("dup")

	h.client().registerUser(email)

	status, body := h.client().do(http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email": email, "password": "a-sufficiently-long-password", "name": "Other",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 (body %v)", status, body)
	}
	if !strings.Contains(strings.ToLower(digString(t, body, "fields", "email")), "already registered") {
		t.Errorf("unexpected message: %v", body["fields"])
	}
}

func TestLoginDoesNotDistinguishUnknownEmailFromWrongPassword(t *testing.T) {
	h := newHarness(t)
	email := uniqueEmail("enum")
	h.client().registerUser(email)

	// Both failures must be indistinguishable, or the endpoint becomes an
	// account enumeration oracle.
	_, wrongPassword := h.client().do(http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email": email, "password": "definitely-the-wrong-password",
	})
	_, unknownEmail := h.client().do(http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email": uniqueEmail("nobody"), "password": "definitely-the-wrong-password",
	})

	if wrongPassword["error"] != unknownEmail["error"] {
		t.Errorf("responses differ: %v vs %v", wrongPassword["error"], unknownEmail["error"])
	}
}

func TestSecretLifecycle(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	c.registerUser(uniqueEmail("secrets"))

	workspaceID := c.firstWorkspaceID()
	_, environments := c.newProject(workspaceID, "Lifecycle")
	dev := environments["development"]

	secretID := c.createSecret(dev, "API_KEY", "first-value")

	// A listing must never carry values.
	list := c.mustDo(http.MethodGet, "/api/v1/environments/"+dev+"/secrets", nil, http.StatusOK)
	for _, raw := range digSlice(t, list, "secrets") {
		if _, present := raw.(map[string]any)["value"]; present {
			t.Fatal("the secret listing included a value")
		}
	}

	revealed := c.mustDo(http.MethodGet, "/api/v1/secrets/"+secretID+"/reveal", nil, http.StatusOK)
	if got := digString(t, revealed, "secret", "value"); got != "first-value" {
		t.Errorf("value = %q, want first-value", got)
	}

	c.mustDo(http.MethodPut, "/api/v1/secrets/"+secretID,
		map[string]any{"value": "second-value", "comment": "rotated"}, http.StatusOK)
	c.mustDo(http.MethodPut, "/api/v1/secrets/"+secretID,
		map[string]any{"value": "third-value"}, http.StatusOK)

	versions := digSlice(t, c.mustDo(http.MethodGet,
		"/api/v1/secrets/"+secretID+"/versions", nil, http.StatusOK), "versions")
	if len(versions) != 3 {
		t.Fatalf("version count = %d, want 3", len(versions))
	}

	// Every historical value must remain readable; that is what the diff view
	// depends on.
	for version, want := range map[string]string{"1": "first-value", "2": "second-value", "3": "third-value"} {
		body := c.mustDo(http.MethodGet,
			"/api/v1/secrets/"+secretID+"/versions/"+version, nil, http.StatusOK)
		if got := digString(t, body, "version", "value"); got != want {
			t.Errorf("version %s = %q, want %q", version, got, want)
		}
	}

	// Rolling back appends rather than rewinding, so history keeps growing.
	rolled := c.mustDo(http.MethodPost,
		"/api/v1/secrets/"+secretID+"/versions/1/rollback", nil, http.StatusOK)
	if got := digFloat(t, rolled, "secret", "currentVersion"); got != 4 {
		t.Errorf("currentVersion after rollback = %v, want 4", got)
	}

	revealed = c.mustDo(http.MethodGet, "/api/v1/secrets/"+secretID+"/reveal", nil, http.StatusOK)
	if got := digString(t, revealed, "secret", "value"); got != "first-value" {
		t.Errorf("value after rollback = %q, want first-value", got)
	}

	c.mustDo(http.MethodDelete, "/api/v1/secrets/"+secretID, nil, http.StatusNoContent)
	if status, _ := c.do(http.MethodGet, "/api/v1/secrets/"+secretID+"/reveal", nil); status != http.StatusNotFound {
		t.Errorf("reveal after delete: status %d, want 404", status)
	}
}

func TestSecretsAreEncryptedAtRest(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	c.registerUser(uniqueEmail("atrest"))

	workspaceID := c.firstWorkspaceID()
	_, environments := c.newProject(workspaceID, "At Rest")

	const plaintext = "a-very-recognisable-secret-value"
	c.createSecret(environments["development"], "RECOGNISABLE", plaintext)

	// Read straight from the table: whatever is stored must not contain the
	// plaintext in any form.
	var matches int
	err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM secret_versions
		 WHERE position($1::bytea in ciphertext) > 0`, []byte(plaintext)).Scan(&matches)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if matches != 0 {
		t.Fatalf("found the plaintext in %d stored ciphertexts", matches)
	}
}

func TestOptimisticConcurrency(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	c.registerUser(uniqueEmail("concurrency"))

	_, environments := c.newProject(c.firstWorkspaceID(), "Concurrency")
	secretID := c.createSecret(environments["development"], "SHARED", "original")

	// Someone else writes first.
	c.mustDo(http.MethodPut, "/api/v1/secrets/"+secretID,
		map[string]any{"value": "written-by-someone-else"}, http.StatusOK)

	// Our write was based on version 1, which is no longer current.
	status, _ := c.do(http.MethodPut, "/api/v1/secrets/"+secretID,
		map[string]any{"value": "our-stale-write", "expectedVersion": 1})
	if status != http.StatusConflict {
		t.Fatalf("stale write: status %d, want 409", status)
	}

	// The earlier write must survive our rejected one.
	revealed := c.mustDo(http.MethodGet, "/api/v1/secrets/"+secretID+"/reveal", nil, http.StatusOK)
	if got := digString(t, revealed, "secret", "value"); got != "written-by-someone-else" {
		t.Errorf("value = %q, want the value written by the other writer", got)
	}

	// Writing against the current version succeeds.
	c.mustDo(http.MethodPut, "/api/v1/secrets/"+secretID,
		map[string]any{"value": "our-fresh-write", "expectedVersion": 2}, http.StatusOK)
}

func TestPromotion(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	c.registerUser(uniqueEmail("promote"))

	projectID, environments := c.newProject(c.firstWorkspaceID(), "Promotion")
	dev, staging, prod := environments["development"], environments["staging"], environments["production"]

	c.createSecret(dev, "ALPHA", "alpha-value")
	c.createSecret(dev, "BETA", "beta-value")

	// A dry run must report the plan and change nothing.
	plan := c.mustDo(http.MethodPost, "/api/v1/projects/"+projectID+"/promote", map[string]any{
		"sourceEnvironmentId": dev, "targetEnvironmentId": staging, "dryRun": true,
	}, http.StatusOK)
	if applied := digFloat(t, plan, "plan", "applied"); applied != 0 {
		t.Errorf("dry run applied %v changes, want 0", applied)
	}
	for _, raw := range digSlice(t, plan, "plan", "changes") {
		if got := raw.(map[string]any)["type"]; got != "added" {
			t.Errorf("change type = %v, want added", got)
		}
	}
	if listed := digSlice(t, c.mustDo(http.MethodGet,
		"/api/v1/environments/"+staging+"/secrets", nil, http.StatusOK), "secrets"); len(listed) != 0 {
		t.Fatalf("dry run wrote %d secrets into staging", len(listed))
	}

	// Applying it copies the values across.
	plan = c.mustDo(http.MethodPost, "/api/v1/projects/"+projectID+"/promote", map[string]any{
		"sourceEnvironmentId": dev, "targetEnvironmentId": staging,
	}, http.StatusOK)
	if applied := digFloat(t, plan, "plan", "applied"); applied != 2 {
		t.Errorf("applied = %v, want 2", applied)
	}

	staged := digSlice(t, c.mustDo(http.MethodGet,
		"/api/v1/environments/"+staging+"/secrets", nil, http.StatusOK), "secrets")
	if len(staged) != 2 {
		t.Fatalf("staging holds %d secrets, want 2", len(staged))
	}
	for _, raw := range staged {
		secret := raw.(map[string]any)
		revealed := c.mustDo(http.MethodGet,
			"/api/v1/secrets/"+secret["id"].(string)+"/reveal", nil, http.StatusOK)
		want := strings.ToLower(secret["key"].(string)) + "-value"
		if got := digString(t, revealed, "secret", "value"); got != want {
			t.Errorf("%s = %q, want %q", secret["key"], got, want)
		}
	}

	// Promoting again changes nothing, so no pointless versions are written.
	plan = c.mustDo(http.MethodPost, "/api/v1/projects/"+projectID+"/promote", map[string]any{
		"sourceEnvironmentId": dev, "targetEnvironmentId": staging,
	}, http.StatusOK)
	if applied := digFloat(t, plan, "plan", "applied"); applied != 0 {
		t.Errorf("re-promotion applied %v changes, want 0", applied)
	}

	// Promotion is directional: prod may not be pushed back down to dev.
	status, _ := c.do(http.MethodPost, "/api/v1/projects/"+projectID+"/promote", map[string]any{
		"sourceEnvironmentId": prod, "targetEnvironmentId": dev, "dryRun": true,
	})
	if status != http.StatusBadRequest {
		t.Errorf("backwards promotion: status %d, want 400", status)
	}

	// A changed source value shows as changed rather than added.
	c.mustDo(http.MethodPut, "/api/v1/secrets/"+staged[0].(map[string]any)["id"].(string),
		map[string]any{"value": "edited-in-staging"}, http.StatusOK)
	plan = c.mustDo(http.MethodPost, "/api/v1/projects/"+projectID+"/promote", map[string]any{
		"sourceEnvironmentId": dev, "targetEnvironmentId": staging, "dryRun": true,
	}, http.StatusOK)
	var sawChanged bool
	for _, raw := range digSlice(t, plan, "plan", "changes") {
		if raw.(map[string]any)["type"] == "changed" {
			sawChanged = true
		}
	}
	if !sawChanged {
		t.Error("an edited target value was not reported as changed")
	}
}

func TestRoleBasedAccess(t *testing.T) {
	h := newHarness(t)

	owner := h.client()
	owner.registerUser(uniqueEmail("owner"))
	workspaceID := owner.firstWorkspaceID()
	projectID, environments := owner.newProject(workspaceID, "Roles")
	dev := environments["development"]
	secretID := owner.createSecret(dev, "PRIVATE_KEY", "the-value")

	viewerEmail := uniqueEmail("viewer")
	viewer := h.client()
	viewer.registerUser(viewerEmail)

	owner.mustDo(http.MethodPost, "/api/v1/workspaces/"+workspaceID+"/members",
		map[string]any{"email": viewerEmail, "role": "viewer"}, http.StatusCreated)

	// A viewer sees that a secret exists and how it has changed, but never its
	// value. That distinction is the whole point of the role.
	listed := digSlice(t, viewer.mustDo(http.MethodGet,
		"/api/v1/environments/"+dev+"/secrets", nil, http.StatusOK), "secrets")
	if len(listed) != 1 {
		t.Fatalf("viewer sees %d secrets, want 1", len(listed))
	}
	viewer.mustDo(http.MethodGet, "/api/v1/secrets/"+secretID+"/versions", nil, http.StatusOK)

	forbidden := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{"reveal a value", http.MethodGet, "/api/v1/secrets/" + secretID + "/reveal", nil},
		{"reveal a version", http.MethodGet, "/api/v1/secrets/" + secretID + "/versions/1", nil},
		{"create a secret", http.MethodPost, "/api/v1/environments/" + dev + "/secrets",
			map[string]any{"key": "NEW_KEY", "value": "x"}},
		{"update a secret", http.MethodPut, "/api/v1/secrets/" + secretID,
			map[string]any{"value": "x"}},
		{"delete a secret", http.MethodDelete, "/api/v1/secrets/" + secretID, nil},
		{"mint a token", http.MethodPost, "/api/v1/projects/" + projectID + "/tokens",
			map[string]any{"environmentId": dev, "name": "x", "scopes": []string{"secrets:read"}}},
		{"promote", http.MethodPost, "/api/v1/projects/" + projectID + "/promote",
			map[string]any{"sourceEnvironmentId": dev, "targetEnvironmentId": environments["staging"]}},
	}
	for _, tc := range forbidden {
		t.Run("viewer cannot "+tc.name, func(t *testing.T) {
			status, _ := viewer.do(tc.method, tc.path, tc.body)
			if status != http.StatusForbidden {
				t.Errorf("status %d, want 403", status)
			}
		})
	}

	// A complete outsider must not even learn that the workspace exists.
	outsider := h.client()
	outsider.registerUser(uniqueEmail("outsider"))
	for _, path := range []string{
		"/api/v1/workspaces/" + workspaceID,
		"/api/v1/projects/" + projectID,
		"/api/v1/environments/" + dev + "/secrets",
	} {
		if status, _ := outsider.do(http.MethodGet, path, nil); status != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404 for a non-member", path, status)
		}
	}
}

func TestUnauthenticatedRequestsAreRejected(t *testing.T) {
	h := newHarness(t)
	anonymous := h.client()

	for _, path := range []string{
		"/api/v1/auth/me",
		"/api/v1/workspaces",
		"/api/v1/cicd/secrets",
	} {
		if status, _ := anonymous.do(http.MethodGet, path, nil); status != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", path, status)
		}
	}
}
