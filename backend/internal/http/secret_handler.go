package http

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"vaultly/backend/internal/service"
)

// SecretHandler serves secret, version and promotion endpoints.
type SecretHandler struct {
	secrets   *service.SecretService
	promotion *service.PromotionService
}

// NewSecretHandler builds a SecretHandler.
func NewSecretHandler(secrets *service.SecretService, promotion *service.PromotionService) *SecretHandler {
	return &SecretHandler{secrets: secrets, promotion: promotion}
}

// List returns an environment's secrets as metadata only, without values.
func (h *SecretHandler) List(c *gin.Context) {
	environmentID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	secrets, err := h.secrets.List(c.Request.Context(), UserID(c), environmentID)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"secrets": secrets})
}

type createSecretRequest struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Description string `json:"description"`
}

// Create stores a new secret.
func (h *SecretHandler) Create(c *gin.Context) {
	environmentID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	var req createSecretRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondValidation(c, "body", "must be a valid JSON object")
		return
	}

	secret, err := h.secrets.Create(c.Request.Context(), UserID(c), service.CreateSecretInput{
		EnvironmentID: environmentID,
		Key:           req.Key,
		Value:         req.Value,
		Description:   req.Description,
		Actor:         actorFrom(c),
	})
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"secret": secret})
}

// Get returns a secret's metadata. It exists so a client can resolve a
// secret's project and environment without revealing the value, which would
// otherwise be recorded as a read it never intended.
func (h *SecretHandler) Get(c *gin.Context) {
	secretID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	secret, err := h.secrets.Get(c.Request.Context(), UserID(c), secretID)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"secret": secret})
}

// Reveal returns a secret's current value. This is the endpoint the masked
// display calls when a user clicks to reveal, and every call is audited.
func (h *SecretHandler) Reveal(c *gin.Context) {
	secretID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	secret, err := h.secrets.Reveal(c.Request.Context(), UserID(c), secretID, actorFrom(c))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"secret": secret})
}

type updateSecretRequest struct {
	Value   string `json:"value"`
	Comment string `json:"comment"`
	// ExpectedVersion carries the version the client last saw. When present it
	// turns a blind overwrite into a detectable conflict.
	ExpectedVersion int32 `json:"expectedVersion"`
}

// Update appends a new version with a new value.
func (h *SecretHandler) Update(c *gin.Context) {
	secretID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	var req updateSecretRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondValidation(c, "body", "must be a valid JSON object")
		return
	}

	secret, err := h.secrets.Update(c.Request.Context(), UserID(c), service.UpdateSecretInput{
		SecretID:        secretID,
		Value:           req.Value,
		Comment:         req.Comment,
		ExpectedVersion: req.ExpectedVersion,
		Actor:           actorFrom(c),
	})
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"secret": secret})
}

type updateDescriptionRequest struct {
	Description string `json:"description"`
}

// UpdateDescription changes a secret's description without creating a version.
func (h *SecretHandler) UpdateDescription(c *gin.Context) {
	secretID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	var req updateDescriptionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondValidation(c, "body", "must be a valid JSON object")
		return
	}

	if err := h.secrets.UpdateDescription(c.Request.Context(), UserID(c), secretID, req.Description); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// Delete soft-deletes a secret.
func (h *SecretHandler) Delete(c *gin.Context) {
	secretID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	if err := h.secrets.Delete(c.Request.Context(), UserID(c), secretID, actorFrom(c)); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// ListVersions returns a secret's history without any values.
func (h *SecretHandler) ListVersions(c *gin.Context) {
	secretID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	versions, err := h.secrets.ListVersions(c.Request.Context(), UserID(c), secretID)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"versions": versions})
}

// RevealVersion returns the value stored at one version, which is what the
// diff view fetches for each side of a comparison.
func (h *SecretHandler) RevealVersion(c *gin.Context) {
	secretID, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	version, ok := int32Param(c, "version")
	if !ok {
		return
	}

	revealed, err := h.secrets.RevealVersion(c.Request.Context(), UserID(c), secretID, version, actorFrom(c))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"version": revealed})
}

// Rollback restores an earlier version as a new version.
func (h *SecretHandler) Rollback(c *gin.Context) {
	secretID, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	version, ok := int32Param(c, "version")
	if !ok {
		return
	}

	secret, err := h.secrets.Rollback(c.Request.Context(), UserID(c), secretID, version, actorFrom(c))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"secret": secret})
}

type promoteRequest struct {
	SourceEnvironmentID string   `json:"sourceEnvironmentId"`
	TargetEnvironmentID string   `json:"targetEnvironmentId"`
	Keys                []string `json:"keys"`
	DryRun              bool     `json:"dryRun"`
	IncludeValues       bool     `json:"includeValues"`
}

// Promote copies values from one environment to the next.
func (h *SecretHandler) Promote(c *gin.Context) {
	projectID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	var req promoteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondValidation(c, "body", "must be a valid JSON object")
		return
	}

	sourceID, ok := parseUUID(c, "sourceEnvironmentId", req.SourceEnvironmentID)
	if !ok {
		return
	}
	targetID, ok := parseUUID(c, "targetEnvironmentId", req.TargetEnvironmentID)
	if !ok {
		return
	}

	plan, err := h.promotion.Promote(c.Request.Context(), UserID(c), service.PromoteInput{
		ProjectID:     projectID,
		SourceEnvID:   sourceID,
		TargetEnvID:   targetID,
		Keys:          req.Keys,
		DryRun:        req.DryRun,
		IncludeValues: req.IncludeValues,
		Actor:         actorFrom(c),
	})
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"plan": plan})
}

// int32Param reads an integer path parameter.
func int32Param(c *gin.Context, name string) (int32, bool) {
	parsed, err := strconv.ParseInt(c.Param(name), 10, 32)
	if err != nil || parsed < 1 {
		respondValidation(c, name, "must be a positive integer")
		return 0, false
	}
	return int32(parsed), true
}
