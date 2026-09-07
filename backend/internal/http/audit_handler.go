package http

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"vaultly/backend/internal/service"
)

// AuditHandler serves the activity feed.
type AuditHandler struct {
	audit *service.AuditService
}

// NewAuditHandler builds an AuditHandler.
func NewAuditHandler(audit *service.AuditService) *AuditHandler {
	return &AuditHandler{audit: audit}
}

// List returns a page of audit entries, newest first.
func (h *AuditHandler) List(c *gin.Context) {
	workspaceID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	filter := service.AuditFilter{
		Action:       c.Query("action"),
		ResourceType: c.Query("resourceType"),
	}

	if raw := c.Query("actorUserId"); raw != "" {
		actorID, err := uuid.Parse(raw)
		if err != nil {
			respondValidation(c, "actorUserId", "must be a valid identifier")
			return
		}
		filter.ActorUserID = &actorID
	}

	if raw := c.Query("resourceId"); raw != "" {
		resourceID, err := uuid.Parse(raw)
		if err != nil {
			respondValidation(c, "resourceId", "must be a valid identifier")
			return
		}
		filter.ResourceID = &resourceID
	}

	if raw := c.Query("limit"); raw != "" {
		limit, err := strconv.ParseInt(raw, 10, 32)
		if err != nil || limit < 1 {
			respondValidation(c, "limit", "must be a positive integer")
			return
		}
		filter.Limit = int32(limit)
	}

	// The cursor encodes the last row of the previous page, so paging stays
	// stable while new entries are being appended.
	createdAt, id, err := service.DecodeAuditCursor(c.Query("cursor"))
	if err != nil {
		respondError(c, err)
		return
	}
	filter.BeforeCreatedAt = createdAt
	filter.BeforeID = id

	page, err := h.audit.List(c.Request.Context(), UserID(c), workspaceID, filter)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, page)
}

// Actions lists the distinct actions recorded in a workspace, for the feed's
// filter dropdown.
func (h *AuditHandler) Actions(c *gin.Context) {
	workspaceID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	actions, err := h.audit.Actions(c.Request.Context(), UserID(c), workspaceID)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"actions": actions})
}
