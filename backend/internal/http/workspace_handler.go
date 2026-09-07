package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"vaultly/backend/internal/domain"
	"vaultly/backend/internal/service"
)

// WorkspaceHandler serves workspace and membership endpoints.
type WorkspaceHandler struct {
	workspaces *service.WorkspaceService
}

// NewWorkspaceHandler builds a WorkspaceHandler.
func NewWorkspaceHandler(workspaces *service.WorkspaceService) *WorkspaceHandler {
	return &WorkspaceHandler{workspaces: workspaces}
}

// List returns the caller's workspaces.
func (h *WorkspaceHandler) List(c *gin.Context) {
	workspaces, err := h.workspaces.List(c.Request.Context(), UserID(c))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"workspaces": workspaces})
}

// Get returns one workspace.
func (h *WorkspaceHandler) Get(c *gin.Context) {
	workspaceID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	workspace, err := h.workspaces.Get(c.Request.Context(), UserID(c), workspaceID)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"workspace": workspace})
}

type createWorkspaceRequest struct {
	Name string `json:"name"`
}

// Create makes a workspace owned by the caller.
func (h *WorkspaceHandler) Create(c *gin.Context) {
	var req createWorkspaceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondValidation(c, "body", "must be a valid JSON object")
		return
	}

	workspace, err := h.workspaces.Create(c.Request.Context(), UserID(c), req.Name, actorFrom(c))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"workspace": workspace})
}

// ListMembers returns a workspace's members.
func (h *WorkspaceHandler) ListMembers(c *gin.Context) {
	workspaceID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	members, err := h.workspaces.ListMembers(c.Request.Context(), UserID(c), workspaceID)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"members": members})
}

type addMemberRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

// AddMember adds an existing user to a workspace.
func (h *WorkspaceHandler) AddMember(c *gin.Context) {
	workspaceID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	var req addMemberRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondValidation(c, "body", "must be a valid JSON object")
		return
	}

	member, err := h.workspaces.AddMember(c.Request.Context(), UserID(c), workspaceID,
		req.Email, domain.Role(req.Role), actorFrom(c))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"member": member})
}

type updateMemberRequest struct {
	Role string `json:"role"`
}

// UpdateMember changes a member's role.
func (h *WorkspaceHandler) UpdateMember(c *gin.Context) {
	workspaceID, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	memberID, ok := uuidParam(c, "memberId")
	if !ok {
		return
	}

	var req updateMemberRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondValidation(c, "body", "must be a valid JSON object")
		return
	}

	if err := h.workspaces.UpdateMemberRole(c.Request.Context(), UserID(c), workspaceID,
		memberID, domain.Role(req.Role), actorFrom(c)); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// RemoveMember removes a member from a workspace.
func (h *WorkspaceHandler) RemoveMember(c *gin.Context) {
	workspaceID, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	memberID, ok := uuidParam(c, "memberId")
	if !ok {
		return
	}

	if err := h.workspaces.RemoveMember(c.Request.Context(), UserID(c), workspaceID,
		memberID, actorFrom(c)); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// uuidParam reads a UUID path parameter, writing a validation error and
// returning false when it is malformed. Doing this once means no handler has
// to hand-roll the check, and a bad identifier never reaches a query.
func uuidParam(c *gin.Context, name string) (uuid.UUID, bool) {
	raw := c.Param(name)
	parsed, err := uuid.Parse(raw)
	if err != nil {
		respondValidation(c, name, "must be a valid identifier")
		return uuid.Nil, false
	}
	return parsed, true
}
