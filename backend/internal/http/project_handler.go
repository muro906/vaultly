package http

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"vaultly/backend/internal/service"
)

// ProjectHandler serves project and environment endpoints.
type ProjectHandler struct {
	projects *service.ProjectService
}

// NewProjectHandler builds a ProjectHandler.
func NewProjectHandler(projects *service.ProjectService) *ProjectHandler {
	return &ProjectHandler{projects: projects}
}

// List returns the projects in a workspace.
func (h *ProjectHandler) List(c *gin.Context) {
	workspaceID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	projects, err := h.projects.List(c.Request.Context(), UserID(c), workspaceID)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"projects": projects})
}

// Get returns one project.
func (h *ProjectHandler) Get(c *gin.Context) {
	projectID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	project, err := h.projects.Get(c.Request.Context(), UserID(c), projectID)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"project": project})
}

type createProjectRequest struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description"`
}

// Create makes a project with the default environments.
func (h *ProjectHandler) Create(c *gin.Context) {
	workspaceID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	var req createProjectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondValidation(c, "body", "must be a valid JSON object")
		return
	}

	project, err := h.projects.Create(c.Request.Context(), UserID(c), service.CreateProjectInput{
		WorkspaceID: workspaceID,
		Name:        req.Name,
		Slug:        req.Slug,
		Description: req.Description,
		Actor:       actorFrom(c),
	})
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"project": project})
}

type updateProjectRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Update changes a project's name and description.
func (h *ProjectHandler) Update(c *gin.Context) {
	projectID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	var req updateProjectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondValidation(c, "body", "must be a valid JSON object")
		return
	}

	project, err := h.projects.Update(c.Request.Context(), UserID(c), projectID,
		req.Name, req.Description, actorFrom(c))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"project": project})
}

// Delete soft-deletes a project.
func (h *ProjectHandler) Delete(c *gin.Context) {
	projectID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	if err := h.projects.Delete(c.Request.Context(), UserID(c), projectID, actorFrom(c)); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// ListEnvironments returns a project's environments in promotion order.
func (h *ProjectHandler) ListEnvironments(c *gin.Context) {
	projectID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	environments, err := h.projects.ListEnvironments(c.Request.Context(), UserID(c), projectID)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"environments": environments})
}

// GetEnvironment returns one environment.
func (h *ProjectHandler) GetEnvironment(c *gin.Context) {
	environmentID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	environment, err := h.projects.GetEnvironment(c.Request.Context(), UserID(c), environmentID)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"environment": environment})
}

type createEnvironmentRequest struct {
	Name string `json:"name"`
	Rank int32  `json:"rank"`
}

// CreateEnvironment adds an environment to a project.
func (h *ProjectHandler) CreateEnvironment(c *gin.Context) {
	projectID, ok := uuidParam(c, "id")
	if !ok {
		return
	}

	var req createEnvironmentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondValidation(c, "body", "must be a valid JSON object")
		return
	}

	environment, err := h.projects.CreateEnvironment(c.Request.Context(), UserID(c),
		projectID, req.Name, req.Rank, actorFrom(c))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"environment": environment})
}
