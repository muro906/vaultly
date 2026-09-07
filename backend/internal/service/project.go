package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"vaultly/backend/internal/db/sqlcgen"
	"vaultly/backend/internal/domain"
)

// ProjectService manages projects and their environments.
type ProjectService struct {
	store *Store
	authz *Authorizer
	audit *AuditRecorder
}

// NewProjectService builds a ProjectService.
func NewProjectService(store *Store, authz *Authorizer, audit *AuditRecorder) *ProjectService {
	return &ProjectService{store: store, authz: authz, audit: audit}
}

// List returns the projects in a workspace.
func (s *ProjectService) List(ctx context.Context, userID, workspaceID uuid.UUID) ([]domain.Project, error) {
	if _, err := s.authz.RequireWorkspaceRole(ctx, userID, workspaceID, domain.RoleViewer); err != nil {
		return nil, err
	}

	rows, err := s.store.Queries().ListProjects(ctx, workspaceID)
	if err != nil {
		return nil, translateDBError(err, "list projects")
	}

	projects := make([]domain.Project, 0, len(rows))
	for _, row := range rows {
		projects = append(projects, domain.Project{
			ID:          row.ID,
			WorkspaceID: row.WorkspaceID,
			Name:        row.Name,
			Slug:        row.Slug,
			Description: row.Description,
			CreatedAt:   row.CreatedAt,
			UpdatedAt:   row.UpdatedAt,
		})
	}
	return projects, nil
}

// Get returns a project.
func (s *ProjectService) Get(ctx context.Context, userID, projectID uuid.UUID) (*domain.Project, error) {
	if _, err := s.authz.RequireProjectRole(ctx, userID, projectID, domain.RoleViewer); err != nil {
		return nil, err
	}

	row, err := s.store.Queries().GetProject(ctx, projectID)
	if err != nil {
		if isNoRows(err) {
			return nil, domain.ErrNotFound
		}
		return nil, translateDBError(err, "get project")
	}

	return &domain.Project{
		ID:          row.ID,
		WorkspaceID: row.WorkspaceID,
		Name:        row.Name,
		Slug:        row.Slug,
		Description: row.Description,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}, nil
}

// CreateProjectInput is the payload for creating a project.
type CreateProjectInput struct {
	WorkspaceID uuid.UUID
	Name        string
	Slug        string
	Description string
	Actor       Actor
}

// Create makes a project with the default promotion path already in place.
//
// The environments are created in the same transaction, so a project always
// has somewhere to put a secret: there is no window in which a project exists
// with no environments.
func (s *ProjectService) Create(ctx context.Context, userID uuid.UUID, in CreateProjectInput) (*domain.Project, error) {
	if _, err := s.authz.RequireWorkspaceRole(ctx, userID, in.WorkspaceID, domain.RoleMember); err != nil {
		return nil, err
	}

	v := &domain.ValidationError{}
	name := validateName(v, "name", in.Name)
	description := validateDescription(v, "description", in.Description)

	slug := in.Slug
	if slug == "" {
		slug = Slugify(name)
	} else {
		slug = Slugify(slug)
	}
	if slug == "" {
		v.Add("slug", "could not be derived from the name; provide one explicitly")
	} else if !slugPattern.MatchString(slug) {
		v.Add("slug", "must contain only lowercase letters, digits and hyphens")
	}
	if err := v.ErrorOrNil(); err != nil {
		return nil, err
	}

	exists, err := s.store.Queries().ProjectSlugExists(ctx, sqlcgen.ProjectSlugExistsParams{
		WorkspaceID: in.WorkspaceID,
		Slug:        slug,
	})
	if err != nil {
		return nil, translateDBError(err, "check project slug")
	}
	if exists {
		return nil, domain.NewValidationError("slug", "is already used by another project in this workspace")
	}

	var project domain.Project
	err = s.store.InTx(ctx, func(q *sqlcgen.Queries) error {
		created, err := q.CreateProject(ctx, sqlcgen.CreateProjectParams{
			WorkspaceID: in.WorkspaceID,
			Name:        name,
			Slug:        slug,
			Description: description,
		})
		if err != nil {
			return translateDBError(err, "create project")
		}

		project = domain.Project{
			ID:          created.ID,
			WorkspaceID: created.WorkspaceID,
			Name:        created.Name,
			Slug:        created.Slug,
			Description: created.Description,
			CreatedAt:   created.CreatedAt,
			UpdatedAt:   created.UpdatedAt,
		}

		for _, env := range domain.DefaultEnvironments {
			if _, err := q.CreateEnvironment(ctx, sqlcgen.CreateEnvironmentParams{
				ProjectID: created.ID,
				Name:      env.Name,
				Rank:      env.Rank,
			}); err != nil {
				return translateDBError(err, "create environment")
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	s.audit.Record(Event{
		WorkspaceID:  in.WorkspaceID,
		Actor:        in.Actor,
		Action:       domain.ActionProjectCreated,
		ResourceType: "project",
		ResourceID:   &project.ID,
		Metadata:     map[string]any{"name": project.Name, "slug": project.Slug},
	})

	return &project, nil
}

// Update changes a project's name and description. The slug is immutable
// because it appears in URLs and in CI configuration.
func (s *ProjectService) Update(ctx context.Context, userID, projectID uuid.UUID, name, description string, actor Actor) (*domain.Project, error) {
	if _, err := s.authz.RequireProjectRole(ctx, userID, projectID, domain.RoleAdmin); err != nil {
		return nil, err
	}

	v := &domain.ValidationError{}
	name = validateName(v, "name", name)
	description = validateDescription(v, "description", description)
	if err := v.ErrorOrNil(); err != nil {
		return nil, err
	}

	row, err := s.store.Queries().UpdateProject(ctx, sqlcgen.UpdateProjectParams{
		ID:          projectID,
		Name:        name,
		Description: description,
	})
	if err != nil {
		if isNoRows(err) {
			return nil, domain.ErrNotFound
		}
		return nil, translateDBError(err, "update project")
	}

	return &domain.Project{
		ID:          row.ID,
		WorkspaceID: row.WorkspaceID,
		Name:        row.Name,
		Slug:        row.Slug,
		Description: row.Description,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}, nil
}

// Delete soft-deletes a project. Deleting one destroys access to every secret
// it holds, so it is restricted to owners.
func (s *ProjectService) Delete(ctx context.Context, userID, projectID uuid.UUID, actor Actor) error {
	scope, err := s.authz.RequireProjectRole(ctx, userID, projectID, domain.RoleOwner)
	if err != nil {
		return err
	}

	if err := s.store.Queries().SoftDeleteProject(ctx, projectID); err != nil {
		return translateDBError(err, "delete project")
	}

	s.audit.Record(Event{
		WorkspaceID:  scope.WorkspaceID,
		Actor:        actor,
		Action:       domain.ActionProjectDeleted,
		ResourceType: "project",
		ResourceID:   &projectID,
	})
	return nil
}

// ListEnvironments returns a project's environments in promotion order.
func (s *ProjectService) ListEnvironments(ctx context.Context, userID, projectID uuid.UUID) ([]domain.Environment, error) {
	if _, err := s.authz.RequireProjectRole(ctx, userID, projectID, domain.RoleViewer); err != nil {
		return nil, err
	}

	rows, err := s.store.Queries().ListEnvironments(ctx, projectID)
	if err != nil {
		return nil, translateDBError(err, "list environments")
	}

	environments := make([]domain.Environment, 0, len(rows))
	for _, row := range rows {
		environments = append(environments, domain.Environment{
			ID:          row.ID,
			ProjectID:   row.ProjectID,
			Name:        row.Name,
			Rank:        row.Rank,
			SecretCount: row.SecretCount,
			CreatedAt:   row.CreatedAt,
			UpdatedAt:   row.UpdatedAt,
		})
	}
	return environments, nil
}

// GetEnvironment returns one environment.
func (s *ProjectService) GetEnvironment(ctx context.Context, userID, environmentID uuid.UUID) (*domain.Environment, error) {
	if _, err := s.authz.RequireEnvironmentRole(ctx, userID, environmentID, domain.RoleViewer); err != nil {
		return nil, err
	}

	row, err := s.store.Queries().GetEnvironment(ctx, environmentID)
	if err != nil {
		if isNoRows(err) {
			return nil, domain.ErrNotFound
		}
		return nil, translateDBError(err, "get environment")
	}

	return &domain.Environment{
		ID:        row.ID,
		ProjectID: row.ProjectID,
		Name:      row.Name,
		Rank:      row.Rank,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}, nil
}

// CreateEnvironment adds an environment to a project's promotion path.
func (s *ProjectService) CreateEnvironment(ctx context.Context, userID, projectID uuid.UUID, name string, rank int32, actor Actor) (*domain.Environment, error) {
	scope, err := s.authz.RequireProjectRole(ctx, userID, projectID, domain.RoleAdmin)
	if err != nil {
		return nil, err
	}

	v := &domain.ValidationError{}
	name = validateName(v, "name", name)
	if rank < 0 {
		v.Add("rank", "must not be negative")
	}
	if err := v.ErrorOrNil(); err != nil {
		return nil, err
	}

	exists, err := s.store.Queries().EnvironmentNameExists(ctx, sqlcgen.EnvironmentNameExistsParams{
		ProjectID: projectID,
		Name:      name,
	})
	if err != nil {
		return nil, translateDBError(err, "check environment name")
	}
	if exists {
		return nil, domain.NewValidationError("name", "is already used by another environment in this project")
	}

	row, err := s.store.Queries().CreateEnvironment(ctx, sqlcgen.CreateEnvironmentParams{
		ProjectID: projectID,
		Name:      name,
		Rank:      rank,
	})
	if err != nil {
		return nil, translateDBError(err, "create environment")
	}

	s.audit.Record(Event{
		WorkspaceID:  scope.WorkspaceID,
		Actor:        actor,
		Action:       domain.ActionEnvCreated,
		ResourceType: "environment",
		ResourceID:   &row.ID,
		Metadata:     map[string]any{"name": name, "rank": rank},
	})

	return &domain.Environment{
		ID:        row.ID,
		ProjectID: row.ProjectID,
		Name:      row.Name,
		Rank:      row.Rank,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}, nil
}

// resolveEnvironment loads an environment and confirms it belongs to the
// expected project, so that an identifier from one project cannot be used to
// reach into another.
func (s *ProjectService) resolveEnvironment(ctx context.Context, projectID, environmentID uuid.UUID) (*domain.Environment, error) {
	row, err := s.store.Queries().GetEnvironment(ctx, environmentID)
	if err != nil {
		if isNoRows(err) {
			return nil, domain.ErrNotFound
		}
		return nil, translateDBError(err, "get environment")
	}
	if row.ProjectID != projectID {
		return nil, fmt.Errorf("environment does not belong to this project: %w", domain.ErrNotFound)
	}
	return &domain.Environment{
		ID:        row.ID,
		ProjectID: row.ProjectID,
		Name:      row.Name,
		Rank:      row.Rank,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}, nil
}
