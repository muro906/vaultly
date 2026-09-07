package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"vaultly/backend/internal/db/sqlcgen"
	"vaultly/backend/internal/domain"
)

// WorkspaceService manages workspaces and their membership.
type WorkspaceService struct {
	store *Store
	authz *Authorizer
	audit *AuditRecorder
}

// NewWorkspaceService builds a WorkspaceService.
func NewWorkspaceService(store *Store, authz *Authorizer, audit *AuditRecorder) *WorkspaceService {
	return &WorkspaceService{store: store, authz: authz, audit: audit}
}

// List returns the workspaces a user belongs to, each carrying their role.
func (s *WorkspaceService) List(ctx context.Context, userID uuid.UUID) ([]domain.Workspace, error) {
	rows, err := s.store.Queries().ListWorkspacesForUser(ctx, userID)
	if err != nil {
		return nil, translateDBError(err, "list workspaces")
	}

	workspaces := make([]domain.Workspace, 0, len(rows))
	for _, row := range rows {
		workspaces = append(workspaces, domain.Workspace{
			ID:        row.ID,
			Name:      row.Name,
			Slug:      row.Slug,
			OwnerID:   row.OwnerID,
			CreatedAt: row.CreatedAt,
			UpdatedAt: row.UpdatedAt,
			Role:      domain.Role(row.Role),
		})
	}
	return workspaces, nil
}

// Get returns a single workspace the user belongs to.
func (s *WorkspaceService) Get(ctx context.Context, userID, workspaceID uuid.UUID) (*domain.Workspace, error) {
	row, err := s.store.Queries().GetWorkspaceForUser(ctx, sqlcgen.GetWorkspaceForUserParams{
		ID:     workspaceID,
		UserID: userID,
	})
	if err != nil {
		if isNoRows(err) {
			return nil, domain.ErrNotFound
		}
		return nil, translateDBError(err, "get workspace")
	}

	return &domain.Workspace{
		ID:        row.ID,
		Name:      row.Name,
		Slug:      row.Slug,
		OwnerID:   row.OwnerID,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
		Role:      domain.Role(row.Role),
	}, nil
}

// Create makes a new workspace owned by the user.
func (s *WorkspaceService) Create(ctx context.Context, userID uuid.UUID, name string, actor Actor) (*domain.Workspace, error) {
	v := &domain.ValidationError{}
	name = validateName(v, "name", name)
	if err := v.ErrorOrNil(); err != nil {
		return nil, err
	}

	slug, err := s.uniqueWorkspaceSlug(ctx, name)
	if err != nil {
		return nil, err
	}

	var workspace domain.Workspace
	err = s.store.InTx(ctx, func(q *sqlcgen.Queries) error {
		created, err := q.CreateWorkspace(ctx, sqlcgen.CreateWorkspaceParams{
			Name:    name,
			Slug:    slug,
			OwnerID: userID,
		})
		if err != nil {
			return translateDBError(err, "create workspace")
		}

		workspace = domain.Workspace{
			ID:        created.ID,
			Name:      created.Name,
			Slug:      created.Slug,
			OwnerID:   created.OwnerID,
			CreatedAt: created.CreatedAt,
			UpdatedAt: created.UpdatedAt,
			Role:      domain.RoleOwner,
		}

		return translateDBError(q.AddWorkspaceMember(ctx, sqlcgen.AddWorkspaceMemberParams{
			WorkspaceID: created.ID,
			UserID:      userID,
			Role:        string(domain.RoleOwner),
		}), "add workspace member")
	})
	if err != nil {
		return nil, err
	}

	s.audit.Record(Event{
		WorkspaceID:  workspace.ID,
		Actor:        actor,
		Action:       domain.ActionWorkspaceCreated,
		ResourceType: "workspace",
		ResourceID:   &workspace.ID,
		Metadata:     map[string]any{"name": workspace.Name},
	})

	return &workspace, nil
}

// ListMembers returns a workspace's members. Any member may see who else is in
// the workspace.
func (s *WorkspaceService) ListMembers(ctx context.Context, userID, workspaceID uuid.UUID) ([]domain.WorkspaceMember, error) {
	if _, err := s.authz.RequireWorkspaceRole(ctx, userID, workspaceID, domain.RoleViewer); err != nil {
		return nil, err
	}

	rows, err := s.store.Queries().ListWorkspaceMembers(ctx, workspaceID)
	if err != nil {
		return nil, translateDBError(err, "list members")
	}

	members := make([]domain.WorkspaceMember, 0, len(rows))
	for _, row := range rows {
		members = append(members, domain.WorkspaceMember{
			WorkspaceID: row.WorkspaceID,
			UserID:      row.UserID,
			Email:       row.Email,
			Name:        row.Name,
			Role:        domain.Role(row.Role),
			CreatedAt:   row.CreatedAt,
		})
	}
	return members, nil
}

// AddMember adds an existing user to a workspace by email.
func (s *WorkspaceService) AddMember(ctx context.Context, userID, workspaceID uuid.UUID, email string, role domain.Role, actor Actor) (*domain.WorkspaceMember, error) {
	scope, err := s.authz.RequireWorkspaceRole(ctx, userID, workspaceID, domain.RoleAdmin)
	if err != nil {
		return nil, err
	}

	v := &domain.ValidationError{}
	email = validateEmail(v, email)
	if !role.Valid() {
		v.Add("role", "must be one of owner, admin, member or viewer")
	}
	if err := v.ErrorOrNil(); err != nil {
		return nil, err
	}

	// Only an owner may create another owner: an admin must not be able to
	// promote someone past their own authority.
	if role == domain.RoleOwner && !scope.Role.AtLeast(domain.RoleOwner) {
		return nil, fmt.Errorf("only an owner may grant the owner role: %w", domain.ErrForbidden)
	}

	invitee, err := s.store.Queries().GetUserByEmail(ctx, email)
	if err != nil {
		if isNoRows(err) {
			return nil, domain.NewValidationError("email", "no account exists with this address")
		}
		return nil, translateDBError(err, "look up user")
	}

	if err := s.store.Queries().AddWorkspaceMember(ctx, sqlcgen.AddWorkspaceMemberParams{
		WorkspaceID: workspaceID,
		UserID:      invitee.ID,
		Role:        string(role),
	}); err != nil {
		return nil, translateDBError(err, "add member")
	}

	s.audit.Record(Event{
		WorkspaceID:  workspaceID,
		Actor:        actor,
		Action:       domain.ActionMemberAdded,
		ResourceType: "member",
		ResourceID:   &invitee.ID,
		Metadata:     map[string]any{"email": invitee.Email, "role": string(role)},
	})

	return &domain.WorkspaceMember{
		WorkspaceID: workspaceID,
		UserID:      invitee.ID,
		Email:       invitee.Email,
		Name:        invitee.Name,
		Role:        role,
	}, nil
}

// UpdateMemberRole changes a member's role.
func (s *WorkspaceService) UpdateMemberRole(ctx context.Context, userID, workspaceID, memberID uuid.UUID, role domain.Role, actor Actor) error {
	scope, err := s.authz.RequireWorkspaceRole(ctx, userID, workspaceID, domain.RoleAdmin)
	if err != nil {
		return err
	}
	if !role.Valid() {
		return domain.NewValidationError("role", "must be one of owner, admin, member or viewer")
	}
	if role == domain.RoleOwner && !scope.Role.AtLeast(domain.RoleOwner) {
		return fmt.Errorf("only an owner may grant the owner role: %w", domain.ErrForbidden)
	}

	current, err := s.store.Queries().GetWorkspaceRole(ctx, sqlcgen.GetWorkspaceRoleParams{
		WorkspaceID: workspaceID,
		UserID:      memberID,
	})
	if err != nil {
		if isNoRows(err) {
			return domain.ErrNotFound
		}
		return translateDBError(err, "resolve member role")
	}

	// Demoting the last owner would leave the workspace unmanageable, with
	// nobody able to promote anyone back.
	if domain.Role(current) == domain.RoleOwner && role != domain.RoleOwner {
		if err := s.ensureNotLastOwner(ctx, workspaceID); err != nil {
			return err
		}
	}

	if err := s.store.Queries().UpdateWorkspaceMemberRole(ctx, sqlcgen.UpdateWorkspaceMemberRoleParams{
		WorkspaceID: workspaceID,
		UserID:      memberID,
		Role:        string(role),
	}); err != nil {
		return translateDBError(err, "update member role")
	}

	s.audit.Record(Event{
		WorkspaceID:  workspaceID,
		Actor:        actor,
		Action:       domain.ActionMemberRoleUpdate,
		ResourceType: "member",
		ResourceID:   &memberID,
		Metadata:     map[string]any{"from": current, "to": string(role)},
	})
	return nil
}

// RemoveMember removes a member from a workspace. Members may always remove
// themselves; removing anyone else requires admin.
func (s *WorkspaceService) RemoveMember(ctx context.Context, userID, workspaceID, memberID uuid.UUID, actor Actor) error {
	minimum := domain.RoleAdmin
	if userID == memberID {
		minimum = domain.RoleViewer
	}
	if _, err := s.authz.RequireWorkspaceRole(ctx, userID, workspaceID, minimum); err != nil {
		return err
	}

	current, err := s.store.Queries().GetWorkspaceRole(ctx, sqlcgen.GetWorkspaceRoleParams{
		WorkspaceID: workspaceID,
		UserID:      memberID,
	})
	if err != nil {
		if isNoRows(err) {
			return domain.ErrNotFound
		}
		return translateDBError(err, "resolve member role")
	}

	if domain.Role(current) == domain.RoleOwner {
		if err := s.ensureNotLastOwner(ctx, workspaceID); err != nil {
			return err
		}
	}

	if err := s.store.Queries().RemoveWorkspaceMember(ctx, sqlcgen.RemoveWorkspaceMemberParams{
		WorkspaceID: workspaceID,
		UserID:      memberID,
	}); err != nil {
		return translateDBError(err, "remove member")
	}

	s.audit.Record(Event{
		WorkspaceID:  workspaceID,
		Actor:        actor,
		Action:       domain.ActionMemberRemoved,
		ResourceType: "member",
		ResourceID:   &memberID,
	})
	return nil
}

// ensureNotLastOwner rejects an operation that would leave a workspace with no
// owner.
func (s *WorkspaceService) ensureNotLastOwner(ctx context.Context, workspaceID uuid.UUID) error {
	owners, err := s.store.Queries().CountWorkspaceOwners(ctx, workspaceID)
	if err != nil {
		return translateDBError(err, "count owners")
	}
	if owners <= 1 {
		return fmt.Errorf("a workspace must keep at least one owner: %w", domain.ErrConflict)
	}
	return nil
}

// uniqueWorkspaceSlug derives a slug from name, appending a counter if it is
// taken. Slugs are globally unique, so collisions across unrelated teams are
// expected rather than exceptional.
func (s *WorkspaceService) uniqueWorkspaceSlug(ctx context.Context, name string) (string, error) {
	base := Slugify(name)
	if base == "" {
		base = "workspace"
	}

	candidate := base
	for attempt := 2; attempt < 100; attempt++ {
		exists, err := s.store.Queries().WorkspaceSlugExists(ctx, candidate)
		if err != nil {
			return "", translateDBError(err, "check workspace slug")
		}
		if !exists {
			return candidate, nil
		}
		candidate = fmt.Sprintf("%s-%d", base, attempt)
	}

	// Falling back to a random suffix guarantees progress rather than
	// returning an error the user cannot act on.
	return fmt.Sprintf("%s-%s", base, uuid.NewString()[:8]), nil
}
