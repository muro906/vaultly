package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"vaultly/backend/internal/db/sqlcgen"
	"vaultly/backend/internal/domain"
)

// Authorizer resolves what a user may do with a resource.
//
// Every service routes its access decisions through this type rather than
// checking roles inline, so that the rules live in one place and a new
// endpoint cannot accidentally skip them.
//
// Resolution deliberately conflates "does not exist" with "you may not see
// it": both return ErrNotFound. Distinguishing them would let a caller probe
// for the existence of workspaces and projects they have no access to.
type Authorizer struct {
	store *Store
}

// NewAuthorizer builds an Authorizer.
func NewAuthorizer(store *Store) *Authorizer { return &Authorizer{store: store} }

// Scope describes where a resource sits in the hierarchy, along with the
// caller's role there. Resolvers return it so a caller gets the identifiers it
// needs (for auditing, say) without issuing further queries.
type Scope struct {
	WorkspaceID   uuid.UUID
	ProjectID     uuid.UUID
	EnvironmentID uuid.UUID
	Role          domain.Role
}

// RequireWorkspaceRole checks that the user holds at least the given role in a
// workspace.
func (a *Authorizer) RequireWorkspaceRole(ctx context.Context, userID, workspaceID uuid.UUID, minimum domain.Role) (Scope, error) {
	role, err := a.store.Queries().GetWorkspaceRole(ctx, sqlcgen.GetWorkspaceRoleParams{
		WorkspaceID: workspaceID,
		UserID:      userID,
	})
	if err != nil {
		if isNoRows(err) {
			return Scope{}, domain.ErrNotFound
		}
		return Scope{}, translateDBError(err, "resolve workspace role")
	}

	scope := Scope{WorkspaceID: workspaceID, Role: domain.Role(role)}
	return scope, requireRole(scope.Role, minimum)
}

// RequireProjectRole resolves a project and checks the caller's role in its
// workspace.
func (a *Authorizer) RequireProjectRole(ctx context.Context, userID, projectID uuid.UUID, minimum domain.Role) (Scope, error) {
	row, err := a.store.Queries().GetWorkspaceRoleByProject(ctx, sqlcgen.GetWorkspaceRoleByProjectParams{
		ID:     projectID,
		UserID: userID,
	})
	if err != nil {
		if isNoRows(err) {
			return Scope{}, domain.ErrNotFound
		}
		return Scope{}, translateDBError(err, "resolve project role")
	}

	scope := Scope{
		WorkspaceID: row.WorkspaceID,
		ProjectID:   projectID,
		Role:        domain.Role(row.Role),
	}
	return scope, requireRole(scope.Role, minimum)
}

// RequireEnvironmentRole resolves an environment up to its workspace and
// checks the caller's role.
func (a *Authorizer) RequireEnvironmentRole(ctx context.Context, userID, environmentID uuid.UUID, minimum domain.Role) (Scope, error) {
	row, err := a.store.Queries().GetWorkspaceRoleByEnvironment(ctx, sqlcgen.GetWorkspaceRoleByEnvironmentParams{
		ID:     environmentID,
		UserID: userID,
	})
	if err != nil {
		if isNoRows(err) {
			return Scope{}, domain.ErrNotFound
		}
		return Scope{}, translateDBError(err, "resolve environment role")
	}

	scope := Scope{
		WorkspaceID:   row.WorkspaceID,
		ProjectID:     row.ProjectID,
		EnvironmentID: environmentID,
		Role:          domain.Role(row.Role),
	}
	return scope, requireRole(scope.Role, minimum)
}

// RequireSecretRole resolves a secret up to its workspace and checks the
// caller's role.
func (a *Authorizer) RequireSecretRole(ctx context.Context, userID, secretID uuid.UUID, minimum domain.Role) (Scope, error) {
	row, err := a.store.Queries().GetWorkspaceRoleBySecret(ctx, sqlcgen.GetWorkspaceRoleBySecretParams{
		ID:     secretID,
		UserID: userID,
	})
	if err != nil {
		if isNoRows(err) {
			return Scope{}, domain.ErrNotFound
		}
		return Scope{}, translateDBError(err, "resolve secret role")
	}

	scope := Scope{
		WorkspaceID:   row.WorkspaceID,
		ProjectID:     row.ProjectID,
		EnvironmentID: row.EnvironmentID,
		Role:          domain.Role(row.Role),
	}
	return scope, requireRole(scope.Role, minimum)
}

// RequireTokenRole resolves an access token up to its workspace and checks the
// caller's role.
func (a *Authorizer) RequireTokenRole(ctx context.Context, userID, tokenID uuid.UUID, minimum domain.Role) (Scope, error) {
	row, err := a.store.Queries().GetWorkspaceRoleByToken(ctx, sqlcgen.GetWorkspaceRoleByTokenParams{
		ID:     tokenID,
		UserID: userID,
	})
	if err != nil {
		if isNoRows(err) {
			return Scope{}, domain.ErrNotFound
		}
		return Scope{}, translateDBError(err, "resolve token role")
	}

	scope := Scope{WorkspaceID: row.WorkspaceID, Role: domain.Role(row.Role)}
	return scope, requireRole(scope.Role, minimum)
}

// requireRole is the one place a role comparison is made.
func requireRole(actual, minimum domain.Role) error {
	if !actual.Valid() {
		// An unrecognised stored role fails closed rather than being treated
		// as some default level.
		return fmt.Errorf("unrecognised role %q: %w", actual, domain.ErrForbidden)
	}
	if !actual.AtLeast(minimum) {
		return fmt.Errorf("role %q is below the required %q: %w", actual, minimum, domain.ErrForbidden)
	}
	return nil
}
