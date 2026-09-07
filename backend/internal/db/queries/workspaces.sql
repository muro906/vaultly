-- name: CreateWorkspace :one
INSERT INTO workspaces (name, slug, owner_id)
VALUES ($1, $2, $3)
RETURNING id, name, slug, owner_id, created_at, updated_at;

-- name: AddWorkspaceMember :exec
INSERT INTO workspace_members (workspace_id, user_id, role)
VALUES ($1, $2, $3)
ON CONFLICT (workspace_id, user_id) DO UPDATE SET role = EXCLUDED.role;

-- Lists the workspaces a user belongs to, carrying their role so the caller
-- does not need a second query to decide what to render.
-- name: ListWorkspacesForUser :many
SELECT w.id, w.name, w.slug, w.owner_id, w.created_at, w.updated_at, m.role
FROM workspaces w
JOIN workspace_members m ON m.workspace_id = w.id
WHERE m.user_id = $1
ORDER BY w.created_at DESC;

-- name: GetWorkspaceForUser :one
SELECT w.id, w.name, w.slug, w.owner_id, w.created_at, w.updated_at, m.role
FROM workspaces w
JOIN workspace_members m ON m.workspace_id = w.id
WHERE w.id = $1 AND m.user_id = $2;

-- The single source of truth for "what may this user do here". Every
-- authorisation decision resolves through this one query.
-- name: GetWorkspaceRole :one
SELECT role
FROM workspace_members
WHERE workspace_id = $1 AND user_id = $2;

-- Resolves a project's workspace and the caller's role there in one round
-- trip, so nested resources can be authorised without walking the hierarchy.
-- name: GetWorkspaceRoleByProject :one
SELECT p.workspace_id, m.role
FROM projects p
JOIN workspace_members m ON m.workspace_id = p.workspace_id
WHERE p.id = $1 AND m.user_id = $2 AND p.deleted_at IS NULL;

-- name: GetWorkspaceRoleByEnvironment :one
SELECT p.workspace_id, p.id AS project_id, m.role
FROM environments e
JOIN projects p ON p.id = e.project_id
JOIN workspace_members m ON m.workspace_id = p.workspace_id
WHERE e.id = $1 AND m.user_id = $2 AND p.deleted_at IS NULL;

-- name: GetWorkspaceRoleBySecret :one
SELECT p.workspace_id, p.id AS project_id, s.environment_id, m.role
FROM secrets s
JOIN projects p ON p.id = s.project_id
JOIN workspace_members m ON m.workspace_id = p.workspace_id
WHERE s.id = $1 AND m.user_id = $2 AND s.deleted_at IS NULL AND p.deleted_at IS NULL;

-- name: GetWorkspaceRoleByToken :one
SELECT p.workspace_id, m.role
FROM access_tokens t
JOIN projects p ON p.id = t.project_id
JOIN workspace_members m ON m.workspace_id = p.workspace_id
WHERE t.id = $1 AND m.user_id = $2;

-- name: ListWorkspaceMembers :many
SELECT m.workspace_id, m.user_id, u.email, u.name, m.role, m.created_at
FROM workspace_members m
JOIN users u ON u.id = m.user_id
WHERE m.workspace_id = $1
ORDER BY m.created_at;

-- name: UpdateWorkspaceMemberRole :exec
UPDATE workspace_members
SET role = $3
WHERE workspace_id = $1 AND user_id = $2;

-- name: RemoveWorkspaceMember :exec
DELETE FROM workspace_members
WHERE workspace_id = $1 AND user_id = $2;

-- name: WorkspaceSlugExists :one
SELECT EXISTS (SELECT 1 FROM workspaces WHERE slug = $1);

-- name: CountWorkspaceOwners :one
SELECT count(*) FROM workspace_members
WHERE workspace_id = $1 AND role = 'owner';
