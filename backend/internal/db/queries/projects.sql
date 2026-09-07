-- name: CreateProject :one
INSERT INTO projects (workspace_id, name, slug, description)
VALUES ($1, $2, $3, $4)
RETURNING id, workspace_id, name, slug, description, created_at, updated_at;

-- name: ListProjects :many
SELECT id, workspace_id, name, slug, description, created_at, updated_at
FROM projects
WHERE workspace_id = $1 AND deleted_at IS NULL
ORDER BY name;

-- name: GetProject :one
SELECT id, workspace_id, name, slug, description, created_at, updated_at
FROM projects
WHERE id = $1 AND deleted_at IS NULL;

-- name: UpdateProject :one
UPDATE projects
SET name = $2, description = $3, updated_at = now()
WHERE id = $1 AND deleted_at IS NULL
RETURNING id, workspace_id, name, slug, description, created_at, updated_at;

-- Soft delete: audit entries and version history keep referring to this row,
-- so it must survive even though it disappears from every listing.
-- name: SoftDeleteProject :exec
UPDATE projects
SET deleted_at = now()
WHERE id = $1 AND deleted_at IS NULL;

-- name: ProjectSlugExists :one
SELECT EXISTS (
    SELECT 1 FROM projects
    WHERE workspace_id = $1 AND slug = $2 AND deleted_at IS NULL
);

-- name: CreateEnvironment :one
INSERT INTO environments (project_id, name, rank)
VALUES ($1, $2, $3)
RETURNING id, project_id, name, rank, created_at, updated_at;

-- Environments are returned in promotion order, which is also the order the
-- UI displays them in.
-- name: ListEnvironments :many
SELECT e.id, e.project_id, e.name, e.rank, e.created_at, e.updated_at,
       count(s.id) AS secret_count
FROM environments e
LEFT JOIN secrets s ON s.environment_id = e.id AND s.deleted_at IS NULL
WHERE e.project_id = $1
GROUP BY e.id
ORDER BY e.rank, e.name;

-- name: GetEnvironment :one
SELECT id, project_id, name, rank, created_at, updated_at
FROM environments
WHERE id = $1;

-- name: EnvironmentNameExists :one
SELECT EXISTS (
    SELECT 1 FROM environments WHERE project_id = $1 AND name = $2
);
