-- name: CreateAuditLog :exec
INSERT INTO audit_logs (
    workspace_id, actor_user_id, actor_token_id, action,
    resource_type, resource_id, metadata, ip_address, user_agent
)
VALUES (
    $1,
    sqlc.narg('actor_user_id')::uuid,
    sqlc.narg('actor_token_id')::uuid,
    $2, $3,
    sqlc.narg('resource_id')::uuid,
    $4,
    sqlc.narg('ip_address')::inet,
    $5
);

-- Keyset pagination rather than OFFSET: the feed is append-heavy, and an
-- offset scan would both slow down and skip rows as new entries arrive while
-- a user pages. The (created_at, id) tuple matches the covering index and is
-- unique, so no row is ever seen twice or missed.
--
-- Every filter is optional; passing NULL disables it.
-- name: ListAuditLogs :many
SELECT a.id, a.workspace_id, a.actor_user_id, a.actor_token_id, a.action,
       a.resource_type, a.resource_id, a.metadata,
       host(a.ip_address) AS ip_address, a.user_agent, a.created_at,
       coalesce(u.email, '') AS actor_email,
       coalesce(t.name, '')  AS actor_token_name
FROM audit_logs a
LEFT JOIN users u ON u.id = a.actor_user_id
LEFT JOIN access_tokens t ON t.id = a.actor_token_id
WHERE a.workspace_id = $1
  AND (sqlc.narg('action')::text IS NULL OR a.action = sqlc.narg('action')::text)
  AND (sqlc.narg('actor_user_id')::uuid IS NULL OR a.actor_user_id = sqlc.narg('actor_user_id')::uuid)
  AND (sqlc.narg('resource_type')::text IS NULL OR a.resource_type = sqlc.narg('resource_type')::text)
  AND (sqlc.narg('resource_id')::uuid IS NULL OR a.resource_id = sqlc.narg('resource_id')::uuid)
  AND (
        sqlc.narg('before_created_at')::timestamptz IS NULL
        OR (a.created_at, a.id) < (sqlc.narg('before_created_at')::timestamptz, sqlc.narg('before_id')::uuid)
      )
ORDER BY a.created_at DESC, a.id DESC
LIMIT $2;

-- Powers the filter dropdowns in the activity feed without a hardcoded list.
-- name: ListAuditActions :many
SELECT DISTINCT action FROM audit_logs
WHERE workspace_id = $1
ORDER BY action;
