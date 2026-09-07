-- ip_allowlist and scopes are cast to text[] on the way in and out so the Go
-- layer works with plain strings and owns the parsing into netip.Prefix. That
-- keeps address validation in one tested place instead of splitting it between
-- Go and PostgreSQL.

-- name: CreateAccessToken :one
INSERT INTO access_tokens (
    project_id, environment_id, name, token_hash, prefix,
    scopes, ip_allowlist, rate_limit_rpm, expires_at, created_by
)
VALUES (
    $1, $2, $3, $4, $5,
    sqlc.arg('scopes')::text[], sqlc.arg('ip_allowlist')::text[]::inet[], $6,
    sqlc.narg('expires_at')::timestamptz, sqlc.narg('created_by')::uuid
)
RETURNING id, project_id, environment_id, name, prefix,
          scopes::text[] AS scopes,
          ip_allowlist::text[] AS ip_allowlist,
          rate_limit_rpm, expires_at, revoked_at, last_used_at, created_at, created_by;

-- Looks a token up by digest. Revocation and expiry are checked in Go rather
-- than here so that the middleware can tell the two apart when logging.
-- name: GetAccessTokenByHash :one
SELECT t.id, t.project_id, t.environment_id, t.name, t.prefix,
       t.scopes::text[] AS scopes,
       t.ip_allowlist::text[] AS ip_allowlist,
       t.rate_limit_rpm, t.expires_at, t.revoked_at, t.last_used_at,
       t.created_at, t.created_by,
       p.workspace_id
FROM access_tokens t
JOIN projects p ON p.id = t.project_id
WHERE t.token_hash = $1 AND p.deleted_at IS NULL;

-- name: GetAccessToken :one
SELECT id, project_id, environment_id, name, prefix,
       scopes::text[] AS scopes,
       ip_allowlist::text[] AS ip_allowlist,
       rate_limit_rpm, expires_at, revoked_at, last_used_at, created_at, created_by
FROM access_tokens
WHERE id = $1;

-- name: ListAccessTokens :many
SELECT id, project_id, environment_id, name, prefix,
       scopes::text[] AS scopes,
       ip_allowlist::text[] AS ip_allowlist,
       rate_limit_rpm, expires_at, revoked_at, last_used_at, created_at, created_by
FROM access_tokens
WHERE project_id = $1
ORDER BY created_at DESC;

-- name: RevokeAccessToken :one
UPDATE access_tokens
SET revoked_at = now()
WHERE id = $1 AND revoked_at IS NULL
RETURNING id;

-- Recorded on a best-effort basis after a successful authentication. It is
-- deliberately not part of the request transaction: a failure to record
-- last use must never fail the request itself.
-- name: TouchAccessToken :exec
UPDATE access_tokens
SET last_used_at = now()
WHERE id = $1;
