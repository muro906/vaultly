-- name: CreateSecret :one
INSERT INTO secrets (project_id, environment_id, key, description, current_version, updated_by)
VALUES ($1, $2, $3, $4, 0, sqlc.narg('updated_by')::uuid)
RETURNING id, project_id, environment_id, key, description, current_version,
          created_at, updated_at, updated_by;

-- Metadata only. Values are never included in a listing: revealing one is a
-- separate, individually audited request.
-- name: ListSecrets :many
SELECT id, project_id, environment_id, key, description, current_version,
       created_at, updated_at, updated_by
FROM secrets
WHERE environment_id = $1 AND deleted_at IS NULL
ORDER BY key;

-- name: GetSecret :one
SELECT id, project_id, environment_id, key, description, current_version,
       created_at, updated_at, updated_by
FROM secrets
WHERE id = $1 AND deleted_at IS NULL;

-- name: GetSecretByKey :one
SELECT id, project_id, environment_id, key, description, current_version,
       created_at, updated_at, updated_by
FROM secrets
WHERE environment_id = $1 AND key = $2 AND deleted_at IS NULL;

-- name: SecretKeyExists :one
SELECT EXISTS (
    SELECT 1 FROM secrets
    WHERE environment_id = $1 AND key = $2 AND deleted_at IS NULL
);

-- Bumps the version pointer, but only if the caller's expected version is
-- still current. A zero row count means someone else wrote first, which the
-- service reports as a version conflict rather than silently overwriting.
-- name: BumpSecretVersion :one
UPDATE secrets
SET current_version = current_version + 1,
    updated_at      = now(),
    updated_by      = sqlc.narg('updated_by')::uuid
WHERE id = $1 AND current_version = $2 AND deleted_at IS NULL
RETURNING current_version;

-- Unconditional bump, for writes that do not carry an expected version.
-- name: BumpSecretVersionUnchecked :one
UPDATE secrets
SET current_version = current_version + 1,
    updated_at      = now(),
    updated_by      = sqlc.narg('updated_by')::uuid
WHERE id = $1 AND deleted_at IS NULL
RETURNING current_version;

-- name: UpdateSecretDescription :exec
UPDATE secrets
SET description = $2, updated_at = now()
WHERE id = $1 AND deleted_at IS NULL;

-- name: SoftDeleteSecret :exec
UPDATE secrets
SET deleted_at = now(), updated_by = sqlc.narg('updated_by')::uuid
WHERE id = $1 AND deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- Versions
-- ---------------------------------------------------------------------------

-- name: CreateSecretVersion :one
INSERT INTO secret_versions (secret_id, version, wrapped_dek, nonce, ciphertext, comment, created_by)
VALUES ($1, $2, $3, $4, $5, $6, sqlc.narg('created_by')::uuid)
RETURNING id, secret_id, version, comment, created_at, created_by;

-- name: GetSecretVersion :one
SELECT id, secret_id, version, wrapped_dek, nonce, ciphertext, comment, created_at, created_by
FROM secret_versions
WHERE secret_id = $1 AND version = $2;

-- Resolves the value a secret currently holds. Ordering by version rather
-- than by created_at keeps this correct even if two versions land in the same
-- clock tick.
-- name: GetCurrentSecretVersion :one
SELECT id, secret_id, version, wrapped_dek, nonce, ciphertext, comment, created_at, created_by
FROM secret_versions
WHERE secret_id = $1
ORDER BY version DESC
LIMIT 1;

-- History for the UI: metadata plus the author's email, without ciphertext,
-- since the history list never reveals values.
-- name: ListSecretVersions :many
SELECT v.id, v.secret_id, v.version, v.comment, v.created_at, v.created_by,
       coalesce(u.email, '') AS created_by_email
FROM secret_versions v
LEFT JOIN users u ON u.id = v.created_by
WHERE v.secret_id = $1
ORDER BY v.version DESC;

-- Loads every current value in an environment in one query, for promotion and
-- for CI/CD pulls. DISTINCT ON picks the highest version per secret, which
-- avoids issuing one query per secret.
-- name: ListCurrentSecretValues :many
SELECT DISTINCT ON (s.id)
       s.id AS secret_id, s.key, s.project_id, s.environment_id,
       v.version, v.wrapped_dek, v.nonce, v.ciphertext
FROM secrets s
JOIN secret_versions v ON v.secret_id = s.id
WHERE s.environment_id = $1 AND s.deleted_at IS NULL
ORDER BY s.id, v.version DESC;

-- ---------------------------------------------------------------------------
-- Master key rotation
-- ---------------------------------------------------------------------------

-- name: CountSecretVersions :one
SELECT count(*) FROM secret_versions;

-- Walks every stored version in id order for rewrapping. Keyset pagination is
-- used rather than OFFSET so a rotation over a large table stays linear, and
-- so it can be resumed from the last id it reported.
--
-- Only the wrapped key is selected: rotation never touches the ciphertext, so
-- there is no reason to read it into the process.
-- name: ListSecretVersionsForRotation :many
SELECT id, wrapped_dek
FROM secret_versions
WHERE id > $1
ORDER BY id
LIMIT $2;

-- name: UpdateSecretVersionWrappedDEK :exec
UPDATE secret_versions
SET wrapped_dek = $2
WHERE id = $1;
