-- Vaultly initial schema.
--
-- Design notes:
--   * Secret values live only in secret_versions, always as ciphertext. The
--     secrets table holds metadata and a pointer to the current version.
--   * Version history is append-only. Updates and rollbacks both insert a new
--     row, so history can never be rewritten and every change is attributable.
--   * Deletes are soft, so audit rows and version history never dangle.

CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- Users
-- ---------------------------------------------------------------------------

CREATE TABLE users (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email         citext      NOT NULL UNIQUE,
    password_hash text        NOT NULL,
    name          text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Opaque refresh tokens, stored only as a SHA-256 digest. Rotating a session
-- inserts a new row and marks the old one revoked, so a stolen token that is
-- replayed after the legitimate client has refreshed will be rejected.
CREATE TABLE refresh_tokens (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash bytea       NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    user_agent text        NOT NULL DEFAULT '',
    ip_address inet
);

CREATE INDEX refresh_tokens_user_id_idx ON refresh_tokens (user_id);
CREATE INDEX refresh_tokens_expires_at_idx ON refresh_tokens (expires_at);

-- ---------------------------------------------------------------------------
-- Workspaces and membership
-- ---------------------------------------------------------------------------

CREATE TABLE workspaces (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text        NOT NULL,
    slug       text        NOT NULL UNIQUE,
    owner_id   uuid        NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX workspaces_owner_id_idx ON workspaces (owner_id);

CREATE TABLE workspace_members (
    workspace_id uuid        NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    user_id      uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role         text        NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, user_id)
);

CREATE INDEX workspace_members_user_id_idx ON workspace_members (user_id);

-- ---------------------------------------------------------------------------
-- Projects and environments
-- ---------------------------------------------------------------------------

CREATE TABLE projects (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid        NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    name         text        NOT NULL,
    slug         text        NOT NULL,
    description  text        NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    deleted_at   timestamptz,
    UNIQUE (workspace_id, slug)
);

CREATE INDEX projects_workspace_id_idx ON projects (workspace_id) WHERE deleted_at IS NULL;

-- rank orders the promotion path: a secret may only be promoted from a lower
-- rank to a higher one, which is what makes dev -> staging -> prod directional.
CREATE TABLE environments (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    name       text        NOT NULL,
    rank       integer     NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (project_id, name)
);

CREATE INDEX environments_project_id_idx ON environments (project_id);

-- ---------------------------------------------------------------------------
-- Secrets
-- ---------------------------------------------------------------------------

CREATE TABLE secrets (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      uuid        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    environment_id  uuid        NOT NULL REFERENCES environments (id) ON DELETE CASCADE,
    key             text        NOT NULL,
    description     text        NOT NULL DEFAULT '',
    current_version integer     NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    updated_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    deleted_at      timestamptz
);

-- A key is unique within an environment, but only among live secrets: deleting
-- a secret must not block re-creating the same key later.
CREATE UNIQUE INDEX secrets_environment_key_idx
    ON secrets (environment_id, key)
    WHERE deleted_at IS NULL;

CREATE INDEX secrets_project_id_idx ON secrets (project_id) WHERE deleted_at IS NULL;

-- The only place ciphertext is stored. wrapped_dek is the per-version data
-- encryption key sealed under the master key; nonce and ciphertext are the
-- value sealed under that data key.
CREATE TABLE secret_versions (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id   uuid        NOT NULL REFERENCES secrets (id) ON DELETE CASCADE,
    version     integer     NOT NULL,
    wrapped_dek bytea       NOT NULL,
    nonce       bytea       NOT NULL,
    ciphertext  bytea       NOT NULL,
    comment     text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  uuid REFERENCES users (id) ON DELETE SET NULL,
    UNIQUE (secret_id, version)
);

CREATE INDEX secret_versions_secret_id_version_idx
    ON secret_versions (secret_id, version DESC);

-- ---------------------------------------------------------------------------
-- Access tokens (machine credentials)
-- ---------------------------------------------------------------------------

CREATE TABLE access_tokens (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id     uuid        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    environment_id uuid        NOT NULL REFERENCES environments (id) ON DELETE CASCADE,
    name           text        NOT NULL,
    -- Only the digest is stored; the token itself is shown once at creation.
    token_hash     bytea       NOT NULL UNIQUE,
    -- A short, non-secret identifier so a token can be recognised in the UI
    -- and in logs without revealing it.
    prefix         text        NOT NULL,
    scopes         text[]      NOT NULL DEFAULT '{}',
    -- Empty means "any source address".
    ip_allowlist   inet[]      NOT NULL DEFAULT '{}',
    rate_limit_rpm integer     NOT NULL DEFAULT 60 CHECK (rate_limit_rpm > 0),
    expires_at     timestamptz,
    revoked_at     timestamptz,
    last_used_at   timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    created_by     uuid REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX access_tokens_project_id_idx ON access_tokens (project_id);
CREATE INDEX access_tokens_environment_id_idx ON access_tokens (environment_id);

-- ---------------------------------------------------------------------------
-- Audit log
-- ---------------------------------------------------------------------------

-- Exactly one actor column is set: a human (actor_user_id) or a machine
-- (actor_token_id). Both are nullable and neither cascades on delete, so
-- removing a user or revoking a token never erases the record of what it did.
CREATE TABLE audit_logs (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id   uuid        NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    actor_user_id  uuid REFERENCES users (id) ON DELETE SET NULL,
    actor_token_id uuid REFERENCES access_tokens (id) ON DELETE SET NULL,
    action         text        NOT NULL,
    resource_type  text        NOT NULL,
    resource_id    uuid,
    metadata       jsonb       NOT NULL DEFAULT '{}',
    ip_address     inet,
    user_agent     text        NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT audit_logs_single_actor CHECK (
        NOT (actor_user_id IS NOT NULL AND actor_token_id IS NOT NULL)
    )
);

-- The activity feed is always "this workspace, newest first", optionally
-- filtered; this index serves the feed and its keyset pagination.
CREATE INDEX audit_logs_workspace_created_idx
    ON audit_logs (workspace_id, created_at DESC, id DESC);
CREATE INDEX audit_logs_action_idx ON audit_logs (workspace_id, action);
CREATE INDEX audit_logs_resource_idx ON audit_logs (resource_type, resource_id);
