package domain

import (
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// Role is a member's authority within a workspace. Roles are totally ordered:
// every role can do everything the roles below it can.
type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
	RoleViewer Role = "viewer"
)

// rank orders roles from least to most privileged. An unknown role ranks below
// every real role, so an unrecognised value fails closed.
func (r Role) rank() int {
	switch r {
	case RoleViewer:
		return 1
	case RoleMember:
		return 2
	case RoleAdmin:
		return 3
	case RoleOwner:
		return 4
	default:
		return 0
	}
}

// Valid reports whether r is a role the system recognises.
func (r Role) Valid() bool { return r.rank() > 0 }

// AtLeast reports whether r carries at least the authority of other.
func (r Role) AtLeast(other Role) bool {
	// An unknown required role can never be satisfied.
	if !other.Valid() {
		return false
	}
	return r.rank() >= other.rank()
}

// CanReadSecretValues reports whether the role may decrypt secret values.
// Viewers see that a key exists and how it has changed over time, but never
// the value itself; that distinction is the point of having a viewer role.
func (r Role) CanReadSecretValues() bool { return r.AtLeast(RoleMember) }

// CanWriteSecrets reports whether the role may create, update or roll back
// secrets.
func (r Role) CanWriteSecrets() bool { return r.AtLeast(RoleMember) }

// CanManageTokens reports whether the role may mint or revoke access tokens.
// Tokens grant long-lived automated access, so they are an admin concern.
func (r Role) CanManageTokens() bool { return r.AtLeast(RoleAdmin) }

// CanManageMembers reports whether the role may invite or remove members.
func (r Role) CanManageMembers() bool { return r.AtLeast(RoleAdmin) }

// CanManageWorkspace reports whether the role may rename or delete the
// workspace itself.
func (r Role) CanManageWorkspace() bool { return r.AtLeast(RoleOwner) }

// User is a human account.
type User struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Workspace is the top-level tenant boundary. Every project, secret, token and
// audit entry belongs to exactly one workspace.
type Workspace struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	OwnerID   uuid.UUID `json:"ownerId"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	// Role is the requesting user's role in this workspace. It is populated
	// on list and read responses, and is empty otherwise.
	Role Role `json:"role,omitempty"`
}

// WorkspaceMember joins a user to a workspace with a role.
type WorkspaceMember struct {
	WorkspaceID uuid.UUID `json:"workspaceId"`
	UserID      uuid.UUID `json:"userId"`
	Email       string    `json:"email"`
	Name        string    `json:"name"`
	Role        Role      `json:"role"`
	CreatedAt   time.Time `json:"createdAt"`
}

// Project groups a set of environments within a workspace.
type Project struct {
	ID          uuid.UUID `json:"id"`
	WorkspaceID uuid.UUID `json:"workspaceId"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// Environment is a named deployment stage within a project.
type Environment struct {
	ID        uuid.UUID `json:"id"`
	ProjectID uuid.UUID `json:"projectId"`
	Name      string    `json:"name"`
	// Rank orders environments along the promotion path: lower ranks promote
	// into higher ones. The defaults are dev=0, staging=1, prod=2.
	Rank        int32     `json:"rank"`
	SecretCount int64     `json:"secretCount,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// Default environment names created with every new project.
const (
	EnvDev     = "development"
	EnvStaging = "staging"
	EnvProd    = "production"
)

// DefaultEnvironments is the promotion path a new project starts with.
var DefaultEnvironments = []struct {
	Name string
	Rank int32
}{
	{EnvDev, 0},
	{EnvStaging, 1},
	{EnvProd, 2},
}

// Secret is one key within one environment. It carries metadata only: the
// value lives in SecretVersion and is returned only when a caller with
// sufficient authority asks for it explicitly.
type Secret struct {
	ID             uuid.UUID  `json:"id"`
	ProjectID      uuid.UUID  `json:"projectId"`
	EnvironmentID  uuid.UUID  `json:"environmentId"`
	Key            string     `json:"key"`
	Description    string     `json:"description"`
	CurrentVersion int32      `json:"currentVersion"`
	CreatedAt      time.Time  `json:"createdAt"`
	UpdatedAt      time.Time  `json:"updatedAt"`
	UpdatedBy      *uuid.UUID `json:"updatedBy,omitempty"`

	// Value is populated only by endpoints that explicitly reveal a secret,
	// and only for callers permitted to decrypt. It is omitted otherwise so
	// that a plaintext value can never leak through a list response.
	Value *string `json:"value,omitempty"`
}

// SecretVersion is one point in a secret's history. Versions are append-only:
// updates and rollbacks both add a new version rather than mutating an old one.
type SecretVersion struct {
	ID        uuid.UUID  `json:"id"`
	SecretID  uuid.UUID  `json:"secretId"`
	Version   int32      `json:"version"`
	Comment   string     `json:"comment"`
	CreatedAt time.Time  `json:"createdAt"`
	CreatedBy *uuid.UUID `json:"createdBy,omitempty"`
	// CreatedByEmail is resolved for display in history views.
	CreatedByEmail string `json:"createdByEmail,omitempty"`

	// Value is populated only when the caller may decrypt.
	Value *string `json:"value,omitempty"`
}

// TokenScope is a capability granted to an access token. Tokens are for
// machines, so the scope set is intentionally small.
type TokenScope string

const (
	// ScopeSecretsRead allows pulling decrypted secrets for the token's
	// environment.
	ScopeSecretsRead TokenScope = "secrets:read"
	// ScopeSecretsWrite allows creating and updating secrets in the token's
	// environment.
	ScopeSecretsWrite TokenScope = "secrets:write"
)

// Valid reports whether s is a scope the system recognises.
func (s TokenScope) Valid() bool {
	return s == ScopeSecretsRead || s == ScopeSecretsWrite
}

// AccessToken is a machine credential scoped to one project and environment.
// The token string itself is shown once at creation and never stored; only its
// SHA-256 digest is persisted.
type AccessToken struct {
	ID            uuid.UUID    `json:"id"`
	ProjectID     uuid.UUID    `json:"projectId"`
	EnvironmentID uuid.UUID    `json:"environmentId"`
	Name          string       `json:"name"`
	Prefix        string       `json:"prefix"`
	Scopes        []TokenScope `json:"scopes"`
	// IPAllowlist restricts which source addresses may present this token.
	// An empty list means any address is accepted.
	IPAllowlist []netip.Prefix `json:"ipAllowlist"`
	// RateLimitRPM caps requests per minute for this token.
	RateLimitRPM int32      `json:"rateLimitRpm"`
	ExpiresAt    *time.Time `json:"expiresAt,omitempty"`
	RevokedAt    *time.Time `json:"revokedAt,omitempty"`
	LastUsedAt   *time.Time `json:"lastUsedAt,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
	CreatedBy    *uuid.UUID `json:"createdBy,omitempty"`

	// Plaintext is set exactly once, in the response to token creation. It is
	// never persisted and never returned again.
	Plaintext string `json:"plaintext,omitempty"`
}

// Active reports whether the token may currently be used.
func (t *AccessToken) Active(now time.Time) bool {
	if t.RevokedAt != nil {
		return false
	}
	if t.ExpiresAt != nil && !now.Before(*t.ExpiresAt) {
		return false
	}
	return true
}

// HasScope reports whether the token carries the given scope.
func (t *AccessToken) HasScope(scope TokenScope) bool {
	for _, s := range t.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// AllowsIP reports whether addr may present this token. An empty allowlist
// permits every address.
func (t *AccessToken) AllowsIP(addr netip.Addr) bool {
	if len(t.IPAllowlist) == 0 {
		return true
	}
	if !addr.IsValid() {
		return false
	}
	// Unmap so that an IPv4-mapped IPv6 address matches an IPv4 prefix, which
	// is how addresses commonly arrive through a proxy.
	addr = addr.Unmap()
	for _, prefix := range t.IPAllowlist {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// Audit actions. These are stable strings: they are written to the audit log
// and displayed in the activity feed, so they must not be renamed casually.
const (
	ActionUserRegistered   = "user.registered"
	ActionUserLoggedIn     = "user.logged_in"
	ActionUserLoggedOut    = "user.logged_out"
	ActionWorkspaceCreated = "workspace.created"
	ActionMemberAdded      = "member.added"
	ActionMemberRemoved    = "member.removed"
	ActionMemberRoleUpdate = "member.role_updated"
	ActionProjectCreated   = "project.created"
	ActionProjectDeleted   = "project.deleted"
	ActionEnvCreated       = "environment.created"
	ActionSecretCreated    = "secret.created"
	ActionSecretUpdated    = "secret.updated"
	ActionSecretDeleted    = "secret.deleted"
	ActionSecretRead       = "secret.read"
	ActionSecretRolledBack = "secret.rolled_back"
	ActionSecretsPromoted  = "secrets.promoted"
	ActionSecretsPulled    = "secrets.pulled"
	ActionTokenCreated     = "token.created"
	ActionTokenRevoked     = "token.revoked"
)

// AuditEntry is one recorded action. Exactly one of ActorUserID and
// ActorTokenID is set, identifying whether a human or a machine acted.
type AuditEntry struct {
	ID           uuid.UUID      `json:"id"`
	WorkspaceID  uuid.UUID      `json:"workspaceId"`
	ActorUserID  *uuid.UUID     `json:"actorUserId,omitempty"`
	ActorEmail   string         `json:"actorEmail,omitempty"`
	ActorTokenID *uuid.UUID     `json:"actorTokenId,omitempty"`
	ActorTokenNm string         `json:"actorTokenName,omitempty"`
	Action       string         `json:"action"`
	ResourceType string         `json:"resourceType"`
	ResourceID   *uuid.UUID     `json:"resourceId,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	IPAddress    string         `json:"ipAddress,omitempty"`
	UserAgent    string         `json:"userAgent,omitempty"`
	CreatedAt    time.Time      `json:"createdAt"`
}

// PromotionChangeType classifies what promoting a secret would do to the
// target environment.
type PromotionChangeType string

const (
	// PromotionAdded means the key does not exist in the target environment.
	PromotionAdded PromotionChangeType = "added"
	// PromotionChanged means the key exists with a different value.
	PromotionChanged PromotionChangeType = "changed"
	// PromotionUnchanged means the key exists with the same value; promoting
	// it would be a no-op, so no version is written.
	PromotionUnchanged PromotionChangeType = "unchanged"
)

// PromotionChange is one entry in a promotion preview.
type PromotionChange struct {
	Key    string              `json:"key"`
	Type   PromotionChangeType `json:"type"`
	Masked bool                `json:"masked"`
	// SourceValue and TargetValue are populated only for callers permitted to
	// decrypt, and only when the preview was requested with values.
	SourceValue *string `json:"sourceValue,omitempty"`
	TargetValue *string `json:"targetValue,omitempty"`
}

// PromotionPlan is the result of a promotion, whether previewed or applied.
type PromotionPlan struct {
	SourceEnvironmentID uuid.UUID         `json:"sourceEnvironmentId"`
	TargetEnvironmentID uuid.UUID         `json:"targetEnvironmentId"`
	SourceName          string            `json:"sourceName"`
	TargetName          string            `json:"targetName"`
	Changes             []PromotionChange `json:"changes"`
	DryRun              bool              `json:"dryRun"`
	Applied             int               `json:"applied"`
}
