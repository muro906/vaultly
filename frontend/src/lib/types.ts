// Shapes returned by the Vaultly API. They mirror the Go domain types, and
// exist so that a response is checked at the boundary rather than flowing
// through the app as `any`.

export type Role = "owner" | "admin" | "member" | "viewer";

export type TokenScope = "secrets:read" | "secrets:write";

export interface User {
  id: string;
  email: string;
  name: string;
  createdAt: string;
  updatedAt: string;
}

export interface Workspace {
  id: string;
  name: string;
  slug: string;
  ownerId: string;
  createdAt: string;
  updatedAt: string;
  role?: Role;
}

export interface WorkspaceMember {
  workspaceId: string;
  userId: string;
  email: string;
  name: string;
  role: Role;
  createdAt: string;
}

export interface Project {
  id: string;
  workspaceId: string;
  name: string;
  slug: string;
  description: string;
  createdAt: string;
  updatedAt: string;
}

export interface Environment {
  id: string;
  projectId: string;
  name: string;
  /** Orders the promotion path; lower ranks promote into higher ones. */
  rank: number;
  secretCount?: number;
  createdAt: string;
  updatedAt: string;
}

export interface Secret {
  id: string;
  projectId: string;
  environmentId: string;
  key: string;
  description: string;
  currentVersion: number;
  createdAt: string;
  updatedAt: string;
  updatedBy?: string;
  /**
   * Present only on an explicit reveal. A listing never carries values, which
   * is why this is optional rather than a plain string.
   */
  value?: string;
}

export interface SecretVersion {
  id: string;
  secretId: string;
  version: number;
  comment: string;
  createdAt: string;
  createdBy?: string;
  createdByEmail?: string;
  value?: string;
}

export interface AccessToken {
  id: string;
  projectId: string;
  environmentId: string;
  name: string;
  prefix: string;
  scopes: TokenScope[];
  ipAllowlist: string[];
  rateLimitRpm: number;
  expiresAt?: string;
  revokedAt?: string;
  lastUsedAt?: string;
  createdAt: string;
  createdBy?: string;
  /** Returned exactly once, in the response to creating the token. */
  plaintext?: string;
}

export interface AuditEntry {
  id: string;
  workspaceId: string;
  actorUserId?: string;
  actorEmail?: string;
  actorTokenId?: string;
  actorTokenName?: string;
  action: string;
  resourceType: string;
  resourceId?: string;
  metadata?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
  createdAt: string;
}

export interface AuditPage {
  entries: AuditEntry[];
  nextCursor?: string;
}

export type PromotionChangeType = "added" | "changed" | "unchanged";

export interface PromotionChange {
  key: string;
  type: PromotionChangeType;
  masked: boolean;
  sourceValue?: string;
  targetValue?: string;
}

export interface PromotionPlan {
  sourceEnvironmentId: string;
  targetEnvironmentId: string;
  sourceName: string;
  targetName: string;
  changes: PromotionChange[];
  dryRun: boolean;
  applied: number;
}

/** The error shape every failing endpoint returns. */
export interface ApiErrorBody {
  error: string;
  fields?: Record<string, string>;
  requestId?: string;
}

/** Ranks roles so the UI can hide controls a member could not use anyway. */
const ROLE_RANK: Record<Role, number> = {
  viewer: 1,
  member: 2,
  admin: 3,
  owner: 4,
};

export function roleAtLeast(role: Role | undefined, minimum: Role): boolean {
  if (!role) return false;
  return (ROLE_RANK[role] ?? 0) >= ROLE_RANK[minimum];
}

/**
 * Hiding a control the server would reject is a courtesy, not a security
 * boundary: the API enforces the same rules independently.
 */
export const can = {
  readSecretValues: (role?: Role) => roleAtLeast(role, "member"),
  writeSecrets: (role?: Role) => roleAtLeast(role, "member"),
  manageTokens: (role?: Role) => roleAtLeast(role, "admin"),
  manageMembers: (role?: Role) => roleAtLeast(role, "admin"),
  manageWorkspace: (role?: Role) => roleAtLeast(role, "owner"),
};
