import "server-only";

import { cache } from "react";

import { apiFetch, ApiError } from "./api";
import type {
  AccessToken,
  AuditPage,
  Environment,
  Project,
  Secret,
  SecretVersion,
  User,
  Workspace,
  WorkspaceMember,
} from "./types";

/**
 * Loaders used by Server Components.
 *
 * Each is wrapped in React's `cache` so that several components in one render
 * asking for the same thing produce one API call rather than several. The
 * cache lives for a single request, so it never serves one user's data to
 * another.
 */

export const getCurrentUser = cache(async (): Promise<User | null> => {
  try {
    const body = await apiFetch<{ user: User }>("/api/v1/auth/me");
    return body.user;
  } catch (error) {
    // An expired or absent session is an ordinary state for a page that may
    // render either signed-in or signed-out, not an error worth throwing.
    if (error instanceof ApiError && error.isUnauthenticated) return null;
    throw error;
  }
});

export const listWorkspaces = cache(async (): Promise<Workspace[]> => {
  const body = await apiFetch<{ workspaces: Workspace[] }>("/api/v1/workspaces");
  return body.workspaces ?? [];
});

export const getWorkspace = cache(async (workspaceId: string): Promise<Workspace> => {
  const body = await apiFetch<{ workspace: Workspace }>(`/api/v1/workspaces/${workspaceId}`);
  return body.workspace;
});

export const listProjects = cache(async (workspaceId: string): Promise<Project[]> => {
  const body = await apiFetch<{ projects: Project[] }>(
    `/api/v1/workspaces/${workspaceId}/projects`,
  );
  return body.projects ?? [];
});

export const getProject = cache(async (projectId: string): Promise<Project> => {
  const body = await apiFetch<{ project: Project }>(`/api/v1/projects/${projectId}`);
  return body.project;
});

export const listEnvironments = cache(async (projectId: string): Promise<Environment[]> => {
  const body = await apiFetch<{ environments: Environment[] }>(
    `/api/v1/projects/${projectId}/environments`,
  );
  return body.environments ?? [];
});

export const listSecrets = cache(async (environmentId: string): Promise<Secret[]> => {
  const body = await apiFetch<{ secrets: Secret[] }>(
    `/api/v1/environments/${environmentId}/secrets`,
  );
  return body.secrets ?? [];
});

export const listSecretVersions = cache(async (secretId: string): Promise<SecretVersion[]> => {
  const body = await apiFetch<{ versions: SecretVersion[] }>(
    `/api/v1/secrets/${secretId}/versions`,
  );
  return body.versions ?? [];
});

export const listMembers = cache(async (workspaceId: string): Promise<WorkspaceMember[]> => {
  const body = await apiFetch<{ members: WorkspaceMember[] }>(
    `/api/v1/workspaces/${workspaceId}/members`,
  );
  return body.members ?? [];
});

export const listTokens = cache(async (projectId: string): Promise<AccessToken[]> => {
  const body = await apiFetch<{ tokens: AccessToken[] }>(`/api/v1/projects/${projectId}/tokens`);
  return body.tokens ?? [];
});

export const listAuditActions = cache(async (workspaceId: string): Promise<string[]> => {
  const body = await apiFetch<{ actions: string[] }>(
    `/api/v1/workspaces/${workspaceId}/audit-actions`,
  );
  return body.actions ?? [];
});

export async function listAuditLogs(
  workspaceId: string,
  params: { action?: string; cursor?: string; limit?: number } = {},
): Promise<AuditPage> {
  const query = new URLSearchParams();
  if (params.action) query.set("action", params.action);
  if (params.cursor) query.set("cursor", params.cursor);
  query.set("limit", String(params.limit ?? 25));

  return apiFetch<AuditPage>(`/api/v1/workspaces/${workspaceId}/audit-logs?${query.toString()}`);
}

export const getSecret = cache(async (secretId: string): Promise<Secret> => {
  const body = await apiFetch<{ secret: Secret }>(`/api/v1/secrets/${secretId}`);
  return body.secret;
});
