"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { cookies } from "next/headers";

import { apiFetch, ApiError, ACCESS_COOKIE, REFRESH_COOKIE } from "./api";
import type { AccessToken, PromotionPlan, Secret, TokenScope } from "./types";

/**
 * Server Actions for every mutation.
 *
 * Running these on the server keeps the session cookie out of page scripts:
 * the browser posts a form, this code adds the credential, and only the
 * result comes back. It also means a secret value submitted by a user reaches
 * the API without ever being held in client-side state.
 */

/** What a form action returns, so a form can render field-level errors. */
export interface FormState {
  error?: string;
  fields?: Record<string, string>;
  /** Set on success, for forms that show a confirmation. */
  ok?: boolean;
  /** Carries a one-time token back to the page that created it. */
  token?: AccessToken;
  plan?: PromotionPlan;
}

/** Converts a thrown ApiError into the shape a form can render. */
function toFormState(error: unknown): FormState {
  if (error instanceof ApiError) {
    return { error: error.message, fields: error.fields };
  }
  return { error: "Something went wrong. Please try again." };
}

function requiredString(formData: FormData, name: string): string {
  const value = formData.get(name);
  return typeof value === "string" ? value : "";
}

// --- Authentication --------------------------------------------------------

export async function registerAction(_prev: FormState, formData: FormData): Promise<FormState> {
  try {
    await apiFetch("/api/v1/auth/register", {
      method: "POST",
      body: {
        email: requiredString(formData, "email"),
        password: requiredString(formData, "password"),
        name: requiredString(formData, "name"),
      },
    });
  } catch (error) {
    return toFormState(error);
  }
  // Outside the try: redirect works by throwing, so catching it here would
  // turn a successful registration into a rendered error.
  redirect("/workspaces");
}

export async function loginAction(_prev: FormState, formData: FormData): Promise<FormState> {
  try {
    await apiFetch("/api/v1/auth/login", {
      method: "POST",
      body: {
        email: requiredString(formData, "email"),
        password: requiredString(formData, "password"),
      },
    });
  } catch (error) {
    return toFormState(error);
  }
  redirect("/workspaces");
}

export async function logoutAction(): Promise<void> {
  try {
    await apiFetch("/api/v1/auth/logout", { method: "POST" });
  } catch {
    // Signing out must always succeed locally, even if the API is unreachable.
  }
  const store = cookies();
  store.delete(ACCESS_COOKIE);
  store.delete(REFRESH_COOKIE);
  redirect("/login");
}

// --- Workspaces and projects ----------------------------------------------

export async function createWorkspaceAction(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  try {
    await apiFetch("/api/v1/workspaces", {
      method: "POST",
      body: { name: requiredString(formData, "name") },
    });
  } catch (error) {
    return toFormState(error);
  }
  revalidatePath("/workspaces");
  return { ok: true };
}

export async function createProjectAction(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const workspaceId = requiredString(formData, "workspaceId");
  try {
    await apiFetch(`/api/v1/workspaces/${workspaceId}/projects`, {
      method: "POST",
      body: {
        name: requiredString(formData, "name"),
        description: requiredString(formData, "description"),
      },
    });
  } catch (error) {
    return toFormState(error);
  }
  revalidatePath(`/workspaces/${workspaceId}`);
  return { ok: true };
}

export async function addMemberAction(_prev: FormState, formData: FormData): Promise<FormState> {
  const workspaceId = requiredString(formData, "workspaceId");
  try {
    await apiFetch(`/api/v1/workspaces/${workspaceId}/members`, {
      method: "POST",
      body: {
        email: requiredString(formData, "email"),
        role: requiredString(formData, "role"),
      },
    });
  } catch (error) {
    return toFormState(error);
  }
  revalidatePath(`/workspaces/${workspaceId}/members`);
  return { ok: true };
}

// --- Secrets ---------------------------------------------------------------

export async function createSecretAction(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const environmentId = requiredString(formData, "environmentId");
  const projectId = requiredString(formData, "projectId");
  try {
    await apiFetch(`/api/v1/environments/${environmentId}/secrets`, {
      method: "POST",
      body: {
        key: requiredString(formData, "key"),
        value: requiredString(formData, "value"),
        description: requiredString(formData, "description"),
      },
    });
  } catch (error) {
    return toFormState(error);
  }
  revalidatePath(`/projects/${projectId}`);
  return { ok: true };
}

export async function updateSecretAction(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const secretId = requiredString(formData, "secretId");
  const projectId = requiredString(formData, "projectId");
  const expected = Number(requiredString(formData, "expectedVersion"));

  try {
    await apiFetch(`/api/v1/secrets/${secretId}`, {
      method: "PUT",
      body: {
        value: requiredString(formData, "value"),
        comment: requiredString(formData, "comment"),
        // Sending the version the form was built from turns a blind overwrite
        // into a conflict the user is told about.
        expectedVersion: Number.isFinite(expected) ? expected : 0,
      },
    });
  } catch (error) {
    if (error instanceof ApiError && error.status === 409) {
      return {
        error:
          "This secret changed while you were editing it. Reload to see the current value before saving.",
      };
    }
    return toFormState(error);
  }
  revalidatePath(`/projects/${projectId}`);
  revalidatePath(`/secrets/${secretId}`);
  return { ok: true };
}

export async function deleteSecretAction(formData: FormData): Promise<void> {
  const secretId = requiredString(formData, "secretId");
  const projectId = requiredString(formData, "projectId");
  await apiFetch(`/api/v1/secrets/${secretId}`, { method: "DELETE" });
  revalidatePath(`/projects/${projectId}`);
}

export async function rollbackSecretAction(formData: FormData): Promise<void> {
  const secretId = requiredString(formData, "secretId");
  const version = requiredString(formData, "version");
  await apiFetch(`/api/v1/secrets/${secretId}/versions/${version}/rollback`, { method: "POST" });
  revalidatePath(`/secrets/${secretId}`);
}

/** Reveals one secret. Used by the masked display, and audited server-side. */
export async function revealSecretAction(secretId: string): Promise<{ value?: string; error?: string }> {
  try {
    const body = await apiFetch<{ secret: Secret }>(`/api/v1/secrets/${secretId}/reveal`);
    return { value: body.secret.value ?? "" };
  } catch (error) {
    if (error instanceof ApiError) return { error: error.message };
    return { error: "Could not reveal this secret." };
  }
}

/** Reveals one historical version, for the diff view. */
export async function revealVersionAction(
  secretId: string,
  version: number,
): Promise<{ value?: string; error?: string }> {
  try {
    const body = await apiFetch<{ version: { value?: string } }>(
      `/api/v1/secrets/${secretId}/versions/${version}`,
    );
    return { value: body.version.value ?? "" };
  } catch (error) {
    if (error instanceof ApiError) return { error: error.message };
    return { error: "Could not load this version." };
  }
}

// --- Promotion -------------------------------------------------------------

export async function promoteAction(_prev: FormState, formData: FormData): Promise<FormState> {
  const projectId = requiredString(formData, "projectId");
  const dryRun = requiredString(formData, "dryRun") === "true";

  try {
    const body = await apiFetch<{ plan: PromotionPlan }>(`/api/v1/projects/${projectId}/promote`, {
      method: "POST",
      body: {
        sourceEnvironmentId: requiredString(formData, "sourceEnvironmentId"),
        targetEnvironmentId: requiredString(formData, "targetEnvironmentId"),
        dryRun,
      },
    });
    if (!dryRun) revalidatePath(`/projects/${projectId}`);
    return { ok: true, plan: body.plan };
  } catch (error) {
    return toFormState(error);
  }
}

// --- Access tokens ---------------------------------------------------------

export async function createTokenAction(_prev: FormState, formData: FormData): Promise<FormState> {
  const projectId = requiredString(formData, "projectId");

  const scopes: TokenScope[] = [];
  if (formData.get("scopeRead")) scopes.push("secrets:read");
  if (formData.get("scopeWrite")) scopes.push("secrets:write");

  // Entered one per line, which is easier to read and edit than a comma list.
  const ipAllowlist = requiredString(formData, "ipAllowlist")
    .split(/[\n,]/)
    .map((entry) => entry.trim())
    .filter(Boolean);

  const rateLimit = Number(requiredString(formData, "rateLimitRpm"));
  const expiresAt = requiredString(formData, "expiresAt");

  try {
    const body = await apiFetch<{ token: AccessToken }>(`/api/v1/projects/${projectId}/tokens`, {
      method: "POST",
      body: {
        environmentId: requiredString(formData, "environmentId"),
        name: requiredString(formData, "name"),
        scopes,
        ipAllowlist,
        rateLimitRpm: Number.isFinite(rateLimit) && rateLimit > 0 ? rateLimit : 60,
        expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
      },
    });
    revalidatePath(`/projects/${projectId}/tokens`);
    // Returned so the page can show it once; it is not stored anywhere.
    return { ok: true, token: body.token };
  } catch (error) {
    return toFormState(error);
  }
}

export async function revokeTokenAction(formData: FormData): Promise<void> {
  const tokenId = requiredString(formData, "tokenId");
  const projectId = requiredString(formData, "projectId");
  await apiFetch(`/api/v1/tokens/${tokenId}`, { method: "DELETE" });
  revalidatePath(`/projects/${projectId}/tokens`);
}
