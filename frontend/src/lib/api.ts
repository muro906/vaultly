import "server-only";

import { cookies } from "next/headers";

import type { ApiErrorBody } from "./types";

/**
 * Where the Next.js server reaches the Go API. This is a server-only value: it
 * is never prefixed with NEXT_PUBLIC_, so it is not inlined into the browser
 * bundle and the API's address stays an internal detail.
 */
const API_BASE_URL = process.env.API_BASE_URL ?? "http://localhost:8080";

/** Cookie names shared with the Go server. */
export const ACCESS_COOKIE = "vaultly_access";
export const REFRESH_COOKIE = "vaultly_refresh";

/** An API failure carrying the status and any per-field messages. */
export class ApiError extends Error {
  readonly status: number;
  readonly fields?: Record<string, string>;
  readonly requestId?: string;

  constructor(status: number, body: ApiErrorBody) {
    super(body.error || `request failed with status ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.fields = body.fields;
    this.requestId = body.requestId;
  }

  get isUnauthenticated(): boolean {
    return this.status === 401;
  }

  get isForbidden(): boolean {
    return this.status === 403;
  }

  get isNotFound(): boolean {
    return this.status === 404;
  }

  /** A one-line message suited to a form, preferring field-level detail. */
  get displayMessage(): string {
    if (this.fields) {
      const first = Object.entries(this.fields)[0];
      if (first) return `${first[0]}: ${first[1]}`;
    }
    return this.message;
  }
}

/**
 * Session cookies the Go API issues, re-pathed for this origin.
 *
 * The API scopes its refresh cookie to its own /api/v1/auth path. That path
 * does not exist on the Next.js origin, so a cookie copied across verbatim
 * would never be sent back and the session would silently fail to refresh.
 * Everything is therefore re-pathed to "/" here.
 */
export function forwardSessionCookies(setCookies: string[]): void {
  const store = cookies();

  for (const raw of setCookies) {
    const [pair, ...attributes] = raw.split(";");
    if (!pair) continue;

    const separator = pair.indexOf("=");
    if (separator === -1) continue;

    const name = pair.slice(0, separator).trim();
    const value = pair.slice(separator + 1).trim();
    if (name !== ACCESS_COOKIE && name !== REFRESH_COOKIE) continue;

    let maxAge: number | undefined;
    let secure = false;
    for (const attribute of attributes) {
      const [key, attrValue] = attribute.split("=");
      const normalised = key?.trim().toLowerCase();
      if (normalised === "max-age") maxAge = Number(attrValue);
      if (normalised === "secure") secure = true;
    }

    // An expiring cookie (Max-Age 0 or negative) is a deletion.
    if (maxAge !== undefined && maxAge <= 0) {
      store.delete(name);
      continue;
    }

    store.set({
      name,
      value,
      httpOnly: true,
      sameSite: "lax",
      secure,
      path: "/",
      maxAge,
    });
  }
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  /**
   * Next.js caching. Everything here defaults to no-store: this app shows
   * live, per-user, permission-sensitive data, and a cached response could
   * show one user another's secrets.
   */
  cache?: RequestCache;
  signal?: AbortSignal;
  /**
   * Copy the API's Set-Cookie headers onto this origin's response. Only the
   * endpoints that start or rotate a session need it; without it a sign-in
   * succeeds against the API and the browser is handed nothing.
   *
   * Only valid inside a Server Action or Route Handler, since those are the
   * only places Next.js permits writing a cookie.
   */
  forwardCookies?: boolean;
}

/**
 * Calls the Go API from the server, forwarding the caller's session cookie.
 *
 * Doing this server-side is the point of the whole design: the session token
 * lives in an httpOnly cookie that page scripts cannot read, and a secret
 * value only ever travels from the API to this server, then into rendered
 * output the user asked for.
 */
export async function apiFetch<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const cookieStore = cookies();

  // Forwarded verbatim so the Go server sees the same session it issued.
  const cookieHeader = cookieStore
    .getAll()
    .filter((c) => c.name === ACCESS_COOKIE || c.name === REFRESH_COOKIE)
    .map((c) => `${c.name}=${c.value}`)
    .join("; ");

  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (cookieHeader) headers.Cookie = cookieHeader;

  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: options.method ?? "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    cache: options.cache ?? "no-store",
    signal: options.signal,
  });

  if (options.forwardCookies) {
    forwardSessionCookies(response.headers.getSetCookie());
  }

  if (response.status === 204) {
    return undefined as T;
  }

  const text = await response.text();
  let parsed: unknown = undefined;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      // A non-JSON body from an error is still worth surfacing.
      if (!response.ok) {
        throw new ApiError(response.status, { error: text.slice(0, 200) });
      }
      return text as T;
    }
  }

  if (!response.ok) {
    throw new ApiError(response.status, (parsed as ApiErrorBody) ?? { error: "request failed" });
  }

  return parsed as T;
}

/** True when a session cookie is present. It does not prove the token is valid. */
export function hasSessionCookie(): boolean {
  const store = cookies();
  return Boolean(store.get(ACCESS_COOKIE) ?? store.get(REFRESH_COOKIE));
}
