import { NextResponse, type NextRequest } from "next/server";

/**
 * Refreshes an expired session before the request reaches a page.
 *
 * The access token is short-lived. Without this, a user whose token has just
 * expired would be bounced to the sign-in page despite holding a perfectly
 * valid refresh token. Middleware is the only place that can both notice the
 * expiry and write the replacement cookie.
 *
 * This is deliberately **not** the authorisation boundary. It never decides
 * who may see what — it only tops up a session. Access is decided by the
 * signed-in layout, which verifies the session against the API, and by the API
 * itself, which enforces roles independently. Middleware that gates access is
 * a well-known source of bypasses, so nothing here is load-bearing for
 * security: if this runs and fails, the worst outcome is a redirect to sign in.
 */

const ACCESS_COOKIE = "vaultly_access";
const REFRESH_COOKIE = "vaultly_refresh";

const API_BASE_URL = process.env.API_BASE_URL ?? "http://localhost:8080";

export async function middleware(request: NextRequest) {
  const hasAccess = request.cookies.has(ACCESS_COOKIE);
  const refresh = request.cookies.get(REFRESH_COOKIE);

  // Nothing to do when the session is live, or when there is no way to renew it.
  if (hasAccess || !refresh) {
    return NextResponse.next();
  }

  let refreshed: Response;
  try {
    refreshed = await fetch(`${API_BASE_URL}/api/v1/auth/refresh`, {
      method: "POST",
      headers: { Cookie: `${REFRESH_COOKIE}=${refresh.value}` },
      cache: "no-store",
    });
  } catch {
    // The API being unreachable must not break rendering; the page falls
    // through to its own sign-in redirect.
    return NextResponse.next();
  }

  if (!refreshed.ok) {
    // The refresh token is spent or revoked. Clear it so the browser stops
    // presenting a credential that can never work again.
    const response = NextResponse.next();
    response.cookies.delete(REFRESH_COOKIE);
    return response;
  }

  const renewed = parseSessionCookies(refreshed.headers.getSetCookie());

  // The page about to render reads the *request* cookies, so the new access
  // token has to be written there as well as onto the response. Building the
  // request headers up front is what makes this a single response rather than
  // two, the second of which would discard the first one's cookies.
  const requestHeaders = new Headers(request.headers);
  const access = renewed.find((cookie) => cookie.name === ACCESS_COOKIE);
  if (access) {
    request.cookies.set(ACCESS_COOKIE, access.value);
    requestHeaders.set("cookie", request.cookies.toString());
  }

  const response = NextResponse.next({ request: { headers: requestHeaders } });

  for (const cookie of renewed) {
    if (cookie.maxAge !== undefined && cookie.maxAge <= 0) {
      response.cookies.delete(cookie.name);
      continue;
    }
    // Re-pathed to "/" because the API scopes its refresh cookie to its own
    // path, which does not exist on this origin.
    response.cookies.set({
      name: cookie.name,
      value: cookie.value,
      httpOnly: true,
      sameSite: "lax",
      secure: cookie.secure,
      path: "/",
      maxAge: cookie.maxAge,
    });
  }

  return response;
}

interface ParsedCookie {
  name: string;
  value: string;
  maxAge?: number;
  secure: boolean;
}

function parseSessionCookies(setCookies: string[]): ParsedCookie[] {
  const parsed: ParsedCookie[] = [];

  for (const raw of setCookies) {
    const [pair, ...attributes] = raw.split(";");
    if (!pair) continue;

    const separator = pair.indexOf("=");
    if (separator === -1) continue;

    const name = pair.slice(0, separator).trim();
    if (name !== ACCESS_COOKIE && name !== REFRESH_COOKIE) continue;

    const cookie: ParsedCookie = {
      name,
      value: pair.slice(separator + 1).trim(),
      secure: false,
    };

    for (const attribute of attributes) {
      const [key, attrValue] = attribute.split("=");
      const normalised = key?.trim().toLowerCase();
      if (normalised === "max-age") cookie.maxAge = Number(attrValue);
      if (normalised === "secure") cookie.secure = true;
    }

    parsed.push(cookie);
  }

  return parsed;
}

export const config = {
  // Static assets and the Next internals never need a session.
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
