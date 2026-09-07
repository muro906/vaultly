import { beforeEach, describe, expect, it, vi } from "vitest";

// forwardSessionCookies writes through next/headers, so the store is faked.
const store = {
  set: vi.fn(),
  delete: vi.fn(),
};

vi.mock("next/headers", () => ({ cookies: () => store }));

const { forwardSessionCookies } = await import("./api");

describe("forwardSessionCookies", () => {
  beforeEach(() => {
    store.set.mockClear();
    store.delete.mockClear();
  });

  it("copies the session cookies the API issued", () => {
    // Without this the API accepts a sign-in and the browser is handed
    // nothing, so the session silently never starts.
    forwardSessionCookies([
      "vaultly_access=access-token-value; Path=/; Max-Age=899; HttpOnly; SameSite=Lax",
      "vaultly_refresh=refresh-token-value; Path=/api/v1/auth; Max-Age=2591999; HttpOnly; SameSite=Lax",
    ]);

    expect(store.set).toHaveBeenCalledTimes(2);
    expect(store.set).toHaveBeenCalledWith(
      expect.objectContaining({ name: "vaultly_access", value: "access-token-value", maxAge: 899 }),
    );
  });

  it("re-paths the refresh cookie to this origin", () => {
    // The API scopes it to its own /api/v1/auth, which does not exist here, so
    // a verbatim copy would never be sent back and refresh would silently fail.
    forwardSessionCookies([
      "vaultly_refresh=value; Path=/api/v1/auth; Max-Age=2591999; HttpOnly; SameSite=Lax",
    ]);

    expect(store.set).toHaveBeenCalledWith(expect.objectContaining({ path: "/" }));
  });

  it("always marks the cookies httpOnly so page scripts cannot read them", () => {
    forwardSessionCookies(["vaultly_access=value; Path=/; Max-Age=899"]);

    expect(store.set).toHaveBeenCalledWith(
      expect.objectContaining({ httpOnly: true, sameSite: "lax" }),
    );
  });

  it("carries the Secure flag through when the API sets it", () => {
    forwardSessionCookies(["vaultly_access=value; Path=/; Max-Age=899; HttpOnly; Secure"]);
    expect(store.set).toHaveBeenCalledWith(expect.objectContaining({ secure: true }));

    store.set.mockClear();
    forwardSessionCookies(["vaultly_access=value; Path=/; Max-Age=899; HttpOnly"]);
    expect(store.set).toHaveBeenCalledWith(expect.objectContaining({ secure: false }));
  });

  it("treats an expiring cookie as a deletion", () => {
    // This is how the API signs a user out.
    forwardSessionCookies(["vaultly_access=; Path=/; Max-Age=0; HttpOnly"]);

    expect(store.delete).toHaveBeenCalledWith("vaultly_access");
    expect(store.set).not.toHaveBeenCalled();
  });

  it("ignores cookies that are not part of the session", () => {
    forwardSessionCookies([
      "some_other_cookie=value; Path=/",
      "vaultly_access=real; Path=/; Max-Age=899",
    ]);

    expect(store.set).toHaveBeenCalledTimes(1);
    expect(store.set).toHaveBeenCalledWith(expect.objectContaining({ name: "vaultly_access" }));
  });

  it("survives malformed input rather than throwing mid sign-in", () => {
    expect(() => forwardSessionCookies(["", "novalue", "=nokey", "vaultly_access"])).not.toThrow();
    expect(store.set).not.toHaveBeenCalled();
  });

  it("handles a value containing an equals sign", () => {
    // base64 padding routinely produces these.
    forwardSessionCookies(["vaultly_refresh=abc==; Path=/api/v1/auth; Max-Age=100"]);

    expect(store.set).toHaveBeenCalledWith(expect.objectContaining({ value: "abc==" }));
  });
});
