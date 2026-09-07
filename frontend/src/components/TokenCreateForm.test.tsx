import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { FormState } from "@/lib/actions";
import type { AccessToken, Environment } from "@/lib/types";

// useFormState drives this component, so the tests control it directly rather
// than standing up a server to run the action.
const formState = { current: {} as FormState };

vi.mock("react-dom", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-dom")>();
  return {
    ...actual,
    useFormState: (_action: unknown, _initial: FormState) => [
      formState.current,
      "/action",
    ],
    useFormStatus: () => ({ pending: false }),
  };
});

vi.mock("@/lib/actions", () => ({
  createTokenAction: vi.fn(),
}));

const { default: TokenCreateForm } = await import("./TokenCreateForm");

const environments: Environment[] = [
  {
    id: "env-dev",
    projectId: "proj-1",
    name: "development",
    rank: 0,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
  },
  {
    id: "env-prod",
    projectId: "proj-1",
    name: "production",
    rank: 2,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
  },
];

function createdToken(overrides: Partial<AccessToken> = {}): AccessToken {
  return {
    id: "token-1",
    projectId: "proj-1",
    environmentId: "env-prod",
    name: "github-actions",
    prefix: "a1b2c3d4",
    scopes: ["secrets:read"],
    ipAllowlist: [],
    rateLimitRpm: 60,
    createdAt: "2026-01-01T00:00:00Z",
    plaintext: "vlt_a1b2c3d4_thesecrethalfofthetoken",
    ...overrides,
  };
}

describe("TokenCreateForm", () => {
  beforeEach(() => {
    formState.current = {};
  });

  describe("the creation form", () => {
    it("offers every environment in the project", () => {
      render(<TokenCreateForm projectId="proj-1" environments={environments} />);

      const select = screen.getByLabelText(/environment/i);
      expect(within(select).getByRole("option", { name: "development" })).toBeInTheDocument();
      expect(within(select).getByRole("option", { name: "production" })).toBeInTheDocument();
    });

    it("defaults to read-only, the least a CI job needs", () => {
      render(<TokenCreateForm projectId="proj-1" environments={environments} />);

      expect(screen.getByLabelText(/read secrets/i)).toBeChecked();
      expect(screen.getByLabelText(/write secrets/i)).not.toBeChecked();
    });

    it("defaults the rate limit rather than leaving it unset", () => {
      render(<TokenCreateForm projectId="proj-1" environments={environments} />);

      expect(screen.getByLabelText(/rate limit/i)).toHaveValue(60);
    });

    it("explains that an empty allowlist allows any address", () => {
      render(<TokenCreateForm projectId="proj-1" environments={environments} />);

      // The empty case is permissive, so it must not be left to be guessed.
      expect(screen.getByText(/leave empty to allow any address/i)).toBeInTheDocument();
    });

    it("carries the project through to the action", () => {
      const { container } = render(
        <TokenCreateForm projectId="proj-1" environments={environments} />,
      );

      const hidden = container.querySelector('input[name="projectId"]');
      expect(hidden).toHaveValue("proj-1");
    });

    it("surfaces field-level errors from the server", () => {
      formState.current = {
        error: "validation failed",
        fields: { ipAllowlist: '"999.1.1.1" is not a valid IP address or CIDR block' },
      };
      render(<TokenCreateForm projectId="proj-1" environments={environments} />);

      expect(screen.getByRole("alert")).toHaveTextContent(/not a valid IP address/i);
    });
  });

  describe("after a token is created", () => {
    beforeEach(() => {
      formState.current = { ok: true, token: createdToken() };
    });

    it("shows the token exactly once, with a warning", () => {
      render(<TokenCreateForm projectId="proj-1" environments={environments} />);

      expect(screen.getByText("vlt_a1b2c3d4_thesecrethalfofthetoken")).toBeInTheDocument();
      expect(screen.getByText(/only time/i)).toBeInTheDocument();
      expect(screen.getByText(/cannot be retrieved later/i)).toBeInTheDocument();
    });

    it("replaces the form so the token cannot scroll out of sight", () => {
      render(<TokenCreateForm projectId="proj-1" environments={environments} />);

      // The panel must be dismissed deliberately; a form still on screen would
      // invite navigating away and losing the value for good.
      expect(screen.queryByLabelText(/rate limit/i)).not.toBeInTheDocument();
      expect(screen.getByRole("button", { name: /i have saved it/i })).toBeInTheDocument();
    });

    it("copies the token to the clipboard", async () => {
      // userEvent.setup installs its own clipboard stub and defines it as a
      // getter, so the assertion spies on that stub rather than replacing it.
      const user = userEvent.setup();
      const writeText = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue();

      render(<TokenCreateForm projectId="proj-1" environments={environments} />);

      await user.click(screen.getByRole("button", { name: /^copy$/i }));

      expect(writeText).toHaveBeenCalledWith("vlt_a1b2c3d4_thesecrethalfofthetoken");
      expect(await screen.findByRole("button", { name: /copied/i })).toBeInTheDocument();
    });

    it("shows a pipeline example so the token can be put to use", () => {
      render(<TokenCreateForm projectId="proj-1" environments={environments} />);

      expect(screen.getByText(/cicd\/secrets\?format=dotenv/)).toBeInTheDocument();
    });

    it("does not show the panel when the action returned no plaintext", () => {
      // A listing carries tokens without their plaintext; that must render the
      // form, not an empty "copy this" panel.
      formState.current = { ok: true, token: createdToken({ plaintext: undefined }) };
      render(<TokenCreateForm projectId="proj-1" environments={environments} />);

      expect(screen.queryByText(/only time/i)).not.toBeInTheDocument();
      expect(screen.getByLabelText(/rate limit/i)).toBeInTheDocument();
    });
  });
});
