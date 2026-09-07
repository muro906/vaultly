import { render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { FormState } from "@/lib/actions";
import type { Environment, PromotionPlan } from "@/lib/types";

const formState = { current: {} as FormState };

vi.mock("react-dom", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-dom")>();
  return {
    ...actual,
    useFormState: (_action: unknown, _initial: FormState) => [formState.current, "/action"],
    useFormStatus: () => ({ pending: false }),
  };
});

vi.mock("@/lib/actions", () => ({ promoteAction: vi.fn() }));

const { default: PromotionPanel } = await import("./PromotionPanel");

const environments: Environment[] = [
  { id: "env-prod", projectId: "p", name: "production", rank: 2, createdAt: "", updatedAt: "" },
  { id: "env-dev", projectId: "p", name: "development", rank: 0, createdAt: "", updatedAt: "" },
  { id: "env-staging", projectId: "p", name: "staging", rank: 1, createdAt: "", updatedAt: "" },
];

function plan(overrides: Partial<PromotionPlan> = {}): PromotionPlan {
  return {
    sourceEnvironmentId: "env-dev",
    targetEnvironmentId: "env-staging",
    sourceName: "development",
    targetName: "staging",
    changes: [],
    dryRun: true,
    applied: 0,
    ...overrides,
  };
}

describe("PromotionPanel", () => {
  beforeEach(() => {
    formState.current = {};
  });

  it("lists environments in promotion order, not the order given", () => {
    render(<PromotionPanel projectId="p" environments={environments} />);

    // The props are deliberately unordered; the UI must impose the ranking so
    // the promotion path reads correctly.
    const options = within(screen.getByLabelText(/^from$/i)).getAllByRole("option");
    expect(options.map((o) => o.textContent)).toEqual(["development", "staging", "production"]);
  });

  it("offers only a preview before anything has been previewed", () => {
    render(<PromotionPanel projectId="p" environments={environments} />);

    expect(screen.getByRole("button", { name: /preview changes/i })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /apply/i })).not.toBeInTheDocument();
  });

  it("shows what a promotion would do without applying it", () => {
    formState.current = {
      ok: true,
      plan: plan({
        changes: [
          { key: "ALPHA", type: "added", masked: true },
          { key: "BETA", type: "changed", masked: true },
          { key: "GAMMA", type: "unchanged", masked: true },
        ],
      }),
    };
    render(<PromotionPanel projectId="p" environments={environments} />);

    expect(screen.getByText(/development → staging/)).toBeInTheDocument();
    expect(screen.getByText(/2 of 3 keys would change/)).toBeInTheDocument();
    expect(screen.getByText("ALPHA")).toBeInTheDocument();
    expect(screen.getByText("added")).toBeInTheDocument();
    expect(screen.getByText("changed")).toBeInTheDocument();
    expect(screen.getByText("unchanged")).toBeInTheDocument();
  });

  it("never shows a value, only the key and what would happen to it", () => {
    formState.current = {
      ok: true,
      plan: plan({
        changes: [
          {
            key: "STRIPE_KEY",
            type: "changed",
            masked: true,
            sourceValue: "sk_live_should_not_render",
            targetValue: "sk_live_also_not",
          },
        ],
      }),
    };
    render(<PromotionPanel projectId="p" environments={environments} />);

    expect(screen.getByText("STRIPE_KEY")).toBeInTheDocument();
    expect(screen.queryByText(/sk_live_should_not_render/)).not.toBeInTheDocument();
    expect(screen.queryByText(/sk_live_also_not/)).not.toBeInTheDocument();
  });

  it("offers to apply only once a preview shows real changes", () => {
    formState.current = {
      ok: true,
      plan: plan({ changes: [{ key: "ALPHA", type: "added", masked: true }] }),
    };
    render(<PromotionPanel projectId="p" environments={environments} />);

    // Applying is a second, deliberate step: this writes into a later
    // environment, possibly production.
    const apply = screen.getByRole("button", { name: /apply 1 change/i });
    expect(apply).toHaveAttribute("name", "dryRun");
    expect(apply).toHaveAttribute("value", "false");
  });

  it("does not offer to apply when nothing would change", () => {
    formState.current = {
      ok: true,
      plan: plan({ changes: [{ key: "ALPHA", type: "unchanged", masked: true }] }),
    };
    render(<PromotionPanel projectId="p" environments={environments} />);

    expect(screen.queryByRole("button", { name: /apply/i })).not.toBeInTheDocument();
  });

  it("says so when the source environment is empty", () => {
    formState.current = { ok: true, plan: plan({ changes: [] }) };
    render(<PromotionPanel projectId="p" environments={environments} />);

    expect(screen.getByText(/no secrets in development to promote/i)).toBeInTheDocument();
  });

  it("reports what was written after applying", () => {
    formState.current = {
      ok: true,
      plan: plan({
        dryRun: false,
        applied: 2,
        changes: [
          { key: "ALPHA", type: "added", masked: true },
          { key: "BETA", type: "changed", masked: true },
        ],
      }),
    };
    render(<PromotionPanel projectId="p" environments={environments} />);

    expect(screen.getByText(/Applied.*2 keys written/)).toBeInTheDocument();
    // The apply button must not linger after the write has happened.
    expect(screen.queryByRole("button", { name: /apply/i })).not.toBeInTheDocument();
  });

  it("surfaces a rejected direction as an error", () => {
    formState.current = {
      error: "validation failed",
      fields: {
        targetEnvironmentId:
          '"development" does not come after "production" in the promotion path',
      },
    };
    render(<PromotionPanel projectId="p" environments={environments} />);

    expect(screen.getByRole("alert")).toHaveTextContent(/does not come after/i);
  });

  it("explains that promotion only runs forwards", () => {
    render(<PromotionPanel projectId="p" environments={environments} />);

    expect(
      screen.getByText(/production can never be pushed back into development/i),
    ).toBeInTheDocument();
  });
});
