import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import ActivityFeed from "./ActivityFeed";
import type { AuditEntry } from "@/lib/types";

function entry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    id: overrides.id ?? "entry-1",
    workspaceId: "ws-1",
    action: "secret.created",
    resourceType: "secret",
    createdAt: new Date().toISOString(),
    ...overrides,
  };
}

describe("ActivityFeed", () => {
  it("says nothing has happened when the log is empty", () => {
    render(<ActivityFeed entries={[]} workspaceId="ws-1" />);

    expect(screen.getByText(/nothing recorded yet/i)).toBeInTheDocument();
  });

  it("names the filter in the empty state so the user knows why it is empty", () => {
    render(<ActivityFeed entries={[]} workspaceId="ws-1" activeAction="secret.read" />);

    // Without this, a filter with no matches looks like an empty workspace.
    expect(screen.getByText(/secret\.read/)).toBeInTheDocument();
  });

  it("renders a readable label rather than the raw action", () => {
    render(
      <ActivityFeed
        entries={[entry({ action: "secret.read", actorEmail: "millie@example.com" })]}
        workspaceId="ws-1"
      />,
    );

    expect(screen.getByText(/revealed a secret/i)).toBeInTheDocument();
    expect(screen.getByText("millie@example.com")).toBeInTheDocument();
  });

  it("falls back to the raw action for one it does not know", () => {
    // A newly added action must still appear rather than silently rendering
    // as blank.
    render(
      <ActivityFeed entries={[entry({ action: "secret.exported" })]} workspaceId="ws-1" />,
    );

    expect(screen.getByText(/secret\.exported/)).toBeInTheDocument();
  });

  it("attributes an action to a token when a machine did it", () => {
    render(
      <ActivityFeed
        entries={[
          entry({ action: "secrets.pulled", actorTokenName: "github-actions", resourceType: "environment" }),
        ]}
        workspaceId="ws-1"
      />,
    );

    // Telling a human apart from a machine is the point of the actor column.
    expect(screen.getByText(/token “github-actions”/)).toBeInTheDocument();
    expect(screen.getByText(/pulled secrets/i)).toBeInTheDocument();
  });

  it("falls back to a neutral actor when neither is recorded", () => {
    render(<ActivityFeed entries={[entry({ action: "secret.created" })]} workspaceId="ws-1" />);

    expect(screen.getByText(/someone/i)).toBeInTheDocument();
  });

  it("summarises the metadata that matters for each action", () => {
    render(
      <ActivityFeed
        entries={[
          entry({
            id: "a",
            action: "secret.updated",
            actorEmail: "millie@example.com",
            metadata: { key: "STRIPE_KEY", version: 4 },
          }),
          entry({
            id: "b",
            action: "secrets.promoted",
            actorEmail: "millie@example.com",
            metadata: { source: "development", target: "staging", applied: 3 },
          }),
        ]}
        workspaceId="ws-1"
      />,
    );

    expect(screen.getByText(/STRIPE_KEY · v4/)).toBeInTheDocument();
    expect(screen.getByText(/development → staging · 3 written/)).toBeInTheDocument();
  });

  it("never renders a secret value even if one appears in the metadata", () => {
    // The API does not put values in the audit log, and this component must
    // not start surfacing them if that ever changes.
    render(
      <ActivityFeed
        entries={[
          entry({
            action: "secret.read",
            metadata: { key: "STRIPE_KEY", value: "sk_live_should_never_render" },
          }),
        ]}
        workspaceId="ws-1"
      />,
    );

    expect(screen.queryByText(/sk_live_should_never_render/)).not.toBeInTheDocument();
    expect(screen.getByText(/STRIPE_KEY/)).toBeInTheDocument();
  });

  it("shows the source address when one was recorded", () => {
    render(
      <ActivityFeed
        entries={[entry({ ipAddress: "203.0.113.4", actorEmail: "millie@example.com" })]}
        workspaceId="ws-1"
      />,
    );

    expect(screen.getByText(/203\.0\.113\.4/)).toBeInTheDocument();
  });

  it("renders a relative time with the exact timestamp available on hover", () => {
    const createdAt = new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString();
    render(<ActivityFeed entries={[entry({ createdAt })]} workspaceId="ws-1" />);

    const time = screen.getByText("3h ago");
    expect(time.tagName).toBe("TIME");
    expect(time).toHaveAttribute("dateTime", createdAt);
    expect(time).toHaveAttribute("title");
  });

  it("offers a pagination link only when there are older entries", () => {
    const { rerender } = render(
      <ActivityFeed entries={[entry()]} workspaceId="ws-1" nextCursor="cursor-abc" />,
    );

    const link = screen.getByRole("link", { name: /load older activity/i });
    expect(link).toHaveAttribute("href", expect.stringContaining("cursor=cursor-abc"));

    rerender(<ActivityFeed entries={[entry()]} workspaceId="ws-1" />);
    expect(screen.queryByRole("link", { name: /load older activity/i })).not.toBeInTheDocument();
  });

  it("carries the active filter through to the next page", () => {
    render(
      <ActivityFeed
        entries={[entry()]}
        workspaceId="ws-1"
        nextCursor="cursor-abc"
        activeAction="secret.read"
      />,
    );

    // Losing the filter when paging would silently widen the results.
    const link = screen.getByRole("link", { name: /load older activity/i });
    expect(link.getAttribute("href")).toContain("action=secret.read");
    expect(link.getAttribute("href")).toContain("cursor=cursor-abc");
  });

  it("lists every entry it is given", () => {
    const entries = Array.from({ length: 5 }, (_, i) =>
      entry({ id: `entry-${i}`, actorEmail: `user${i}@example.com` }),
    );
    render(<ActivityFeed entries={entries} workspaceId="ws-1" />);

    const list = screen.getAllByRole("list")[0]!;
    expect(within(list).getAllByRole("listitem")).toHaveLength(5);
  });
});
