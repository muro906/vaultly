import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import VersionDiff, { diffLines } from "./VersionDiff";
import type { SecretVersion } from "@/lib/types";

const versions: SecretVersion[] = [
  { id: "v1", secretId: "s1", version: 1, comment: "created", createdAt: "2026-01-01T00:00:00Z" },
  { id: "v2", secretId: "s1", version: 2, comment: "rotated", createdAt: "2026-01-02T00:00:00Z" },
  { id: "v3", secretId: "s1", version: 3, comment: "rotated again", createdAt: "2026-01-03T00:00:00Z" },
];

describe("diffLines", () => {
  it("reports identical text as unchanged", () => {
    const lines = diffLines("same", "same");
    expect(lines).toEqual([{ kind: "same", text: "same" }]);
  });

  it("reports a replacement as a removal and an addition", () => {
    const lines = diffLines("before", "after");
    expect(lines).toEqual([
      { kind: "removed", text: "before" },
      { kind: "added", text: "after" },
    ]);
  });

  it("marks only the inserted line when a line is added in the middle", () => {
    // A naive line-by-line comparison would mark everything after the
    // insertion as changed, which makes a certificate diff unreadable.
    const lines = diffLines("a\nc", "a\nb\nc");

    expect(lines.filter((l) => l.kind === "added")).toEqual([{ kind: "added", text: "b" }]);
    expect(lines.filter((l) => l.kind === "removed")).toHaveLength(0);
    expect(lines.filter((l) => l.kind === "same").map((l) => l.text)).toEqual(["a", "c"]);
  });

  it("handles a line removed from the middle", () => {
    const lines = diffLines("a\nb\nc", "a\nc");

    expect(lines.filter((l) => l.kind === "removed")).toEqual([{ kind: "removed", text: "b" }]);
    expect(lines.filter((l) => l.kind === "added")).toHaveLength(0);
  });

  it("handles an empty side", () => {
    expect(diffLines("", "new").filter((l) => l.kind === "added")).toEqual([
      { kind: "added", text: "new" },
    ]);
    expect(diffLines("old", "").filter((l) => l.kind === "removed")).toEqual([
      { kind: "removed", text: "old" },
    ]);
  });

  it("preserves multi-line structure", () => {
    const before = "-----BEGIN KEY-----\nline-one\n-----END KEY-----";
    const after = "-----BEGIN KEY-----\nline-two\n-----END KEY-----";

    const lines = diffLines(before, after);
    expect(lines.filter((l) => l.kind === "same")).toHaveLength(2);
    expect(lines.filter((l) => l.kind === "removed")).toEqual([{ kind: "removed", text: "line-one" }]);
    expect(lines.filter((l) => l.kind === "added")).toEqual([{ kind: "added", text: "line-two" }]);
  });
});

describe("VersionDiff", () => {
  it("fetches nothing until a comparison is requested", () => {
    const reveal = vi.fn();
    render(<VersionDiff secretId="s1" versions={versions} reveal={reveal} canReveal />);

    expect(reveal).not.toHaveBeenCalled();
    expect(screen.queryByTestId("diff-output")).not.toBeInTheDocument();
  });

  it("defaults to comparing the two most recent versions", async () => {
    const reveal = vi.fn().mockResolvedValue({ value: "x" });
    const user = userEvent.setup();
    render(<VersionDiff secretId="s1" versions={versions} reveal={reveal} canReveal />);

    await user.click(screen.getByRole("button", { name: /compare/i }));

    expect(reveal).toHaveBeenCalledWith("s1", 2);
    expect(reveal).toHaveBeenCalledWith("s1", 3);
  });

  it("renders additions and removals once compared", async () => {
    const reveal = vi
      .fn()
      .mockImplementation((_id: string, version: number) =>
        Promise.resolve({ value: version === 2 ? "old-value" : "new-value" }),
      );
    const user = userEvent.setup();
    render(<VersionDiff secretId="s1" versions={versions} reveal={reveal} canReveal />);

    await user.click(screen.getByRole("button", { name: /compare/i }));

    const output = await screen.findByTestId("diff-output");
    expect(output).toHaveTextContent("old-value");
    expect(output).toHaveTextContent("new-value");
    expect(output.querySelector('[data-kind="removed"]')).toHaveTextContent("old-value");
    expect(output.querySelector('[data-kind="added"]')).toHaveTextContent("new-value");
  });

  it("says so when two versions hold the same value", async () => {
    const reveal = vi.fn().mockResolvedValue({ value: "unchanged-value" });
    const user = userEvent.setup();
    render(<VersionDiff secretId="s1" versions={versions} reveal={reveal} canReveal />);

    await user.click(screen.getByRole("button", { name: /compare/i }));

    expect(
      await screen.findByText("These two versions are identical."),
    ).toBeInTheDocument();
  });

  it("hides the values again on request", async () => {
    const reveal = vi.fn().mockResolvedValue({ value: "secret" });
    const user = userEvent.setup();
    render(<VersionDiff secretId="s1" versions={versions} reveal={reveal} canReveal />);

    await user.click(screen.getByRole("button", { name: /compare/i }));
    await screen.findByTestId("diff-output");

    await user.click(screen.getByRole("button", { name: /hide values/i }));

    expect(screen.queryByTestId("diff-output")).not.toBeInTheDocument();
  });

  it("surfaces a failure rather than rendering a half comparison", async () => {
    const reveal = vi
      .fn()
      .mockImplementationOnce(() => Promise.resolve({ value: "ok" }))
      .mockImplementationOnce(() => Promise.resolve({ error: "you do not have permission" }));
    const user = userEvent.setup();
    render(<VersionDiff secretId="s1" versions={versions} reveal={reveal} canReveal />);

    await user.click(screen.getByRole("button", { name: /compare/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/permission/i);
    expect(screen.queryByTestId("diff-output")).not.toBeInTheDocument();
  });

  it("offers nothing to a viewer who cannot decrypt", () => {
    const reveal = vi.fn();
    render(<VersionDiff secretId="s1" versions={versions} reveal={reveal} canReveal={false} />);

    expect(screen.queryByRole("button", { name: /compare/i })).not.toBeInTheDocument();
    expect(screen.getByText(/requires member access/i)).toBeInTheDocument();
    expect(reveal).not.toHaveBeenCalled();
  });
});
