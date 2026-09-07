import { render, screen, waitFor, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import MaskedSecret, { REVEAL_SECONDS } from "./MaskedSecret";

/**
 * The auto-hide is the security-relevant behaviour of this component, so these
 * tests drive the clock directly rather than waiting in real time.
 */
describe("MaskedSecret", () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  function setup(reveal = vi.fn().mockResolvedValue({ value: "s3cr3t-value" })) {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    render(<MaskedSecret secretId="secret-1" reveal={reveal} />);
    return { user, reveal };
  }

  /** Advances the fake clock inside act, so React flushes the resulting state. */
  async function advance(seconds: number) {
    await act(async () => {
      vi.advanceTimersByTime(seconds * 1000);
    });
  }

  it("hides the value until it is asked for", () => {
    const reveal = vi.fn();
    render(<MaskedSecret secretId="secret-1" reveal={reveal} />);

    expect(screen.queryByTestId("revealed-value")).not.toBeInTheDocument();
    // Nothing is fetched on render, so the plaintext is never in the page
    // merely styled as hidden.
    expect(reveal).not.toHaveBeenCalled();
  });

  it("reveals the value when clicked", async () => {
    const { user, reveal } = setup();

    await user.click(screen.getByRole("button", { name: /reveal secret value/i }));

    expect(await screen.findByTestId("revealed-value")).toHaveTextContent("s3cr3t-value");
    expect(reveal).toHaveBeenCalledWith("secret-1");
  });

  it("counts down while the value is visible", async () => {
    const { user } = setup();
    await user.click(screen.getByRole("button", { name: /reveal secret value/i }));
    await screen.findByTestId("revealed-value");

    expect(screen.getByRole("timer")).toHaveTextContent(`${REVEAL_SECONDS}s`);

    await advance(3);
    expect(screen.getByRole("timer")).toHaveTextContent(`${REVEAL_SECONDS - 3}s`);
  });

  it("hides the value automatically once the countdown ends", async () => {
    const { user } = setup();
    await user.click(screen.getByRole("button", { name: /reveal secret value/i }));
    await screen.findByTestId("revealed-value");

    // Still visible just before the deadline.
    await advance(REVEAL_SECONDS - 1);
    expect(screen.getByTestId("revealed-value")).toBeInTheDocument();

    await advance(1);
    await waitFor(() => {
      expect(screen.queryByTestId("revealed-value")).not.toBeInTheDocument();
    });
    expect(screen.getByRole("button", { name: /reveal secret value/i })).toBeInTheDocument();
  });

  it("hides the value when the tab is backgrounded", async () => {
    const { user } = setup();
    await user.click(screen.getByRole("button", { name: /reveal secret value/i }));
    await screen.findByTestId("revealed-value");

    // A revealed secret must not sit on a tab the user has switched away from.
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      get: () => "hidden",
    });
    await act(async () => {
      document.dispatchEvent(new Event("visibilitychange"));
    });

    await waitFor(() => {
      expect(screen.queryByTestId("revealed-value")).not.toBeInTheDocument();
    });
  });

  it("hides the value on an explicit hide", async () => {
    const { user } = setup();
    await user.click(screen.getByRole("button", { name: /reveal secret value/i }));
    await screen.findByTestId("revealed-value");

    await user.click(screen.getByRole("button", { name: /hide secret value/i }));

    expect(screen.queryByTestId("revealed-value")).not.toBeInTheDocument();
  });

  it("restarts the countdown on a second reveal", async () => {
    const { user } = setup();

    await user.click(screen.getByRole("button", { name: /reveal secret value/i }));
    await screen.findByTestId("revealed-value");
    await advance(4);
    await user.click(screen.getByRole("button", { name: /hide secret value/i }));

    await user.click(screen.getByRole("button", { name: /reveal secret value/i }));
    await screen.findByTestId("revealed-value");

    // A stale countdown would hide the new reveal early.
    expect(screen.getByRole("timer")).toHaveTextContent(`${REVEAL_SECONDS}s`);
  });

  it("ignores a reveal that resolves after the component is gone", async () => {
    let resolveReveal: (result: { value: string }) => void = () => {};
    const reveal = vi.fn().mockImplementation(
      () => new Promise((resolve) => { resolveReveal = resolve; }),
    );
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    const { unmount } = render(<MaskedSecret secretId="secret-1" reveal={reveal} />);

    await user.click(screen.getByRole("button", { name: /reveal secret value/i }));
    expect(reveal).toHaveBeenCalledTimes(1);

    // The user navigates away while the request is still in flight. The
    // response must be dropped rather than setting state on a gone component.
    unmount();
    await act(async () => {
      resolveReveal({ value: "late-arriving-secret" });
    });

    expect(screen.queryByTestId("revealed-value")).not.toBeInTheDocument();
  });

  it("does not start a second reveal while one is in flight", async () => {
    const reveal = vi.fn().mockImplementation(() => new Promise(() => {}));
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    render(<MaskedSecret secretId="secret-1" reveal={reveal} />);

    const button = screen.getByRole("button", { name: /reveal secret value/i });
    await user.click(button);
    await user.click(button);

    // Each reveal is separately audited, so an impatient double-click must not
    // record two reads.
    expect(reveal).toHaveBeenCalledTimes(1);
  });

  it("surfaces a failure without showing a value", async () => {
    const reveal = vi.fn().mockResolvedValue({ error: "you do not have permission to do that" });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    render(<MaskedSecret secretId="secret-1" reveal={reveal} />);

    await user.click(screen.getByRole("button", { name: /reveal secret value/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/permission/i);
    expect(screen.queryByTestId("revealed-value")).not.toBeInTheDocument();
  });

  it("renders an empty value as such rather than as a blank row", async () => {
    const reveal = vi.fn().mockResolvedValue({ value: "" });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    render(<MaskedSecret secretId="secret-1" reveal={reveal} />);

    await user.click(screen.getByRole("button", { name: /reveal secret value/i }));

    expect(await screen.findByTestId("revealed-value")).toHaveTextContent("(empty)");
  });

  it("does not fetch anything when the viewer lacks permission", async () => {
    const reveal = vi.fn();
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    render(
      <MaskedSecret
        secretId="secret-1"
        reveal={reveal}
        disabled
        disabledReason="Viewers cannot reveal secret values."
      />,
    );

    // Rendered as static text, so there is nothing to click and no request to
    // make; the server would refuse anyway.
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(reveal).not.toHaveBeenCalled();
  });
});
