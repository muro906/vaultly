"use client";

import { useCallback, useEffect, useRef, useState } from "react";

/** How long a revealed value stays on screen before it hides itself. */
export const REVEAL_SECONDS = 10;

interface MaskedSecretProps {
  secretId: string;
  /**
   * Fetches the plaintext. Injected rather than imported so this component can
   * be tested without a server, and so the same component works for a current
   * value and for a historical version.
   */
  reveal: (secretId: string) => Promise<{ value?: string; error?: string }>;
  /** Shown in place of the value while hidden. */
  placeholder?: string;
  disabled?: boolean;
  disabledReason?: string;
}

/**
 * Shows a secret as dots until clicked, then reveals it for a countdown before
 * hiding it again.
 *
 * The auto-hide exists because the realistic risk is not an attacker at the
 * keyboard, it is a value left on screen during a screen share or in front of
 * a passing colleague. For the same reason the value is also hidden the moment
 * the tab loses focus, and it is fetched on demand rather than being present
 * in the page and merely styled as hidden.
 */
export default function MaskedSecret({
  secretId,
  reveal,
  placeholder = "••••••••••••••••",
  disabled = false,
  disabledReason,
}: MaskedSecretProps) {
  const [value, setValue] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [remaining, setRemaining] = useState(REVEAL_SECONDS);
  const [copied, setCopied] = useState(false);

  // Tracks the in-flight request so a hide can abandon a reveal that has not
  // arrived yet, rather than having it pop into view after the user hid it.
  const requestRef = useRef(0);

  const hide = useCallback(() => {
    requestRef.current += 1;
    setValue(null);
    setError(null);
    setRemaining(REVEAL_SECONDS);
    setCopied(false);
  }, []);

  const show = useCallback(async () => {
    if (disabled || loading) return;

    const requestId = requestRef.current + 1;
    requestRef.current = requestId;

    setLoading(true);
    setError(null);
    try {
      const result = await reveal(secretId);
      // A newer reveal or a hide happened while this was in flight, so this
      // response is stale and must be dropped.
      if (requestRef.current !== requestId) return;

      if (result.error) {
        setError(result.error);
        return;
      }
      setValue(result.value ?? "");
      setRemaining(REVEAL_SECONDS);
    } catch {
      if (requestRef.current === requestId) setError("Could not reveal this secret.");
    } finally {
      if (requestRef.current === requestId) setLoading(false);
    }
  }, [disabled, loading, reveal, secretId]);

  // Counts down while visible and hides at zero.
  useEffect(() => {
    if (value === null) return;

    const timer = setInterval(() => {
      setRemaining((current) => {
        if (current <= 1) {
          hide();
          return REVEAL_SECONDS;
        }
        return current - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [value, hide]);

  // Hides when the tab is backgrounded: a revealed value must not be sitting
  // on a tab the user has walked away from.
  useEffect(() => {
    if (value === null) return;

    const onHidden = () => {
      if (document.visibilityState === "hidden") hide();
    };
    document.addEventListener("visibilitychange", onHidden);
    window.addEventListener("blur", hide);

    return () => {
      document.removeEventListener("visibilitychange", onHidden);
      window.removeEventListener("blur", hide);
    };
  }, [value, hide]);

  // Clears the value if the component goes away while revealed.
  useEffect(() => () => { requestRef.current += 1; }, []);

  const copy = useCallback(async () => {
    if (value === null) return;
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setError("Could not copy to the clipboard.");
    }
  }, [value]);

  if (disabled) {
    return (
      <span
        className="font-mono text-sm text-slate-600"
        title={disabledReason ?? "You do not have permission to view this value."}
      >
        {placeholder}
      </span>
    );
  }

  return (
    <div className="flex items-center gap-2">
      {value === null ? (
        <button
          type="button"
          onClick={show}
          disabled={loading}
          className="font-mono text-sm text-slate-400 hover:text-slate-200 disabled:opacity-60"
          aria-label="Reveal secret value"
        >
          {loading ? "Revealing…" : placeholder}
        </button>
      ) : (
        <>
          <code
            data-testid="revealed-value"
            className="max-w-md truncate rounded bg-surface px-2 py-1 font-mono text-sm text-emerald-300"
          >
            {value === "" ? <span className="text-slate-500">(empty)</span> : value}
          </code>

          <button
            type="button"
            onClick={copy}
            className="text-xs text-slate-400 hover:text-slate-200"
            aria-label="Copy secret value"
          >
            {copied ? "Copied" : "Copy"}
          </button>

          <button
            type="button"
            onClick={hide}
            className="text-xs text-slate-400 hover:text-slate-200"
            aria-label="Hide secret value"
          >
            Hide
          </button>

          <span
            className="text-xs tabular-nums text-slate-500"
            role="timer"
            aria-live="off"
            title={`Hides automatically in ${remaining} seconds`}
          >
            {remaining}s
          </span>
        </>
      )}

      {error && (
        <span role="alert" className="text-xs text-red-400">
          {error}
        </span>
      )}
    </div>
  );
}
