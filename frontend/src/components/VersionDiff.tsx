"use client";

import { useMemo, useState } from "react";

import type { SecretVersion } from "@/lib/types";

interface VersionDiffProps {
  secretId: string;
  versions: SecretVersion[];
  reveal: (secretId: string, version: number) => Promise<{ value?: string; error?: string }>;
  canReveal: boolean;
}

type DiffLine = {
  kind: "same" | "added" | "removed";
  text: string;
};

/**
 * A line-level diff.
 *
 * This is a longest-common-subsequence diff rather than a naive line-by-line
 * comparison, so inserting one line at the top of a multi-line secret (a
 * certificate, say) shows as a single addition instead of marking every
 * subsequent line as changed.
 */
export function diffLines(before: string, after: string): DiffLine[] {
  const a = before.split("\n");
  const b = after.split("\n");

  // lengths[i][j] is the LCS length of a[i:] and b[j:].
  const lengths: number[][] = Array.from({ length: a.length + 1 }, () =>
    new Array<number>(b.length + 1).fill(0),
  );
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      lengths[i]![j] =
        a[i] === b[j]
          ? lengths[i + 1]![j + 1]! + 1
          : Math.max(lengths[i + 1]![j]!, lengths[i]![j + 1]!);
    }
  }

  const result: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      result.push({ kind: "same", text: a[i]! });
      i++;
      j++;
    } else if (lengths[i + 1]![j]! >= lengths[i]![j + 1]!) {
      result.push({ kind: "removed", text: a[i]! });
      i++;
    } else {
      result.push({ kind: "added", text: b[j]! });
      j++;
    }
  }
  while (i < a.length) result.push({ kind: "removed", text: a[i++]! });
  while (j < b.length) result.push({ kind: "added", text: b[j++]! });

  return result;
}

export default function VersionDiff({ secretId, versions, reveal, canReveal }: VersionDiffProps) {
  const sorted = useMemo(() => [...versions].sort((x, y) => y.version - x.version), [versions]);

  // Defaults to comparing the two most recent versions, which is what someone
  // opening a history view almost always wants to see.
  const [left, setLeft] = useState<number>(sorted[1]?.version ?? sorted[0]?.version ?? 1);
  const [right, setRight] = useState<number>(sorted[0]?.version ?? 1);

  const [values, setValues] = useState<Record<number, string>>({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [visible, setVisible] = useState(false);

  async function compare() {
    setLoading(true);
    setError(null);
    try {
      // Both sides are fetched together so the view never renders half a
      // comparison.
      const [a, b] = await Promise.all([reveal(secretId, left), reveal(secretId, right)]);
      if (a.error || b.error) {
        setError(a.error ?? b.error ?? "Could not load these versions.");
        return;
      }
      setValues({ [left]: a.value ?? "", [right]: b.value ?? "" });
      setVisible(true);
    } catch {
      setError("Could not load these versions.");
    } finally {
      setLoading(false);
    }
  }

  function hide() {
    setValues({});
    setVisible(false);
  }

  if (!canReveal) {
    return (
      <p className="text-sm text-slate-500">
        Comparing versions requires member access, because it reveals the stored values.
      </p>
    );
  }

  const lines = visible ? diffLines(values[left] ?? "", values[right] ?? "") : [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end gap-3">
        <div>
          <label className="label" htmlFor="diff-left">
            From version
          </label>
          <select
            id="diff-left"
            className="input"
            value={left}
            onChange={(e) => setLeft(Number(e.target.value))}
          >
            {sorted.map((v) => (
              <option key={v.version} value={v.version}>
                v{v.version} — {v.comment || "no comment"}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="label" htmlFor="diff-right">
            To version
          </label>
          <select
            id="diff-right"
            className="input"
            value={right}
            onChange={(e) => setRight(Number(e.target.value))}
          >
            {sorted.map((v) => (
              <option key={v.version} value={v.version}>
                v{v.version} — {v.comment || "no comment"}
              </option>
            ))}
          </select>
        </div>

        <button type="button" onClick={compare} disabled={loading} className="btn-primary">
          {loading ? "Loading…" : "Compare"}
        </button>

        {visible && (
          <button type="button" onClick={hide} className="btn-secondary">
            Hide values
          </button>
        )}
      </div>

      {error && (
        <p role="alert" className="text-sm text-red-400">
          {error}
        </p>
      )}

      {visible && (
        <div className="space-y-2">
          <p className="text-xs text-slate-500">
            Comparing v{left} to v{right}. Both reveals are recorded in the activity log.
          </p>

          <pre
            data-testid="diff-output"
            className="overflow-x-auto rounded-lg border border-surface-border bg-surface p-4 text-sm"
          >
            {lines.map((line, index) => (
              <div
                key={index}
                data-kind={line.kind}
                className={
                  line.kind === "added"
                    ? "bg-emerald-950/50 text-emerald-300"
                    : line.kind === "removed"
                      ? "bg-red-950/50 text-red-300"
                      : "text-slate-400"
                }
              >
                <span className="select-none pr-2 text-slate-600">
                  {line.kind === "added" ? "+" : line.kind === "removed" ? "-" : " "}
                </span>
                {line.text === "" ? " " : line.text}
              </div>
            ))}
          </pre>

          {lines.every((line) => line.kind === "same") && (
            <p className="text-sm text-slate-500">These two versions are identical.</p>
          )}
        </div>
      )}
    </div>
  );
}
