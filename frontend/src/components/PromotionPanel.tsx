"use client";

import { useFormState, useFormStatus } from "react-dom";
import { useState } from "react";

import { promoteAction, type FormState } from "@/lib/actions";
import type { Environment } from "@/lib/types";

function SubmitButton({ label }: { label: string }) {
  const { pending } = useFormStatus();
  return (
    <button type="submit" name="dryRun" value="false" className="btn-primary" disabled={pending}>
      {pending ? "Working…" : label}
    </button>
  );
}

/**
 * Previews and applies a promotion.
 *
 * Applying is deliberately two steps: the preview says exactly which keys will
 * change, and only then is the apply button offered. Copying values into
 * production is not something to do from a single click.
 */
export default function PromotionPanel({
  projectId,
  environments,
}: {
  projectId: string;
  environments: Environment[];
}) {
  const [state, formAction] = useFormState<FormState, FormData>(promoteAction, {});
  const ordered = [...environments].sort((a, b) => a.rank - b.rank);

  const [source, setSource] = useState(ordered[0]?.id ?? "");
  const [target, setTarget] = useState(ordered[1]?.id ?? "");

  const plan = state.plan;
  const changes = plan?.changes ?? [];
  const changed = changes.filter((c) => c.type !== "unchanged");

  return (
    <div className="card space-y-4 p-4">
      <div>
        <h2 className="font-medium text-slate-100">Promote secrets</h2>
        <p className="text-sm text-slate-400">
          Copy values forward along the promotion path. Promotion only runs towards a later
          environment, so production can never be pushed back into development.
        </p>
      </div>

      <form action={formAction} className="space-y-4">
        <input type="hidden" name="projectId" value={projectId} />

        <div className="flex flex-wrap items-end gap-3">
          <div>
            <label className="label" htmlFor="promote-source">
              From
            </label>
            <select
              id="promote-source"
              name="sourceEnvironmentId"
              className="input"
              value={source}
              onChange={(e) => setSource(e.target.value)}
            >
              {ordered.map((env) => (
                <option key={env.id} value={env.id}>
                  {env.name}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="label" htmlFor="promote-target">
              To
            </label>
            <select
              id="promote-target"
              name="targetEnvironmentId"
              className="input"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            >
              {ordered.map((env) => (
                <option key={env.id} value={env.id}>
                  {env.name}
                </option>
              ))}
            </select>
          </div>

          <button
            type="submit"
            name="dryRun"
            value="true"
            className="btn-secondary"
            formNoValidate
          >
            Preview changes
          </button>
        </div>

        {state.error && (
          <p role="alert" className="text-sm text-red-400">
            {state.fields
              ? Object.values(state.fields).join("; ")
              : state.error}
          </p>
        )}

        {plan && (
          <div className="space-y-3 rounded-md border border-surface-border bg-surface p-3">
            <p className="text-sm text-slate-300">
              {plan.dryRun ? "Preview" : "Applied"}: {plan.sourceName} → {plan.targetName}
              {plan.dryRun
                ? ` — ${changed.length} of ${changes.length} keys would change`
                : ` — ${plan.applied} keys written`}
            </p>

            {changes.length === 0 ? (
              <p className="text-sm text-slate-500">
                There are no secrets in {plan.sourceName} to promote.
              </p>
            ) : (
              <ul className="space-y-1 text-sm">
                {changes.map((change) => (
                  <li key={change.key} className="flex items-center gap-2 font-mono">
                    <span
                      className={
                        change.type === "added"
                          ? "badge bg-emerald-950 text-emerald-300"
                          : change.type === "changed"
                            ? "badge bg-amber-950 text-amber-300"
                            : "badge bg-slate-800 text-slate-400"
                      }
                    >
                      {change.type}
                    </span>
                    {change.key}
                  </li>
                ))}
              </ul>
            )}

            {plan.dryRun && changed.length > 0 && (
              <div className="flex items-center gap-2 pt-1">
                <SubmitButton label={`Apply ${changed.length} change(s)`} />
                <span className="text-xs text-slate-500">
                  This writes a new version for each changed key.
                </span>
              </div>
            )}
          </div>
        )}
      </form>
    </div>
  );
}
