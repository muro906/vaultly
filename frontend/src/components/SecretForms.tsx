"use client";

import { useState } from "react";
import { useFormState, useFormStatus } from "react-dom";

import { createSecretAction, updateSecretAction, type FormState } from "@/lib/actions";

function SubmitButton({ label }: { label: string }) {
  const { pending } = useFormStatus();
  return (
    <button type="submit" className="btn-primary" disabled={pending}>
      {pending ? "Saving…" : label}
    </button>
  );
}

/** Adds a secret to an environment. */
export function CreateSecretForm({
  environmentId,
  projectId,
}: {
  environmentId: string;
  projectId: string;
}) {
  const [state, formAction] = useFormState<FormState, FormData>(createSecretAction, {});
  const [open, setOpen] = useState(false);

  if (!open) {
    return (
      <button type="button" className="btn-primary" onClick={() => setOpen(true)}>
        Add secret
      </button>
    );
  }

  return (
    <form action={formAction} className="card space-y-3 p-4">
      <input type="hidden" name="environmentId" value={environmentId} />
      <input type="hidden" name="projectId" value={projectId} />

      <div className="grid gap-3 sm:grid-cols-2">
        <div>
          <label className="label" htmlFor="secret-key">
            Key
          </label>
          <input
            id="secret-key"
            name="key"
            className="input font-mono"
            placeholder="DATABASE_URL"
            // Mirrors the server's rule so a typo is caught before a round trip.
            pattern="[A-Z][A-Z0-9_]*"
            title="Uppercase letters, digits and underscores; must start with a letter."
            required
          />
        </div>
        <div>
          <label className="label" htmlFor="secret-description">
            Description (optional)
          </label>
          <input id="secret-description" name="description" className="input" />
        </div>
      </div>

      <div>
        <label className="label" htmlFor="secret-value">
          Value
        </label>
        <textarea
          id="secret-value"
          name="value"
          rows={3}
          className="input font-mono"
          // Off so a browser never stores a secret in its form history.
          autoComplete="off"
          spellCheck={false}
          required
        />
      </div>

      {state.error && (
        <p role="alert" className="text-sm text-red-400">
          {state.fields ? Object.entries(state.fields).map(([f, m]) => `${f} ${m}`).join("; ") : state.error}
        </p>
      )}
      {state.ok && <p className="text-sm text-emerald-400">Secret saved.</p>}

      <div className="flex gap-2">
        <SubmitButton label="Save secret" />
        <button type="button" className="btn-secondary" onClick={() => setOpen(false)}>
          Cancel
        </button>
      </div>
    </form>
  );
}

/** Changes a secret's value, creating a new version. */
export function UpdateSecretForm({
  secretId,
  projectId,
  currentVersion,
}: {
  secretId: string;
  projectId: string;
  currentVersion: number;
}) {
  const [state, formAction] = useFormState<FormState, FormData>(updateSecretAction, {});
  const [open, setOpen] = useState(false);

  if (!open) {
    return (
      <button
        type="button"
        className="text-xs text-slate-400 hover:text-slate-200"
        onClick={() => setOpen(true)}
      >
        Edit
      </button>
    );
  }

  return (
    <form action={formAction} className="mt-2 space-y-2 rounded-md border border-surface-border p-3">
      <input type="hidden" name="secretId" value={secretId} />
      <input type="hidden" name="projectId" value={projectId} />
      {/* The version this form was built from, so a concurrent edit is
          reported rather than silently overwritten. */}
      <input type="hidden" name="expectedVersion" value={currentVersion} />

      <div>
        <label className="label" htmlFor={`value-${secretId}`}>
          New value
        </label>
        <textarea
          id={`value-${secretId}`}
          name="value"
          rows={2}
          className="input font-mono"
          autoComplete="off"
          spellCheck={false}
          required
        />
      </div>

      <div>
        <label className="label" htmlFor={`comment-${secretId}`}>
          Reason (optional)
        </label>
        <input
          id={`comment-${secretId}`}
          name="comment"
          className="input"
          placeholder="rotated after key leak"
        />
      </div>

      {state.error && (
        <p role="alert" className="text-sm text-red-400">
          {state.error}
        </p>
      )}
      {state.ok && <p className="text-sm text-emerald-400">Saved as a new version.</p>}

      <div className="flex gap-2">
        <SubmitButton label="Save new version" />
        <button type="button" className="btn-secondary" onClick={() => setOpen(false)}>
          Cancel
        </button>
      </div>
    </form>
  );
}
