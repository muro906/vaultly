"use client";

import { useState } from "react";
import { useFormState, useFormStatus } from "react-dom";

import { createWorkspaceAction, type FormState } from "@/lib/actions";

function SubmitButton() {
  const { pending } = useFormStatus();
  return (
    <button type="submit" className="btn-primary" disabled={pending}>
      {pending ? "Creating…" : "Create workspace"}
    </button>
  );
}

export default function CreateWorkspaceForm() {
  const [state, formAction] = useFormState<FormState, FormData>(createWorkspaceAction, {});
  const [open, setOpen] = useState(false);

  if (!open) {
    return (
      <button type="button" className="btn-secondary" onClick={() => setOpen(true)}>
        New workspace
      </button>
    );
  }

  return (
    <form action={formAction} className="card max-w-md space-y-3 p-4">
      <div>
        <label className="label" htmlFor="workspace-name">
          Workspace name
        </label>
        <input id="workspace-name" name="name" className="input" placeholder="Platform team" required />
      </div>

      {state.error && (
        <p role="alert" className="text-sm text-red-400">
          {state.fields ? Object.values(state.fields).join("; ") : state.error}
        </p>
      )}
      {state.ok && <p className="text-sm text-emerald-400">Workspace created.</p>}

      <div className="flex gap-2">
        <SubmitButton />
        <button type="button" className="btn-secondary" onClick={() => setOpen(false)}>
          Cancel
        </button>
      </div>
    </form>
  );
}
