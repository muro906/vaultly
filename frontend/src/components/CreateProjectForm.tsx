"use client";

import { useState } from "react";
import { useFormState, useFormStatus } from "react-dom";

import { createProjectAction, type FormState } from "@/lib/actions";

function SubmitButton() {
  const { pending } = useFormStatus();
  return (
    <button type="submit" className="btn-primary" disabled={pending}>
      {pending ? "Creating…" : "Create project"}
    </button>
  );
}

export default function CreateProjectForm({ workspaceId }: { workspaceId: string }) {
  const [state, formAction] = useFormState<FormState, FormData>(createProjectAction, {});
  const [open, setOpen] = useState(false);

  if (!open) {
    return (
      <button type="button" className="btn-primary" onClick={() => setOpen(true)}>
        New project
      </button>
    );
  }

  return (
    <form action={formAction} className="card max-w-md space-y-3 p-4">
      <input type="hidden" name="workspaceId" value={workspaceId} />

      <div>
        <label className="label" htmlFor="project-name">
          Project name
        </label>
        <input id="project-name" name="name" className="input" placeholder="Payments API" required />
      </div>

      <div>
        <label className="label" htmlFor="project-description">
          Description (optional)
        </label>
        <input id="project-description" name="description" className="input" />
      </div>

      <p className="text-xs text-slate-500">
        Development, staging and production environments are created automatically.
      </p>

      {state.error && (
        <p role="alert" className="text-sm text-red-400">
          {state.fields ? Object.values(state.fields).join("; ") : state.error}
        </p>
      )}
      {state.ok && <p className="text-sm text-emerald-400">Project created.</p>}

      <div className="flex gap-2">
        <SubmitButton />
        <button type="button" className="btn-secondary" onClick={() => setOpen(false)}>
          Cancel
        </button>
      </div>
    </form>
  );
}
