"use client";

import { useFormState, useFormStatus } from "react-dom";

import { addMemberAction, type FormState } from "@/lib/actions";

function SubmitButton() {
  const { pending } = useFormStatus();
  return (
    <button type="submit" className="btn-primary" disabled={pending}>
      {pending ? "Adding…" : "Add member"}
    </button>
  );
}

export default function AddMemberForm({ workspaceId }: { workspaceId: string }) {
  const [state, formAction] = useFormState<FormState, FormData>(addMemberAction, {});

  return (
    <form action={formAction} className="card max-w-lg space-y-3 p-4">
      <h2 className="font-medium text-slate-100">Add a member</h2>
      <input type="hidden" name="workspaceId" value={workspaceId} />

      <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
        <div>
          <label className="label" htmlFor="member-email">
            Email
          </label>
          <input
            id="member-email"
            name="email"
            type="email"
            className="input"
            placeholder="teammate@example.com"
            required
          />
        </div>

        <div>
          <label className="label" htmlFor="member-role">
            Role
          </label>
          <select id="member-role" name="role" className="input" defaultValue="member">
            <option value="viewer">Viewer</option>
            <option value="member">Member</option>
            <option value="admin">Admin</option>
            <option value="owner">Owner</option>
          </select>
        </div>
      </div>

      <p className="text-xs text-slate-500">
        The person must already have a Vaultly account.
      </p>

      {state.error && (
        <p role="alert" className="text-sm text-red-400">
          {state.fields ? Object.values(state.fields).join("; ") : state.error}
        </p>
      )}
      {state.ok && <p className="text-sm text-emerald-400">Member added.</p>}

      <SubmitButton />
    </form>
  );
}
