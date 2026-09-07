"use client";

import { useFormState, useFormStatus } from "react-dom";
import { useState } from "react";

import { createTokenAction, type FormState } from "@/lib/actions";
import type { Environment } from "@/lib/types";

function SubmitButton() {
  const { pending } = useFormStatus();
  return (
    <button type="submit" className="btn-primary" disabled={pending}>
      {pending ? "Creating…" : "Create token"}
    </button>
  );
}

/**
 * Mints an access token and shows it once.
 *
 * The token is displayed in a panel the user must dismiss deliberately,
 * because it genuinely cannot be recovered afterwards and a toast that fades
 * on its own would lose it.
 */
export default function TokenCreateForm({
  projectId,
  environments,
}: {
  projectId: string;
  environments: Environment[];
}) {
  const [state, formAction] = useFormState<FormState, FormData>(createTokenAction, {});
  const [copied, setCopied] = useState(false);

  const created = state.token;

  if (created?.plaintext) {
    return (
      <div className="card space-y-3 border-amber-800/60 bg-amber-950/20 p-4">
        <h3 className="font-medium text-amber-200">Copy this token now</h3>
        <p className="text-sm text-amber-100/80">
          This is the only time <code>{created.name}</code> will be shown. Only a hash is stored, so
          it cannot be retrieved later. If you lose it, revoke it and create another.
        </p>

        <div className="flex items-center gap-2">
          <code className="flex-1 overflow-x-auto rounded bg-surface px-3 py-2 font-mono text-sm text-emerald-300">
            {created.plaintext}
          </code>
          <button
            type="button"
            className="btn-secondary"
            onClick={async () => {
              await navigator.clipboard.writeText(created.plaintext!);
              setCopied(true);
            }}
          >
            {copied ? "Copied" : "Copy"}
          </button>
        </div>

        <details className="text-sm text-amber-100/70">
          <summary className="cursor-pointer">Use it in a pipeline</summary>
          <pre className="mt-2 overflow-x-auto rounded bg-surface p-3 text-xs text-slate-300">
{`curl -sS -H "Authorization: Bearer $VAULTLY_TOKEN" \\
  "$VAULTLY_URL/api/v1/cicd/secrets?format=dotenv" > .env`}
          </pre>
        </details>

        <button type="button" className="btn-secondary" onClick={() => window.location.reload()}>
          I have saved it
        </button>
      </div>
    );
  }

  return (
    <form action={formAction} className="card space-y-4 p-4">
      <input type="hidden" name="projectId" value={projectId} />

      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <label className="label" htmlFor="token-name">
            Name
          </label>
          <input
            id="token-name"
            name="name"
            className="input"
            placeholder="github-actions-deploy"
            required
          />
        </div>

        <div>
          <label className="label" htmlFor="token-env">
            Environment
          </label>
          <select id="token-env" name="environmentId" className="input" required>
            {environments.map((env) => (
              <option key={env.id} value={env.id}>
                {env.name}
              </option>
            ))}
          </select>
        </div>
      </div>

      <fieldset>
        <legend className="label">Scopes</legend>
        <div className="flex gap-4 text-sm">
          <label className="flex items-center gap-2">
            <input type="checkbox" name="scopeRead" defaultChecked />
            Read secrets
          </label>
          <label className="flex items-center gap-2">
            <input type="checkbox" name="scopeWrite" />
            Write secrets
          </label>
        </div>
      </fieldset>

      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <label className="label" htmlFor="token-rate">
            Rate limit (requests per minute)
          </label>
          <input
            id="token-rate"
            name="rateLimitRpm"
            type="number"
            min={1}
            defaultValue={60}
            className="input"
          />
        </div>

        <div>
          <label className="label" htmlFor="token-expiry">
            Expires (optional)
          </label>
          <input id="token-expiry" name="expiresAt" type="date" className="input" />
        </div>
      </div>

      <div>
        <label className="label" htmlFor="token-ips">
          IP allowlist (optional)
        </label>
        <textarea
          id="token-ips"
          name="ipAllowlist"
          rows={3}
          className="input font-mono"
          placeholder={"203.0.113.4\n198.51.100.0/24"}
        />
        <p className="mt-1 text-xs text-slate-500">
          One address or CIDR block per line. Leave empty to allow any address.
        </p>
      </div>

      {state.error && (
        <p role="alert" className="text-sm text-red-400">
          {state.fields ? Object.entries(state.fields).map(([f, m]) => `${f}: ${m}`).join("; ") : state.error}
        </p>
      )}

      <SubmitButton />
    </form>
  );
}
