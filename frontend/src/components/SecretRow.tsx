"use client";

import Link from "next/link";

import { deleteSecretAction, revealSecretAction } from "@/lib/actions";
import type { Secret } from "@/lib/types";

import MaskedSecret from "./MaskedSecret";
import { UpdateSecretForm } from "./SecretForms";

export default function SecretRow({
  secret,
  projectId,
  canReveal,
  canWrite,
}: {
  secret: Secret;
  projectId: string;
  canReveal: boolean;
  canWrite: boolean;
}) {
  return (
    <li className="px-4 py-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <p className="font-mono text-sm font-medium text-slate-100">{secret.key}</p>
          {secret.description && (
            <p className="mt-0.5 text-xs text-slate-500">{secret.description}</p>
          )}
        </div>

        <div className="flex items-center gap-4">
          <MaskedSecret
            secretId={secret.id}
            reveal={revealSecretAction}
            disabled={!canReveal}
            disabledReason="Viewers cannot reveal secret values."
          />

          <Link
            href={`/secrets/${secret.id}`}
            className="text-xs text-slate-400 hover:text-slate-200"
          >
            v{secret.currentVersion} history
          </Link>

          {canWrite && (
            <>
              <UpdateSecretForm
                secretId={secret.id}
                projectId={projectId}
                currentVersion={secret.currentVersion}
              />

              <form action={deleteSecretAction}>
                <input type="hidden" name="secretId" value={secret.id} />
                <input type="hidden" name="projectId" value={projectId} />
                <button
                  type="submit"
                  className="text-xs text-red-400 hover:text-red-300"
                  onClick={(e) => {
                    // Deleting hides the secret from every environment listing
                    // and from any pipeline pulling it, so it is worth a pause.
                    if (!confirm(`Delete ${secret.key}? Its history is kept, but it will stop being served.`)) {
                      e.preventDefault();
                    }
                  }}
                >
                  Delete
                </button>
              </form>
            </>
          )}
        </div>
      </div>
    </li>
  );
}
