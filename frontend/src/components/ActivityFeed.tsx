import Link from "next/link";

import type { AuditEntry } from "@/lib/types";

/**
 * Human-readable labels for audit actions. Falling back to the raw action
 * means a newly added action shows up as itself rather than disappearing.
 */
const ACTION_LABELS: Record<string, string> = {
  "user.registered": "created an account",
  "user.logged_in": "signed in",
  "user.logged_out": "signed out",
  "workspace.created": "created the workspace",
  "member.added": "added a member",
  "member.removed": "removed a member",
  "member.role_updated": "changed a member's role",
  "project.created": "created a project",
  "project.deleted": "deleted a project",
  "environment.created": "created an environment",
  "secret.created": "added a secret",
  "secret.updated": "updated a secret",
  "secret.deleted": "deleted a secret",
  "secret.read": "revealed a secret",
  "secret.rolled_back": "rolled a secret back",
  "secrets.promoted": "promoted secrets",
  "secrets.pulled": "pulled secrets",
  "token.created": "created an access token",
  "token.revoked": "revoked an access token",
};

/** Actions that read or move secret material get a warmer colour. */
const SENSITIVE = new Set(["secret.read", "secrets.pulled", "secrets.promoted", "token.created"]);

function actorLabel(entry: AuditEntry): string {
  if (entry.actorEmail) return entry.actorEmail;
  if (entry.actorTokenName) return `token “${entry.actorTokenName}”`;
  return "someone";
}

function detailFor(entry: AuditEntry): string | null {
  const meta = entry.metadata;
  if (!meta) return null;

  const parts: string[] = [];
  if (typeof meta.key === "string") parts.push(meta.key);
  if (typeof meta.name === "string") parts.push(meta.name);
  if (typeof meta.version === "number") parts.push(`v${meta.version}`);
  if (typeof meta.source === "string" && typeof meta.target === "string") {
    parts.push(`${meta.source} → ${meta.target}`);
  }
  if (typeof meta.count === "number") parts.push(`${meta.count} secrets`);
  if (typeof meta.applied === "number") parts.push(`${meta.applied} written`);

  return parts.length > 0 ? parts.join(" · ") : null;
}

function formatTime(iso: string): string {
  const date = new Date(iso);
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);

  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`;
  return date.toLocaleDateString();
}

export default function ActivityFeed({
  entries,
  workspaceId,
  nextCursor,
  activeAction,
}: {
  entries: AuditEntry[];
  workspaceId: string;
  nextCursor?: string;
  activeAction?: string;
}) {
  if (entries.length === 0) {
    return (
      <p className="text-sm text-slate-500">
        Nothing recorded yet{activeAction ? ` for “${activeAction}”` : ""}.
      </p>
    );
  }

  return (
    <div className="space-y-4">
      <ul className="divide-y divide-surface-border">
        {entries.map((entry) => {
          const detail = detailFor(entry);
          return (
            <li key={entry.id} className="flex items-start gap-3 py-3">
              <span
                aria-hidden
                className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${
                  SENSITIVE.has(entry.action) ? "bg-amber-400" : "bg-slate-600"
                }`}
              />

              <div className="min-w-0 flex-1">
                <p className="text-sm text-slate-200">
                  <span className="font-medium">{actorLabel(entry)}</span>{" "}
                  {ACTION_LABELS[entry.action] ?? entry.action}
                  {detail && <span className="font-mono text-slate-400"> — {detail}</span>}
                </p>
                <p className="mt-0.5 text-xs text-slate-500">
                  <time dateTime={entry.createdAt} title={new Date(entry.createdAt).toLocaleString()}>
                    {formatTime(entry.createdAt)}
                  </time>
                  {entry.ipAddress && <span> · {entry.ipAddress}</span>}
                </p>
              </div>
            </li>
          );
        })}
      </ul>

      {nextCursor && (
        <Link
          href={{
            pathname: `/workspaces/${workspaceId}/activity`,
            query: { cursor: nextCursor, ...(activeAction ? { action: activeAction } : {}) },
          }}
          className="btn-secondary"
        >
          Load older activity
        </Link>
      )}
    </div>
  );
}
