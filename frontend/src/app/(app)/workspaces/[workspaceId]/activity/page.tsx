import Link from "next/link";
import { Suspense } from "react";

import ActivityFeed from "@/components/ActivityFeed";
import { listAuditActions, listAuditLogs } from "@/lib/data";

export const metadata = { title: "Activity · Vaultly" };

/**
 * The feed is loaded inside Suspense so the page shell and the filter bar
 * render immediately, and only the list waits on the API.
 */
async function Feed({
  workspaceId,
  action,
  cursor,
}: {
  workspaceId: string;
  action?: string;
  cursor?: string;
}) {
  const page = await listAuditLogs(workspaceId, { action, cursor, limit: 30 });
  return (
    <ActivityFeed
      entries={page.entries}
      workspaceId={workspaceId}
      nextCursor={page.nextCursor}
      activeAction={action}
    />
  );
}

function FeedSkeleton() {
  return (
    <ul className="animate-pulse space-y-3" aria-hidden>
      {Array.from({ length: 6 }).map((_, i) => (
        <li key={i} className="h-10 rounded bg-surface-raised" />
      ))}
    </ul>
  );
}

export default async function ActivityPage({
  params,
  searchParams,
}: {
  params: { workspaceId: string };
  searchParams: { action?: string; cursor?: string };
}) {
  const actions = await listAuditActions(params.workspaceId);
  const active = searchParams.action;

  return (
    <div className="space-y-6">
      <div>
        <nav className="mb-1 text-xs text-slate-500">
          <Link href={`/workspaces/${params.workspaceId}`} className="hover:text-slate-300">
            Workspace
          </Link>
        </nav>
        <h1 className="text-xl font-semibold text-slate-100">Activity</h1>
        <p className="mt-1 text-sm text-slate-400">
          Every read and every change, with who did it and from where.
        </p>
      </div>

      {actions.length > 0 && (
        <div className="flex flex-wrap gap-2">
          <Link
            href={`/workspaces/${params.workspaceId}/activity`}
            className={`badge border ${
              active
                ? "border-surface-border text-slate-400"
                : "border-accent bg-accent/20 text-accent-soft"
            }`}
          >
            All
          </Link>
          {actions.map((action) => (
            <Link
              key={action}
              href={{
                pathname: `/workspaces/${params.workspaceId}/activity`,
                query: { action },
              }}
              className={`badge border font-mono ${
                active === action
                  ? "border-accent bg-accent/20 text-accent-soft"
                  : "border-surface-border text-slate-400 hover:text-slate-200"
              }`}
            >
              {action}
            </Link>
          ))}
        </div>
      )}

      <Suspense key={`${active}-${searchParams.cursor}`} fallback={<FeedSkeleton />}>
        <Feed
          workspaceId={params.workspaceId}
          action={active}
          cursor={searchParams.cursor}
        />
      </Suspense>
    </div>
  );
}
