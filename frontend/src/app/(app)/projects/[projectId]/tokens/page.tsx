import Link from "next/link";

import TokenCreateForm from "@/components/TokenCreateForm";
import { revokeTokenAction } from "@/lib/actions";
import { getProject, getWorkspace, listEnvironments, listTokens } from "@/lib/data";

export const metadata = { title: "Access tokens · Vaultly" };

function statusOf(token: {
  revokedAt?: string;
  expiresAt?: string;
}): { label: string; className: string } {
  if (token.revokedAt) return { label: "revoked", className: "bg-red-950 text-red-300" };
  if (token.expiresAt && new Date(token.expiresAt) <= new Date()) {
    return { label: "expired", className: "bg-slate-800 text-slate-400" };
  }
  return { label: "active", className: "bg-emerald-950 text-emerald-300" };
}

export default async function TokensPage({ params }: { params: { projectId: string } }) {
  const project = await getProject(params.projectId);
  const [workspace, environments, tokens] = await Promise.all([
    getWorkspace(project.workspaceId),
    listEnvironments(project.id),
    listTokens(project.id),
  ]);

  const environmentNames = new Map(environments.map((env) => [env.id, env.name]));

  return (
    <div className="space-y-8">
      <div>
        <nav className="mb-1 text-xs text-slate-500">
          <Link href={`/workspaces/${workspace.id}`} className="hover:text-slate-300">
            {workspace.name}
          </Link>
          {" / "}
          <Link href={`/projects/${project.id}`} className="hover:text-slate-300">
            {project.name}
          </Link>
        </nav>
        <h1 className="text-xl font-semibold text-slate-100">Access tokens</h1>
        <p className="mt-1 text-sm text-slate-400">
          Machine credentials for CI/CD. Each is scoped to one environment and can be limited by
          source address and request rate.
        </p>
      </div>

      {tokens.length > 0 && (
        <ul className="card divide-y divide-surface-border">
          {tokens.map((token) => {
            const status = statusOf(token);
            return (
              <li key={token.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-slate-100">{token.name}</span>
                    <span className={`badge ${status.className}`}>{status.label}</span>
                  </div>
                  <p className="mt-1 font-mono text-xs text-slate-500">
                    vlt_{token.prefix}_… · {environmentNames.get(token.environmentId) ?? "unknown"} ·{" "}
                    {token.scopes.join(", ")} · {token.rateLimitRpm}/min
                  </p>
                  <p className="mt-0.5 text-xs text-slate-500">
                    {token.ipAllowlist.length > 0
                      ? `Allowed from ${token.ipAllowlist.join(", ")}`
                      : "Allowed from any address"}
                    {token.lastUsedAt
                      ? ` · last used ${new Date(token.lastUsedAt).toLocaleString()}`
                      : " · never used"}
                  </p>
                </div>

                {!token.revokedAt && (
                  <form action={revokeTokenAction}>
                    <input type="hidden" name="tokenId" value={token.id} />
                    <input type="hidden" name="projectId" value={project.id} />
                    <button type="submit" className="btn-danger">
                      Revoke
                    </button>
                  </form>
                )}
              </li>
            );
          })}
        </ul>
      )}

      <TokenCreateForm projectId={project.id} environments={environments} />
    </div>
  );
}
