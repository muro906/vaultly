import Link from "next/link";
import { notFound } from "next/navigation";

import VersionDiff from "@/components/VersionDiff";
import { revealVersionAction, rollbackSecretAction } from "@/lib/actions";
import { ApiError } from "@/lib/api";
import { getProject, getSecret, getWorkspace, listSecretVersions } from "@/lib/data";
import { can } from "@/lib/types";

export const metadata = { title: "Secret history · Vaultly" };

export default async function SecretHistoryPage({
  params,
}: {
  params: { secretId: string };
}) {
  let secret;
  try {
    // Metadata only: opening a history page must not count as revealing the
    // value, which is why this does not go through the reveal endpoint.
    secret = await getSecret(params.secretId);
  } catch (error) {
    if (error instanceof ApiError && (error.isNotFound || error.isForbidden)) notFound();
    throw error;
  }

  const [project, versions] = await Promise.all([
    getProject(secret.projectId),
    listSecretVersions(secret.id),
  ]);
  const workspace = await getWorkspace(project.workspaceId);
  const role = workspace.role;

  return (
    <div className="space-y-8">
      <div>
        <nav className="mb-1 text-xs text-slate-500">
          <Link href={`/workspaces/${workspace.id}`} className="hover:text-slate-300">
            {workspace.name}
          </Link>
          {" / "}
          <Link
            href={{ pathname: `/projects/${project.id}`, query: { env: secret.environmentId } }}
            className="hover:text-slate-300"
          >
            {project.name}
          </Link>
        </nav>
        <h1 className="font-mono text-xl font-semibold text-slate-100">{secret.key}</h1>
        <p className="mt-1 text-sm text-slate-400">
          {versions.length} version{versions.length === 1 ? "" : "s"} · currently v
          {secret.currentVersion}
          {secret.description ? ` · ${secret.description}` : ""}
        </p>
      </div>

      <section className="space-y-4">
        <h2 className="text-sm font-medium uppercase tracking-wide text-slate-400">Compare</h2>
        <VersionDiff
          secretId={secret.id}
          versions={versions}
          reveal={revealVersionAction}
          canReveal={can.readSecretValues(role)}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-sm font-medium uppercase tracking-wide text-slate-400">History</h2>

        <ol className="card divide-y divide-surface-border">
          {versions.map((version) => {
            const isCurrent = version.version === secret.currentVersion;
            return (
              <li
                key={version.id}
                className="flex flex-wrap items-center justify-between gap-3 px-4 py-3"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm text-slate-100">v{version.version}</span>
                    {isCurrent && (
                      <span className="badge bg-emerald-950 text-emerald-300">current</span>
                    )}
                  </div>
                  <p className="mt-0.5 text-xs text-slate-500">
                    {version.comment || "no comment"}
                    {version.createdByEmail ? ` · ${version.createdByEmail}` : ""} ·{" "}
                    {new Date(version.createdAt).toLocaleString()}
                  </p>
                </div>

                {!isCurrent && can.writeSecrets(role) && (
                  <form action={rollbackSecretAction}>
                    <input type="hidden" name="secretId" value={secret.id} />
                    <input type="hidden" name="version" value={version.version} />
                    <button type="submit" className="btn-secondary">
                      Restore this version
                    </button>
                  </form>
                )}
              </li>
            );
          })}
        </ol>

        <p className="text-xs text-slate-500">
          Restoring writes the old value as a new version rather than deleting anything, so the
          history stays complete and a restore can itself be undone.
        </p>
      </section>
    </div>
  );
}
