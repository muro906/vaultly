import Link from "next/link";
import { notFound } from "next/navigation";

import PromotionPanel from "@/components/PromotionPanel";
import SecretRow from "@/components/SecretRow";
import { CreateSecretForm } from "@/components/SecretForms";
import { ApiError } from "@/lib/api";
import { getProject, getWorkspace, listEnvironments, listSecrets } from "@/lib/data";
import { can } from "@/lib/types";

export default async function ProjectPage({
  params,
  searchParams,
}: {
  params: { projectId: string };
  searchParams: { env?: string };
}) {
  let project;
  try {
    project = await getProject(params.projectId);
  } catch (error) {
    if (error instanceof ApiError && (error.isNotFound || error.isForbidden)) notFound();
    throw error;
  }

  const [workspace, environments] = await Promise.all([
    getWorkspace(project.workspaceId),
    listEnvironments(project.id),
  ]);

  // Defaults to the first environment on the promotion path, which is where
  // work normally starts.
  const selected =
    environments.find((env) => env.id === searchParams.env) ?? environments[0];

  const secrets = selected ? await listSecrets(selected.id) : [];
  const role = workspace.role;

  return (
    <div className="space-y-8">
      <div>
        <nav className="mb-1 text-xs text-slate-500">
          <Link href={`/workspaces/${workspace.id}`} className="hover:text-slate-300">
            {workspace.name}
          </Link>
        </nav>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-xl font-semibold text-slate-100">{project.name}</h1>
            {project.description && (
              <p className="mt-1 text-sm text-slate-400">{project.description}</p>
            )}
          </div>
          {can.manageTokens(role) && (
            <Link href={`/projects/${project.id}/tokens`} className="btn-secondary">
              Access tokens
            </Link>
          )}
        </div>
      </div>

      {/* Environment tabs, in promotion order. */}
      <nav className="flex flex-wrap gap-2 border-b border-surface-border pb-2">
        {environments.map((env) => {
          const active = env.id === selected?.id;
          return (
            <Link
              key={env.id}
              href={{ pathname: `/projects/${project.id}`, query: { env: env.id } }}
              className={`rounded-md px-3 py-1.5 text-sm transition-colors ${
                active
                  ? "bg-accent/20 text-accent-soft"
                  : "text-slate-400 hover:bg-surface-raised hover:text-slate-200"
              }`}
            >
              {env.name}
              {typeof env.secretCount === "number" && (
                <span className="ml-2 text-xs text-slate-500">{env.secretCount}</span>
              )}
            </Link>
          );
        })}
      </nav>

      {selected && (
        <section className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-sm font-medium uppercase tracking-wide text-slate-400">
              {selected.name} secrets
            </h2>
            {can.writeSecrets(role) && (
              <CreateSecretForm environmentId={selected.id} projectId={project.id} />
            )}
          </div>

          {secrets.length === 0 ? (
            <p className="text-sm text-slate-500">No secrets in {selected.name} yet.</p>
          ) : (
            <ul className="card divide-y divide-surface-border">
              {secrets.map((secret) => (
                <SecretRow
                  key={secret.id}
                  secret={secret}
                  projectId={project.id}
                  canReveal={can.readSecretValues(role)}
                  canWrite={can.writeSecrets(role)}
                />
              ))}
            </ul>
          )}

          {!can.readSecretValues(role) && (
            <p className="text-xs text-slate-500">
              As a viewer you can see which secrets exist and how they have changed, but not their
              values.
            </p>
          )}
        </section>
      )}

      {can.writeSecrets(role) && environments.length > 1 && (
        <PromotionPanel projectId={project.id} environments={environments} />
      )}
    </div>
  );
}
