import Link from "next/link";
import { notFound } from "next/navigation";

import CreateProjectForm from "@/components/CreateProjectForm";
import { ApiError } from "@/lib/api";
import { getWorkspace, listProjects } from "@/lib/data";
import { can } from "@/lib/types";

export default async function WorkspacePage({
  params,
}: {
  params: { workspaceId: string };
}) {
  let workspace;
  try {
    workspace = await getWorkspace(params.workspaceId);
  } catch (error) {
    // The API returns 404 both for a workspace that does not exist and for one
    // the caller cannot see, so this page cannot tell them apart either.
    if (error instanceof ApiError && (error.isNotFound || error.isForbidden)) notFound();
    throw error;
  }

  const projects = await listProjects(workspace.id);

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <nav className="mb-1 text-xs text-slate-500">
            <Link href="/workspaces" className="hover:text-slate-300">
              Workspaces
            </Link>
          </nav>
          <h1 className="text-xl font-semibold text-slate-100">{workspace.name}</h1>
          <p className="mt-1 text-sm text-slate-400">
            You are {workspace.role === "owner" ? "an" : "a"} {workspace.role} here.
          </p>
        </div>

        <div className="flex gap-2">
          <Link href={`/workspaces/${workspace.id}/activity`} className="btn-secondary">
            Activity
          </Link>
          <Link href={`/workspaces/${workspace.id}/members`} className="btn-secondary">
            Members
          </Link>
        </div>
      </div>

      <section className="space-y-4">
        <h2 className="text-sm font-medium uppercase tracking-wide text-slate-400">Projects</h2>

        {projects.length === 0 ? (
          <p className="text-sm text-slate-500">No projects yet.</p>
        ) : (
          <ul className="grid gap-3 sm:grid-cols-2">
            {projects.map((project) => (
              <li key={project.id}>
                <Link
                  href={`/projects/${project.id}`}
                  className="card block p-4 transition-colors hover:border-slate-500"
                >
                  <span className="font-medium text-slate-100">{project.name}</span>
                  <p className="mt-1 text-xs text-slate-500">
                    {project.description || <span className="font-mono">{project.slug}</span>}
                  </p>
                </Link>
              </li>
            ))}
          </ul>
        )}

        {can.writeSecrets(workspace.role) && <CreateProjectForm workspaceId={workspace.id} />}
      </section>
    </div>
  );
}
