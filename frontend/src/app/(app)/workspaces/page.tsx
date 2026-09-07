import Link from "next/link";

import CreateWorkspaceForm from "@/components/CreateWorkspaceForm";
import { listWorkspaces } from "@/lib/data";

export const metadata = { title: "Workspaces · Vaultly" };

export default async function WorkspacesPage() {
  const workspaces = await listWorkspaces();

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Workspaces</h1>
        <p className="mt-1 text-sm text-slate-400">
          Each workspace has its own projects, members and activity log.
        </p>
      </div>

      {workspaces.length === 0 ? (
        <p className="text-sm text-slate-500">You are not a member of any workspace yet.</p>
      ) : (
        <ul className="grid gap-3 sm:grid-cols-2">
          {workspaces.map((workspace) => (
            <li key={workspace.id}>
              <Link
                href={`/workspaces/${workspace.id}`}
                className="card block p-4 transition-colors hover:border-slate-500"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-medium text-slate-100">{workspace.name}</span>
                  <span className="badge bg-slate-800 text-slate-300">{workspace.role}</span>
                </div>
                <p className="mt-1 font-mono text-xs text-slate-500">{workspace.slug}</p>
              </Link>
            </li>
          ))}
        </ul>
      )}

      <CreateWorkspaceForm />
    </div>
  );
}
