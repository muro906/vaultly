import Link from "next/link";

import AddMemberForm from "@/components/AddMemberForm";
import { getWorkspace, listMembers } from "@/lib/data";
import { can } from "@/lib/types";

export const metadata = { title: "Members · Vaultly" };

/** What each role may do, shown so the choice in the form is an informed one. */
const ROLE_SUMMARY: Record<string, string> = {
  owner: "Full control, including deleting the workspace.",
  admin: "Manages members and access tokens.",
  member: "Reads and writes secret values.",
  viewer: "Sees which secrets exist and how they changed, but never their values.",
};

export default async function MembersPage({ params }: { params: { workspaceId: string } }) {
  const workspace = await getWorkspace(params.workspaceId);
  const members = await listMembers(params.workspaceId);

  return (
    <div className="space-y-6">
      <div>
        <nav className="mb-1 text-xs text-slate-500">
          <Link href={`/workspaces/${workspace.id}`} className="hover:text-slate-300">
            {workspace.name}
          </Link>
        </nav>
        <h1 className="text-xl font-semibold text-slate-100">Members</h1>
      </div>

      <ul className="card divide-y divide-surface-border">
        {members.map((member) => (
          <li key={member.userId} className="flex items-center justify-between gap-4 px-4 py-3">
            <div>
              <p className="text-sm text-slate-100">{member.name}</p>
              <p className="text-xs text-slate-500">{member.email}</p>
            </div>
            <div className="text-right">
              <span className="badge bg-slate-800 text-slate-300">{member.role}</span>
              <p className="mt-1 max-w-xs text-xs text-slate-500">{ROLE_SUMMARY[member.role]}</p>
            </div>
          </li>
        ))}
      </ul>

      {can.manageMembers(workspace.role) && <AddMemberForm workspaceId={workspace.id} />}
    </div>
  );
}
