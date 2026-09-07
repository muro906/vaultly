import Link from "next/link";
import { redirect } from "next/navigation";

import { logoutAction } from "@/lib/actions";
import { getCurrentUser } from "@/lib/data";

/**
 * The shell for every signed-in page.
 *
 * The session check happens here, in a Server Component, rather than in
 * middleware: it runs on the server for every route in this group, and it
 * verifies the session against the API instead of merely noticing that a
 * cookie exists.
 */
export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const user = await getCurrentUser();
  if (!user) redirect("/login");

  return (
    <div className="min-h-screen">
      <header className="border-b border-surface-border bg-surface-raised">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-6 py-3">
          <Link href="/workspaces" className="flex items-center gap-2 font-semibold text-slate-100">
            <span aria-hidden className="text-lg">🔐</span>
            Vaultly
          </Link>

          <div className="flex items-center gap-4 text-sm">
            <span className="hidden text-slate-400 sm:inline">{user.email}</span>
            <form action={logoutAction}>
              <button type="submit" className="text-slate-400 hover:text-slate-200">
                Sign out
              </button>
            </form>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-8">{children}</main>
    </div>
  );
}
