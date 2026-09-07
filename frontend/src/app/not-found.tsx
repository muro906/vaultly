import Link from "next/link";

export default function NotFound() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-4 p-6 text-center">
      <h1 className="text-xl font-semibold text-slate-100">Not found</h1>
      <p className="max-w-md text-sm text-slate-400">
        This page does not exist, or you do not have access to it. Vaultly does not distinguish
        between the two, so that nobody can probe for workspaces they cannot see.
      </p>
      <Link href="/workspaces" className="btn-primary">
        Back to your workspaces
      </Link>
    </main>
  );
}
