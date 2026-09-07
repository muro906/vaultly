import { redirect } from "next/navigation";

import AuthForm from "@/components/AuthForm";
import { getCurrentUser } from "@/lib/data";

export const metadata = { title: "Sign in · Vaultly" };

export default async function LoginPage() {
  // Someone already signed in has no use for this page.
  if (await getCurrentUser()) redirect("/workspaces");

  return (
    <main className="flex min-h-screen items-center justify-center p-6">
      <AuthForm mode="login" />
    </main>
  );
}
