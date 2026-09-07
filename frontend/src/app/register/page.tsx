import { redirect } from "next/navigation";

import AuthForm from "@/components/AuthForm";
import { getCurrentUser } from "@/lib/data";

export const metadata = { title: "Create an account · Vaultly" };

export default async function RegisterPage() {
  if (await getCurrentUser()) redirect("/workspaces");

  return (
    <main className="flex min-h-screen items-center justify-center p-6">
      <AuthForm mode="register" />
    </main>
  );
}
