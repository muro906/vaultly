import { redirect } from "next/navigation";

import { getCurrentUser } from "@/lib/data";

/**
 * The entry point sends a visitor to the right place rather than rendering a
 * marketing page, so a bookmark to the root always lands somewhere useful.
 */
export default async function HomePage() {
  const user = await getCurrentUser();
  redirect(user ? "/workspaces" : "/login");
}
