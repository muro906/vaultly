import type { Metadata } from "next";

import "./globals.css";

export const metadata: Metadata = {
  title: "Vaultly",
  description: "Encrypted secrets and environment variables for your team.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen">{children}</body>
    </html>
  );
}
