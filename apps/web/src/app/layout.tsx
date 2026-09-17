import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "AICore — Enterprise AI Control Plane",
    template: "%s · AICore",
  },
  description:
    "AICore is an enterprise AI control plane. This build is the Phase 0 foundation: application skeleton, health checks, PostgreSQL infrastructure and tests — no control-plane features yet.",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-dvh font-sans antialiased">{children}</body>
    </html>
  );
}
