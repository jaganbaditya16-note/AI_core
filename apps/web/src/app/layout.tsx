import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "AICore — AI Security Operations Center",
    template: "%s · AICore",
  },
  description:
    "A deterministic enterprise AI control plane with policy enforcement, audit, anomaly analysis and bounded NVIDIA Nemotron advisory intelligence through Nebius Token Factory.",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-dvh font-sans antialiased">{children}</body>
    </html>
  );
}
