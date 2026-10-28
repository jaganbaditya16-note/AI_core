import type { Metadata } from "next";
import Link from "next/link";
import { Suspense } from "react";

import { HealthPanel } from "@/components/health-panel";
import { getServerEnvSummary } from "@/lib/env";

export const metadata: Metadata = {
  title: "System health",
  description: "Read-only view of frontend and backend health for the AICore foundation.",
};

// Configuration is read per request; nothing here is cached or prerendered.
export const dynamic = "force-dynamic";

export default function HealthPage() {
  const config = getServerEnvSummary();

  return (
    <main className="mx-auto flex min-h-dvh w-full max-w-2xl flex-col gap-6 px-6 py-16">
      <header>
        <Link
          href="/"
          className="font-mono text-xs text-aicore-fg-subtle transition hover:text-aicore-fg focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-aicore-accent"
        >
          ← AICore
        </Link>
        <h1 className="mt-3 text-2xl font-semibold tracking-tight">System health</h1>
        <p className="mt-2 text-sm text-aicore-fg-muted">
          Live result from the backend through the same-origin proxy at{" "}
          <code className="font-mono text-xs">/api/health</code>. No cached or sample values.
        </p>
      </header>

      <section className="rounded-xl border border-aicore-border bg-aicore-surface p-6">
        <h2 className="text-sm font-medium">Frontend configuration</h2>
        <dl className="mt-4 grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[10rem_1fr]">
          <dt className="text-aicore-fg-subtle">API base URL</dt>
          <dd className="font-mono text-xs break-all">{config.apiBaseUrl}</dd>

          <dt className="text-aicore-fg-subtle">Request timeout</dt>
          <dd className="font-mono text-xs">{config.apiTimeoutMs} ms</dd>

          <dt className="text-aicore-fg-subtle">Node environment</dt>
          <dd className="font-mono text-xs">{config.nodeEnv}</dd>
        </dl>
        {config.configError ? (
          <p className="mt-4 rounded-lg border border-aicore-danger/40 bg-aicore-bg p-3 font-mono text-xs text-aicore-danger">
            {config.configError}
          </p>
        ) : null}
      </section>

      <Suspense fallback={<p className="text-sm text-aicore-fg-muted">Loading…</p>}>
        <HealthPanel />
      </Suspense>

      <p className="text-xs text-aicore-fg-subtle">
        Phase 0 exposes only liveness and readiness. Domain endpoints, authentication and the
        control-plane features arrive in later phases.
      </p>
    </main>
  );
}
