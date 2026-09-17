import Link from "next/link";
import { FadeIn } from "@/components/fade-in";
import { appVersion, serviceName } from "@/lib/service-info";

const included = [
  "Next.js + TypeScript (App Router) frontend skeleton",
  "FastAPI + Pydantic backend with a health endpoint",
  "PostgreSQL infrastructure and connection foundation",
  "Docker Compose for frontend, backend and database",
  "Pytest, Playwright and CI foundations",
];

const notYetImplemented = [
  "AI inventory, agent/model/tool registries",
  "Identity, permissions, policy, action firewall",
  "Monitoring, audit, anomalies, incidents, kill switch",
  "Nemotron / Nebius Token Factory integration",
];

export default function Home() {
  return (
    <main className="mx-auto flex min-h-dvh w-full max-w-3xl flex-col justify-center gap-10 px-6 py-16">
      <FadeIn>
        <p className="font-mono text-xs tracking-[0.2em] text-aicore-fg-subtle uppercase">
          Phase 0 · Foundation
        </p>
        <h1 className="mt-3 text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
          AICore
        </h1>
        <p className="mt-4 max-w-xl text-base leading-relaxed text-aicore-fg-muted">
          An enterprise AI control plane: discover AI usage, control what it is allowed to do, and
          monitor what it did. This repository currently contains{" "}
          <strong className="font-medium text-aicore-fg">only the foundation</strong> — the
          control-plane features are intentionally not implemented yet.
        </p>
      </FadeIn>

      <FadeIn delay={0.1}>
        <div className="grid gap-4 sm:grid-cols-2">
          <section className="rounded-xl border border-aicore-border bg-aicore-surface p-5">
            <h2 className="text-sm font-medium text-aicore-fg">In this build</h2>
            <ul className="mt-3 space-y-2 text-sm text-aicore-fg-muted">
              {included.map((item) => (
                <li key={item} className="flex gap-2">
                  <span aria-hidden className="mt-2 size-1.5 shrink-0 rounded-full bg-aicore-ok" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </section>

          <section className="rounded-xl border border-aicore-border bg-aicore-surface p-5">
            <h2 className="text-sm font-medium text-aicore-fg">Not implemented yet</h2>
            <ul className="mt-3 space-y-2 text-sm text-aicore-fg-subtle">
              {notYetImplemented.map((item) => (
                <li key={item} className="flex gap-2">
                  <span aria-hidden className="mt-2 size-1.5 shrink-0 rounded-full bg-aicore-border" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </section>
        </div>
      </FadeIn>

      <FadeIn delay={0.2}>
        <div className="flex flex-wrap items-center gap-4 text-sm">
          <Link
            href="/health"
            className="rounded-lg bg-aicore-accent px-4 py-2 font-medium text-white transition hover:opacity-90 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-aicore-accent"
          >
            Open system health
          </Link>
          <span className="font-mono text-xs text-aicore-fg-subtle">
            {serviceName} · v{appVersion}
          </span>
        </div>
      </FadeIn>
    </main>
  );
}
