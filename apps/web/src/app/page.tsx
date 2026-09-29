import Link from "next/link";

import { FadeIn } from "@/components/fade-in";
import { IntelligenceConsole } from "@/components/intelligence-console";
import { fetchHealthReport } from "@/lib/health";
import { appVersion } from "@/lib/service-info";

const capabilities = [
  ["01", "Discover", "Inventory AI assets, models, tools and agents with explicit ownership."],
  ["02", "Control", "Evaluate deterministic RBAC and policy rules before execution."],
  ["03", "Enforce", "Route admitted actions through one firewall boundary."],
  ["04", "Observe", "Audit, measure and baseline agent behaviour without inventing verdicts."],
  ["05", "Investigate", "Use NVIDIA Nemotron through Nebius as a bounded advisory layer for humans."],
];

export default async function Home() {
  const health = await fetchHealthReport();
  const healthy = health.reachable && health.readiness?.status === "ok";

  return (
    <main className="min-h-dvh bg-aicore-bg">
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-10 px-5 py-8 sm:px-8 lg:px-10">
        <FadeIn>
          <header className="flex flex-wrap items-center justify-between gap-4 border-b border-aicore-border pb-6">
            <div>
              <p className="font-mono text-[11px] tracking-[0.2em] text-aicore-accent uppercase">AICore / Control Plane</p>
              <h1 className="mt-2 text-2xl font-semibold tracking-tight sm:text-3xl">AI Security Operations Center</h1>
            </div>
            <div className="flex items-center gap-3 text-xs">
              <span className={`flex items-center gap-2 rounded-full border px-3 py-1.5 ${healthy ? "border-aicore-ok/40 text-aicore-ok" : "border-aicore-warn/40 text-aicore-warn"}`}>
                <span className={`size-1.5 rounded-full ${healthy ? "bg-aicore-ok" : "bg-aicore-warn"}`} />
                {healthy ? "Systems operational" : "Attention required"}
              </span>
              <span className="font-mono text-aicore-fg-subtle">v{appVersion}</span>
            </div>
          </header>
        </FadeIn>

        <FadeIn delay={0.05}>
          <section className="grid gap-8 lg:grid-cols-[1.35fr_0.65fr] lg:items-end">
            <div>
              <p className="font-mono text-xs tracking-[0.16em] text-aicore-fg-subtle uppercase">Deterministic security · advisory intelligence</p>
              <h2 className="mt-4 max-w-4xl text-4xl font-semibold tracking-tight text-balance sm:text-6xl">
                Give every AI action a trail, a policy boundary, and a human-readable reason.
              </h2>
              <p className="mt-5 max-w-2xl text-base leading-7 text-aicore-fg-muted">
                AICore turns AI operations into an inspectable control loop: deterministic policy and
                firewall decisions first, behaviour evidence second, and NVIDIA Nemotron reasoning only
                where a human reviewer needs help understanding the signal.
              </p>
            </div>
            <div className="rounded-2xl border border-aicore-border bg-aicore-surface p-5">
              <p className="text-xs text-aicore-fg-subtle">Architecture invariant</p>
              <p className="mt-3 text-lg font-medium">LLM ≠ security authority</p>
              <p className="mt-2 text-sm leading-6 text-aicore-fg-muted">The model can explain and recommend. It cannot grant permission, approve an action, execute an action, or mutate policy.</p>
            </div>
          </section>
        </FadeIn>

        <FadeIn delay={0.1}>
          <section className="grid gap-px overflow-hidden rounded-2xl border border-aicore-border bg-aicore-border md:grid-cols-5">
            {capabilities.map(([number, title, description]) => (
              <div key={number} className="bg-aicore-surface p-5">
                <p className="font-mono text-[10px] text-aicore-accent">{number}</p>
                <h3 className="mt-5 text-sm font-semibold">{title}</h3>
                <p className="mt-2 text-xs leading-5 text-aicore-fg-muted">{description}</p>
              </div>
            ))}
          </section>
        </FadeIn>

        <FadeIn delay={0.15}>
          <IntelligenceConsole />
        </FadeIn>

        <FadeIn delay={0.2}>
          <section className="grid gap-5 md:grid-cols-3">
            <div className="rounded-2xl border border-aicore-border bg-aicore-surface p-5">
              <p className="text-xs text-aicore-fg-subtle">Backend</p>
              <p className="mt-2 text-lg font-semibold">{health.api?.service ?? "AICore API"}</p>
              <p className="mt-2 text-sm text-aicore-fg-muted">FastAPI · PostgreSQL · OpenAPI · tenant-scoped controls</p>
            </div>
            <div className="rounded-2xl border border-aicore-border bg-aicore-surface p-5">
              <p className="text-xs text-aicore-fg-subtle">Nebius / NVIDIA</p>
              <p className="mt-2 text-lg font-semibold">Token Factory + Nemotron</p>
              <p className="mt-2 text-sm text-aicore-fg-muted">Server-side, bounded advisory inference. Credentials never enter the browser.</p>
            </div>
            <div className="rounded-2xl border border-aicore-border bg-aicore-surface p-5">
              <p className="text-xs text-aicore-fg-subtle">Verification</p>
              <p className="mt-2 text-lg font-semibold">{healthy ? "API ready" : "Check backend"}</p>
              <p className="mt-2 text-sm text-aicore-fg-muted">The page uses the same-origin Next.js BFF to reach the API, avoiding client-side backend credentials.</p>
            </div>
          </section>
        </FadeIn>

        <footer className="flex flex-wrap items-center justify-between gap-4 border-t border-aicore-border pt-6 text-xs text-aicore-fg-subtle">
          <span>AICore · enterprise AI control plane</span>
          <Link href="/health" className="text-aicore-fg-muted hover:text-aicore-fg">Open health details →</Link>
        </footer>
      </div>
    </main>
  );
}
