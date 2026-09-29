import Link from "next/link";
import { FadeIn } from "@/components/fade-in";
import { appVersion, serviceName } from "@/lib/service-info";

const layers = [
  ["CONTROL", "Identity · RBAC · policy · action firewall"],
  ["OBSERVE", "Audit · monitoring · deterministic anomaly detection"],
  ["INVESTIGATE", "NVIDIA Nemotron via Nebius Token Factory · human review"],
];

const guarantees = [
  "The model is advisory — never the authorization authority.",
  "Tenant-scoped evidence; raw payloads and credentials stay out of inference.",
  "Missing Nebius credentials fail honestly; no fake AI responses.",
  "Execution remains behind the existing deterministic firewall.",
];

export default function Home() {
  return (
    <main className="mx-auto flex min-h-dvh w-full max-w-6xl flex-col gap-12 px-6 py-12 sm:px-10 lg:py-16">
      <FadeIn>
        <div className="flex items-center justify-between gap-4">
          <p className="font-mono text-xs tracking-[0.22em] text-aicore-fg-subtle uppercase">
            AICore · Security Intelligence
          </p>
          <span className="rounded-full border border-aicore-border px-3 py-1 font-mono text-[11px] text-aicore-fg-subtle">
            {serviceName} · v{appVersion}
          </span>
        </div>
        <h1 className="mt-5 max-w-4xl text-4xl font-semibold tracking-tight text-balance sm:text-6xl">
          AI security decisions stay deterministic. Intelligence stays human-controlled.
        </h1>
        <p className="mt-5 max-w-3xl text-base leading-7 text-aicore-fg-muted sm:text-lg">
          AICore turns AI activity into bounded, explainable security findings, then uses
          NVIDIA Nemotron on Nebius Token Factory to help a reviewer understand what changed —
          without giving the model permission to execute or approve anything.
        </p>
        <div className="mt-7 flex flex-wrap gap-3">
          <Link
            href="/operations"
            className="inline-flex items-center rounded-lg bg-aicore-accent px-4 py-2.5 text-sm font-medium text-white transition hover:opacity-90 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-aicore-accent"
          >
            Open security operations
          </Link>
          <Link
            href="/health"
            className="inline-flex items-center rounded-lg border border-aicore-border px-4 py-2.5 text-sm font-medium text-aicore-fg-muted transition hover:bg-aicore-surface focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-aicore-accent"
          >
            Check system health
          </Link>
        </div>
      </FadeIn>

      <FadeIn delay={0.08}>
        <section className="grid gap-3 md:grid-cols-3">
          {layers.map(([title, text]) => (
            <div key={title} className="rounded-2xl border border-aicore-border bg-aicore-surface p-5">
              <p className="font-mono text-[11px] tracking-[0.18em] text-aicore-fg-subtle">{title}</p>
              <p className="mt-3 text-sm leading-6 text-aicore-fg-muted">{text}</p>
            </div>
          ))}
        </section>
      </FadeIn>

      <FadeIn delay={0.14}>
        <section className="rounded-2xl border border-aicore-border bg-aicore-surface p-6 sm:p-8">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <p className="font-mono text-xs tracking-[0.18em] text-aicore-fg-subtle">THE SAFETY BOUNDARY</p>
              <h2 className="mt-2 text-2xl font-semibold">Detect → explain → review</h2>
              <p className="mt-3 max-w-2xl text-sm leading-6 text-aicore-fg-muted">
                Phase 10 establishes the deterministic finding. The intelligence layer receives
                only server-generated evidence. A reviewer receives hypotheses, uncertainty and
                questions — never an autonomous action.
              </p>
            </div>
            <Link
              href="/operations"
              className="inline-flex w-fit rounded-lg border border-aicore-border px-4 py-2.5 text-sm font-medium text-aicore-fg-muted transition hover:bg-aicore-surface focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-aicore-accent"
            >
              View investigation workflow
            </Link>
          </div>
        </section>
      </FadeIn>

      <FadeIn delay={0.2}>
        <section className="grid gap-6 md:grid-cols-2">
          <div className="rounded-2xl border border-aicore-border bg-aicore-surface p-6">
            <h2 className="text-sm font-medium">Enterprise guarantees</h2>
            <ul className="mt-4 space-y-3 text-sm leading-6 text-aicore-fg-muted">
              {guarantees.map((item) => (
                <li key={item} className="flex gap-3">
                  <span aria-hidden className="mt-2 size-1.5 shrink-0 rounded-full bg-aicore-ok" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
          <div className="rounded-2xl border border-aicore-border bg-aicore-surface p-6">
            <h2 className="text-sm font-medium">Live inference configuration</h2>
            <p className="mt-4 text-sm leading-6 text-aicore-fg-muted">
              The API expects a server-side <code className="font-mono">AICORE_NEBIUS_API_KEY</code>.
              It defaults to NVIDIA Nemotron 3 Super through Nebius Token Factory. The browser
              never receives this secret.
            </p>
            <p className="mt-4 font-mono text-xs text-aicore-fg-subtle">
              POST /organizations/:id/risk/detections/:id/investigate
            </p>
          </div>
        </section>
      </FadeIn>
    </main>
  );
}
