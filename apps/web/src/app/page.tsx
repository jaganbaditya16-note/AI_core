import Link from "next/link";
import { FadeIn } from "@/components/fade-in";
import { appVersion, serviceName } from "@/lib/service-info";

const pillars = [
  ["01", "DETECT", "Deterministic anomaly detection and bounded evidence."],
  ["02", "INVESTIGATE", "NVIDIA Nemotron on Nebius Token Factory turns evidence into hypotheses and verification checks."],
  ["03", "DECIDE", "Humans and AICore authorization, policy and firewall controls remain authoritative."],
];

export default function Home() {
  return (
    <main className="mx-auto flex min-h-dvh w-full max-w-6xl flex-col justify-center gap-10 px-6 py-16 sm:px-10">
      <FadeIn>
        <p className="font-mono text-xs tracking-[0.2em] text-aicore-fg-subtle uppercase">
          AICore · AI security control plane
        </p>
        <h1 className="mt-3 max-w-4xl text-4xl font-semibold tracking-tight text-balance sm:text-6xl">
          Detect the anomaly. Understand the evidence. Keep the decision human.
        </h1>
        <p className="mt-5 max-w-2xl text-base leading-relaxed text-aicore-fg-muted sm:text-lg">
          AICore connects deterministic AI-agent risk detection with a bounded NVIDIA Nemotron
          investigation workflow on Nebius Token Factory — without giving the model authority to act.
        </p>
      </FadeIn>

      <FadeIn delay={0.1}>
        <div className="grid gap-4 md:grid-cols-3">
          {pillars.map(([number, title, text]) => (
            <section key={number} className="rounded-2xl border border-aicore-border bg-aicore-surface p-5">
              <span className="font-mono text-xs text-aicore-fg-subtle">{number}</span>
              <h2 className="mt-3 text-sm font-semibold">{title}</h2>
              <p className="mt-2 text-sm leading-relaxed text-aicore-fg-muted">{text}</p>
            </section>
          ))}
        </div>
      </FadeIn>

      <FadeIn delay={0.2}>
        <div className="flex flex-wrap items-center gap-4">
          <Link
            href="/investigator"
            className="rounded-xl bg-aicore-accent px-5 py-3 text-sm font-semibold text-white transition hover:opacity-90 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-aicore-accent"
          >
            Open Investigator
          </Link>
          <Link
            href="/health"
            className="rounded-xl border border-aicore-border px-5 py-3 text-sm font-medium transition hover:bg-aicore-surface"
          >
            System health
          </Link>
          <span className="font-mono text-xs text-aicore-fg-subtle">
            {serviceName} · v{appVersion}
          </span>
        </div>
      </FadeIn>

      <FadeIn delay={0.3}>
        <div className="rounded-2xl border border-aicore-border bg-aicore-surface p-6">
          <p className="font-mono text-[11px] tracking-[0.18em] text-aicore-fg-subtle uppercase">
            Trust boundary
          </p>
          <p className="mt-3 text-lg font-medium">
            Nemotron investigates. AICore decides.
          </p>
          <p className="mt-2 max-w-3xl text-sm leading-relaxed text-aicore-fg-muted">
            Model output is advisory, bounded, schema-validated and isolated from the action
            execution path. The existing security controls remain the final authority.
          </p>
        </div>
      </FadeIn>
    </main>
  );
}
