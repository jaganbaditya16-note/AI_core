"use client";

import { FormEvent, useState } from "react";

interface Investigation {
  detection_id: string;
  detection_type: string;
  risk_level: string;
  summary: string;
  severity_interpretation: string;
  why_it_matters: string[];
  hypotheses: string[];
  evidence_used: string[];
  checks: string[];
  recommended_containment: string[];
  confidence: string;
  uncertainties: string[];
  do_not_do: string[];
  model: string;
  correlation_id: string | null;
  input_truncated: boolean;
  evidence_digest: string;
  action_taken: false;
}

const sections: Array<[keyof Investigation, string]> = [
  ["why_it_matters", "Why it matters"],
  ["hypotheses", "AI hypotheses"],
  ["evidence_used", "Evidence used"],
  ["checks", "Human verification"],
  ["recommended_containment", "Containment considerations"],
  ["uncertainties", "Uncertainty"],
  ["do_not_do", "Do not do"],
];

export default function InvestigatorPage() {
  const [organizationId, setOrganizationId] = useState("");
  const [detectionId, setDetectionId] = useState("");
  const [token, setToken] = useState("");
  const [result, setResult] = useState<Investigation | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function investigate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch("/api/investigate", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          organization_id: organizationId.trim(),
          detection_id: detectionId.trim(),
        }),
        cache: "no-store",
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data?.detail?.message ?? data?.error ?? "Investigation failed");
      }
      setResult(data as Investigation);
      setToken("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Investigation failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="mx-auto min-h-dvh w-full max-w-6xl px-6 py-12 sm:px-10">
      <header className="max-w-3xl">
        <p className="font-mono text-xs tracking-[0.2em] text-aicore-fg-subtle uppercase">
          Security intelligence · Human in the loop
        </p>
        <h1 className="mt-3 text-4xl font-semibold tracking-tight sm:text-5xl">
          Evidence-to-Decision Investigator
        </h1>
        <p className="mt-4 text-base leading-relaxed text-aicore-fg-muted">
          Deterministic AICore evidence goes to NVIDIA Nemotron through Nebius Token Factory.
          The model explains the evidence; it never receives authority to act.
        </p>
      </header>

      <section className="mt-10 grid gap-4 lg:grid-cols-3">
        {[
          ["01", "FACT", "Recorded anomaly evidence"],
          ["02", "HYPOTHESIS", "Nemotron reasoning"],
          ["03", "DECISION", "Human + AICore controls"],
        ].map(([number, title, text]) => (
          <div key={number} className="rounded-2xl border border-aicore-border bg-aicore-surface p-5">
            <span className="font-mono text-xs text-aicore-fg-subtle">{number}</span>
            <h2 className="mt-3 text-sm font-semibold">{title}</h2>
            <p className="mt-1 text-sm text-aicore-fg-muted">{text}</p>
          </div>
        ))}
      </section>

      <section className="mt-8 rounded-2xl border border-aicore-border bg-aicore-surface p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold">Investigate a recorded detection</h2>
            <p className="mt-1 text-sm text-aicore-fg-muted">
              The bearer token is held only in this browser tab and forwarded to the existing API.
              It is never stored as a public environment variable.
            </p>
          </div>
          <span className="rounded-full border border-aicore-border px-3 py-1 font-mono text-[11px] text-aicore-fg-subtle">
            advisory only
          </span>
        </div>

        <form onSubmit={investigate} className="mt-6 grid gap-4 lg:grid-cols-3">
          <label className="grid gap-2 text-sm">
            <span className="text-aicore-fg-muted">Organization UUID</span>
            <input
              required
              value={organizationId}
              onChange={(event) => setOrganizationId(event.target.value)}
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              className="rounded-xl border border-aicore-border bg-transparent px-3 py-3 font-mono text-xs outline-none focus:border-aicore-accent"
            />
          </label>
          <label className="grid gap-2 text-sm">
            <span className="text-aicore-fg-muted">Detection UUID</span>
            <input
              required
              value={detectionId}
              onChange={(event) => setDetectionId(event.target.value)}
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              className="rounded-xl border border-aicore-border bg-transparent px-3 py-3 font-mono text-xs outline-none focus:border-aicore-accent"
            />
          </label>
          <label className="grid gap-2 text-sm">
            <span className="text-aicore-fg-muted">AICore bearer token</span>
            <input
              required
              type="password"
              autoComplete="off"
              value={token}
              onChange={(event) => setToken(event.target.value)}
              placeholder="••••••••"
              className="rounded-xl border border-aicore-border bg-transparent px-3 py-3 font-mono text-xs outline-none focus:border-aicore-accent"
            />
          </label>
          <button
            type="submit"
            disabled={loading}
            className="rounded-xl bg-aicore-accent px-5 py-3 text-sm font-semibold text-white transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50 lg:col-span-3"
          >
            {loading ? "Investigating with Nemotron…" : "Investigate with Nemotron"}
          </button>
        </form>

        {error ? (
          <div className="mt-5 rounded-xl border border-red-500/30 bg-red-500/5 p-4 text-sm text-red-200" role="alert">
            {error}
          </div>
        ) : null}
      </section>

      {result ? (
        <section className="mt-8 space-y-5">
          <div className="rounded-2xl border border-aicore-border bg-aicore-surface p-6">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="font-mono text-[11px] text-aicore-fg-subtle">RECORDED FINDING</p>
                <h2 className="mt-2 text-2xl font-semibold">{result.summary}</h2>
              </div>
              <div className="flex gap-2 font-mono text-[11px]">
                <span className="rounded-full border border-aicore-border px-3 py-1">{result.detection_type}</span>
                <span className="rounded-full border border-aicore-border px-3 py-1">risk: {result.risk_level}</span>
              </div>
            </div>
            <p className="mt-4 text-sm text-aicore-fg-muted">{result.severity_interpretation}</p>
            <div className="mt-5 flex flex-wrap gap-2 text-[11px] font-mono text-aicore-fg-subtle">
              <span>model: {result.model}</span>
              <span>confidence: {result.confidence}</span>
              <span>bounded: {result.input_truncated ? "yes" : "no"}</span>
              <span>action_taken: false</span>
            </div>
          </div>

          <div className="grid gap-5 lg:grid-cols-2">
            {sections.map(([key, title]) => {
              const values = result[key];
              if (!Array.isArray(values) || values.length === 0) return null;
              return (
                <article key={key} className="rounded-2xl border border-aicore-border bg-aicore-surface p-6">
                  <h3 className="text-sm font-semibold">{title}</h3>
                  <ul className="mt-4 space-y-3 text-sm leading-relaxed text-aicore-fg-muted">
                    {values.map((item) => (
                      <li key={item} className="flex gap-3">
                        <span aria-hidden className="mt-2 size-1.5 shrink-0 rounded-full bg-aicore-accent" />
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </article>
              );
            })}
          </div>

          <div className="rounded-2xl border border-aicore-border bg-aicore-surface p-6">
            <p className="text-sm font-semibold">Provenance & safety</p>
            <dl className="mt-4 grid gap-3 text-xs text-aicore-fg-muted sm:grid-cols-2">
              <div><dt className="text-aicore-fg-subtle">Evidence digest</dt><dd className="mt-1 break-all font-mono">{result.evidence_digest}</dd></div>
              <div><dt className="text-aicore-fg-subtle">Correlation ID</dt><dd className="mt-1 break-all font-mono">{result.correlation_id ?? "not supplied"}</dd></div>
            </dl>
            <p className="mt-5 rounded-xl border border-aicore-border p-4 text-xs leading-relaxed text-aicore-fg-subtle">
              AI advisory only. Verify the recorded evidence before acting. Any real action remains
              behind AICore authentication, authorization, policy and the action firewall.
            </p>
          </div>
        </section>
      ) : null}
    </main>
  );
}
