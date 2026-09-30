"use client";

import { useState } from "react";

type Advisory = {
  provider: string;
  model: string;
  generated_at: string;
  advisory: string;
  likely_causes: string[];
  safe_next_steps: string[];
  questions_for_reviewer: string[];
  safety_note: string;
};

const demoIncident = {
  incident_type: "unusual_action_frequency",
  risk_level: "high",
  affected_agent: "customer-support-agent",
  signals: [
    { name: "five_minute_peak", value: "42 action attempts" },
    { name: "baseline_peak", value: "7 action attempts" },
    { name: "denial_rate", value: "31% in observation window" },
    { name: "novel_resource", value: "billing.export" },
  ],
  requested_focus: "Explain the most plausible causes and safe, reversible investigation steps.",
};

export function IntelligenceConsole() {
  const [advisory, setAdvisory] = useState<Advisory | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function investigate() {
    setBusy(true);
    setError(null);
    setAdvisory(null);
    try {
      const response = await fetch("/api/intelligence", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(demoIncident),
      });
      const body = (await response.json()) as Advisory | { error?: string; detail?: string };
      if (!response.ok) {
        throw new Error(("detail" in body && body.detail) || ("error" in body && body.error) || "Advisory unavailable");
      }
      setAdvisory(body as Advisory);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Advisory unavailable");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="rounded-2xl border border-aicore-border bg-aicore-surface p-6 shadow-2xl shadow-black/20">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="font-mono text-[11px] tracking-[0.18em] text-aicore-accent uppercase">NVIDIA × Nebius</p>
          <h2 className="mt-2 text-xl font-semibold">Human-review intelligence</h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-aicore-fg-muted">
            Deterministic AICore signals are sent as a bounded, sanitized evidence summary to a
            configurable NVIDIA Nemotron model through Nebius Token Factory. The model advises;
            the firewall and policy engine remain the authority.
          </p>
        </div>
        <button
          type="button"
          onClick={investigate}
          disabled={busy}
          className="rounded-xl bg-aicore-accent px-4 py-2.5 text-sm font-semibold text-white transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {busy ? "Investigating…" : "Investigate sample incident"}
        </button>
      </div>

      <div className="mt-6 grid gap-3 sm:grid-cols-4">
        {demoIncident.signals.map((signal) => (
          <div key={signal.name} className="rounded-xl border border-aicore-border bg-aicore-surface-raised p-4">
            <p className="text-xs text-aicore-fg-subtle">{signal.name.replaceAll("_", " ")}</p>
            <p className="mt-1 text-sm font-medium text-aicore-fg">{signal.value}</p>
          </div>
        ))}
      </div>

      {error && (
        <div className="mt-5 rounded-xl border border-aicore-warn/40 bg-aicore-warn/10 p-4 text-sm text-aicore-fg-muted">
          <strong className="text-aicore-fg">Advisory unavailable.</strong> {error}. Add the Nebius
          credentials only to the server environments before using the live call.
        </div>
      )}

      {advisory && (
        <div className="mt-6 grid gap-5 lg:grid-cols-2">
          <div className="rounded-xl border border-aicore-border bg-aicore-surface-raised p-5 lg:col-span-2">
            <div className="flex flex-wrap justify-between gap-2 text-xs text-aicore-fg-subtle">
              <span>{advisory.provider}</span>
              <span>{advisory.model}</span>
            </div>
            <p className="mt-3 text-sm leading-7 text-aicore-fg">{advisory.advisory}</p>
          </div>
          {[
            ["Likely causes", advisory.likely_causes],
            ["Safe next steps", advisory.safe_next_steps],
            ["Reviewer questions", advisory.questions_for_reviewer],
          ].map(([title, items]) => (
            <div key={title as string} className="rounded-xl border border-aicore-border bg-aicore-surface-raised p-5">
              <h3 className="text-sm font-semibold">{title as string}</h3>
              <ul className="mt-3 space-y-2 text-sm leading-6 text-aicore-fg-muted">
                {(items as string[]).map((item) => <li key={item}>• {item}</li>)}
              </ul>
            </div>
          ))}
          <p className="text-xs leading-5 text-aicore-fg-subtle lg:col-span-2">{advisory.safety_note}</p>
        </div>
      )}
    </section>
  );
}
