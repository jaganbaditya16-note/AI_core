"use client";

import { useCallback, useState } from "react";

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

type RiskFactor = {
  code: string;
  effect: string;
  level?: string | null;
  steps?: number | null;
  detection_type?: string | null;
  count?: number | null;
};

type RiskDetection = {
  detection_type: string;
  risk_level: string;
  risk_factors: RiskFactor[];
  evidence: Record<string, unknown>;
  fingerprint: string;
};

type RiskCheck = {
  detection_type: string;
  status: string;
  reason?: string | null;
};

type RiskAgentAnalysis = {
  entity_type: string;
  agent_id: string;
  status: string;
  anomaly_state: string;
  risk_level: string;
  risk_factors: RiskFactor[];
  insufficient_reasons: string[];
  baseline_statistics: Record<string, unknown> | null;
  observation: Record<string, unknown>;
  behaviour: {
    baseline_requests: number;
    baseline_active_slots: number;
    baseline_distinct_actions: number;
    observed_distinct_actions: number;
    novel_action_count: number;
    baseline_distinct_resources: number;
    observed_distinct_resources: number;
    novel_resource_count: number;
    baseline_active_hours_utc: number;
    observed_active_hours_utc: number;
    baseline_peak_requests: number;
    observed_peak_requests: number;
  };
  checks: RiskCheck[];
  detections: RiskDetection[];
};

type RiskAnalysisResponse = {
  organization_id: string;
  engine_version: number;
  windows: {
    baseline: string;
    baseline_start: string;
    baseline_end: string;
    observation: string;
    observation_start: string;
    observation_end: string;
    slot_seconds: number;
    slots: number;
  };
  items: RiskAgentAnalysis[];
  limit: number;
  offset: number;
  count: number;
  total: number | null;
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
  requested_focus:
    "Explain the most plausible causes and safe, reversible investigation steps.",
};

function displayLabel(value: string) {
  return value.replaceAll("_", " ");
}

function riskColor(level: string) {
  switch (level.toLowerCase()) {
    case "critical":
    case "high":
      return "border-aicore-warn/50 bg-aicore-warn/10";
    case "medium":
      return "border-aicore-accent/40 bg-aicore-accent/10";
    default:
      return "border-aicore-border bg-aicore-surface-raised";
  }
}

export function IntelligenceConsole() {
  const [riskData, setRiskData] = useState<RiskAnalysisResponse | null>(null);
  const [riskBusy, setRiskBusy] = useState(false);
  const [riskError, setRiskError] = useState<string | null>(null);

  const [advisory, setAdvisory] = useState<Advisory | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadRiskAnalysis = useCallback(async () => {
    try {
      const response = await fetch("/api/risk/analysis", {
        method: "GET",
        cache: "no-store",
        headers: { accept: "application/json" },
      });

      const body = (await response.json()) as
        | RiskAnalysisResponse
        | { error?: string; detail?: string };

      if (!response.ok) {
        const message =
          ("error" in body && body.error) ||
          ("detail" in body && body.detail) ||
          "Risk analysis is unavailable";
        throw new Error(message);
      }

      if (!("items" in body) || !Array.isArray(body.items) || !body.windows) {
        throw new Error("AICore returned an unexpected risk-analysis response");
      }

      setRiskData(body);
    } catch (caught) {
      setRiskError(
        caught instanceof Error
          ? caught.message
          : "Risk analysis is temporarily unavailable",
      );
    } finally {
      setRiskBusy(false);
    }
  }, []);

  const refreshRiskAnalysis = useCallback(() => {
    setRiskBusy(true);
    setRiskError(null);
    void loadRiskAnalysis();
  }, [loadRiskAnalysis]);



  async function investigate() {
    setBusy(true);
    setError(null);
    setAdvisory(null);

    try {
      const advisoryEndpoint =
        process.env.NODE_ENV === "development"
          ? "/api/local-intelligence"
          : "/api/intelligence";

      const response = await fetch(advisoryEndpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(demoIncident),
      });

      const body = (await response.json()) as
        | Advisory
        | { error?: string; detail?: string };

      if (!response.ok) {
        throw new Error(
          ("detail" in body && body.detail) ||
            ("error" in body && body.error) ||
            "Advisory unavailable",
        );
      }

      setAdvisory(body as Advisory);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Advisory unavailable");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <section
        aria-labelledby="risk-analysis-title"
        className="rounded-2xl border border-aicore-border bg-aicore-surface p-6 shadow-2xl shadow-black/20"
      >
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="font-mono text-[11px] tracking-[0.18em] text-aicore-accent uppercase">
              Deterministic engine
            </p>
            <h2 id="risk-analysis-title" className="mt-2 text-xl font-semibold">
              Risk analysis
            </h2>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-aicore-fg-muted">
              Findings come from the AICore API. The engine compares attributed
              action activity across a historical baseline and an observation
              window. Empty results are not treated as proof of safety.
            </p>
          </div>

          <button
            type="button"
            onClick={() => void refreshRiskAnalysis()}
            disabled={riskBusy}
            className="rounded-xl border border-aicore-border px-4 py-2.5 text-sm font-semibold transition hover:opacity-80 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {riskBusy ? (riskData ? "Refreshing..." : "Loading...") : (riskData ? "Refresh risk analysis" : "Load risk analysis")}
          </button>
        </div>

        {riskError && (
          <div
            role="alert"
            className="mt-5 rounded-xl border border-aicore-warn/40 bg-aicore-warn/10 p-4 text-sm text-aicore-fg-muted"
          >
            <strong className="text-aicore-fg">Risk analysis unavailable.</strong>{" "}
            {riskError}
          </div>
        )}

        {riskBusy && !riskData && (
          <p className="mt-6 text-sm text-aicore-fg-muted">
            Loading risk analysis from AICore...
          </p>
        )}

        {riskData && (
          <>
            <div className="mt-6 grid gap-3 sm:grid-cols-3">
              <div className="rounded-xl border border-aicore-border bg-aicore-surface-raised p-4">
                <p className="text-xs text-aicore-fg-subtle">Agents analyzed</p>
                <p className="mt-1 text-2xl font-semibold text-aicore-fg">
                  {riskData.count}
                </p>
              </div>
              <div className="rounded-xl border border-aicore-border bg-aicore-surface-raised p-4">
                <p className="text-xs text-aicore-fg-subtle">Baseline</p>
                <p className="mt-1 text-lg font-semibold text-aicore-fg">
                  {riskData.windows.baseline}
                </p>
                <p className="mt-1 break-words text-xs text-aicore-fg-subtle">
                  {riskData.windows.baseline_start} to{" "}
                  {riskData.windows.baseline_end}
                </p>
              </div>
              <div className="rounded-xl border border-aicore-border bg-aicore-surface-raised p-4">
                <p className="text-xs text-aicore-fg-subtle">Observation</p>
                <p className="mt-1 text-lg font-semibold text-aicore-fg">
                  {riskData.windows.observation}
                </p>
                <p className="mt-1 break-words text-xs text-aicore-fg-subtle">
                  {riskData.windows.observation_start} to{" "}
                  {riskData.windows.observation_end}
                </p>
              </div>
            </div>

            {riskData.items.length === 0 && (
              <div className="mt-5 rounded-xl border border-aicore-border bg-aicore-surface-raised p-5">
                <h3 className="font-semibold text-aicore-fg">
                  No agents returned for this window
                </h3>
                <p className="mt-2 text-sm leading-6 text-aicore-fg-muted">
                  The API returned no agents eligible for analysis in this
                  interval. This is not a finding of zero risk. Check that
                  attributed activity falls inside the observation window and
                  that the agent has enough historical data for the detector.
                </p>
              </div>
            )}

            <div className="mt-5 space-y-4">
              {riskData.items.map((item) => (
                <article
                  key={item.agent_id}
                  className="rounded-xl border border-aicore-border bg-aicore-surface-raised p-5"
                >
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <p className="text-xs text-aicore-fg-subtle">
                        {item.entity_type} agent
                      </p>
                      <h3 className="mt-1 break-all font-mono text-sm text-aicore-fg">
                        {item.agent_id}
                      </h3>
                    </div>
                    <span
                      className={`rounded-lg border px-3 py-1.5 text-xs font-semibold uppercase ${riskColor(item.risk_level)}`}
                    >
                      {displayLabel(item.risk_level)}
                    </span>
                  </div>

                  <div className="mt-4 flex flex-wrap gap-2 text-xs">
                    <span className="rounded-lg border border-aicore-border px-2.5 py-1.5 text-aicore-fg-muted">
                      State: {displayLabel(item.anomaly_state)}
                    </span>
                    <span className="rounded-lg border border-aicore-border px-2.5 py-1.5 text-aicore-fg-muted">
                      Analysis: {displayLabel(item.status)}
                    </span>
                    <span className="rounded-lg border border-aicore-border px-2.5 py-1.5 text-aicore-fg-muted">
                      Detections: {item.detections.length}
                    </span>
                  </div>

                  {item.insufficient_reasons.length > 0 && (
                    <div className="mt-4 rounded-lg border border-aicore-border p-3">
                      <p className="text-sm font-semibold text-aicore-fg">
                        Data limitations
                      </p>
                      <ul className="mt-2 space-y-1 text-sm text-aicore-fg-muted">
                        {item.insufficient_reasons.map((reason, index) => (
                          <li key={`${reason}-${index}`}>
                            {displayLabel(reason)}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {item.detections.length === 0 && (
                    <p className="mt-4 text-sm text-aicore-fg-muted">
                      No detections were returned for this agent. Review the
                      individual checks and any data limitations below.
                    </p>
                  )}

                  {item.detections.map((detection) => (
                    <div
                      key={detection.fingerprint}
                      className="mt-4 rounded-xl border border-aicore-border p-4"
                    >
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <h4 className="font-semibold text-aicore-fg">
                          {displayLabel(detection.detection_type)}
                        </h4>
                        <span
                          className={`rounded-lg border px-2.5 py-1 text-xs font-semibold uppercase ${riskColor(detection.risk_level)}`}
                        >
                          {detection.risk_level}
                        </span>
                      </div>

                      {detection.risk_factors.length > 0 && (
                        <div className="mt-3">
                          <p className="text-xs font-semibold text-aicore-fg-subtle">
                            Risk factors
                          </p>
                          <ul className="mt-2 space-y-1 text-sm text-aicore-fg-muted">
                            {detection.risk_factors.map((factor, index) => (
                              <li key={`${factor.code}-${index}`}>
                                {displayLabel(factor.code)} ({factor.effect})
                                {factor.level ? `: ${factor.level}` : ""}
                                {typeof factor.steps === "number"
                                  ? `, steps ${factor.steps}`
                                  : ""}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                      <details className="mt-4">
                        <summary className="cursor-pointer text-sm font-medium text-aicore-fg">
                          Inspect evidence returned by AICore
                        </summary>
                        <pre className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-aicore-border p-3 text-xs leading-5 text-aicore-fg-muted">
                          {JSON.stringify(detection.evidence, null, 2)}
                        </pre>
                      </details>
                    </div>
                  ))}

                  <details className="mt-4">
                    <summary className="cursor-pointer text-sm font-medium text-aicore-fg">
                      View detector checks
                    </summary>
                    <ul className="mt-3 space-y-2 text-sm text-aicore-fg-muted">
                      {item.checks.map((check, index) => (
                        <li
                          key={`${check.detection_type}-${index}`}
                          className="rounded-lg border border-aicore-border p-3"
                        >
                          <span className="font-medium text-aicore-fg">
                            {displayLabel(check.detection_type)}
                          </span>
                          {" - "}
                          {displayLabel(check.status)}
                          {check.reason
                            ? ` (${displayLabel(check.reason)})`
                            : ""}
                        </li>
                      ))}
                    </ul>
                  </details>
                </article>
              ))}
            </div>

            <p className="mt-5 text-xs leading-5 text-aicore-fg-subtle">
              Engine version {riskData.engine_version}. Analysis is calculated
              for the displayed windows; results are not proof that an agent is
              safe or unsafe outside those windows.
            </p>
          </>
        )}
      </section>

      <section className="rounded-2xl border border-aicore-border bg-aicore-surface p-6 shadow-2xl shadow-black/20">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="font-mono text-[11px] tracking-[0.18em] text-aicore-accent uppercase">
              NVIDIA / Nebius
            </p>
            <h2 className="mt-2 text-xl font-semibold">
              Human-review intelligence
            </h2>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-aicore-fg-muted">
              This separate advisory demonstration uses illustrative sample
              signals. When configured, the optional model can advise on those
              signals; AICore policy and the action firewall remain the
              authority. Sample signals below are not live risk findings.
            </p>
          </div>

          <button
            type="button"
            onClick={investigate}
            disabled={busy}
            className="rounded-xl bg-aicore-accent px-4 py-2.5 text-sm font-semibold text-white transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? "Investigating..." : "Investigate sample incident"}
          </button>
        </div>

        <div className="mt-4 rounded-lg border border-aicore-border px-3 py-2 text-xs text-aicore-fg-subtle">
          Illustrative sample incident - not retrieved from the risk API.
        </div>

        <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {demoIncident.signals.map((signal) => (
            <div
              key={signal.name}
              className="rounded-xl border border-aicore-border bg-aicore-surface-raised p-4"
            >
              <p className="text-xs text-aicore-fg-subtle">
                {displayLabel(signal.name)}
              </p>
              <p className="mt-1 text-sm font-medium text-aicore-fg">
                {signal.value}
              </p>
            </div>
          ))}
        </div>

        {error && (
          <div className="mt-5 rounded-xl border border-aicore-warn/40 bg-aicore-warn/10 p-4 text-sm text-aicore-fg-muted">
            <strong className="text-aicore-fg">Advisory unavailable.</strong>{" "}
            {error}. Keep model credentials only in server-side environments.
          </div>
        )}

        {advisory && (
          <div className="mt-6 grid gap-5 lg:grid-cols-2">
            <div className="rounded-xl border border-aicore-border bg-aicore-surface-raised p-5 lg:col-span-2">
              <div className="flex flex-wrap justify-between gap-2 text-xs text-aicore-fg-subtle">
                <span>{advisory.provider}</span>
                <span>{advisory.model}</span>
              </div>
              <p className="mt-3 text-sm leading-7 text-aicore-fg">
                {advisory.advisory}
              </p>
            </div>

            {[
              { title: "Likely causes", items: advisory.likely_causes },
              { title: "Safe next steps", items: advisory.safe_next_steps },
              {
                title: "Reviewer questions",
                items: advisory.questions_for_reviewer,
              },
            ].map((group) => (
              <div
                key={group.title}
                className="rounded-xl border border-aicore-border bg-aicore-surface-raised p-5"
              >
                <h3 className="text-sm font-semibold">{group.title}</h3>
                <ul className="mt-3 space-y-2 text-sm leading-6 text-aicore-fg-muted">
                  {group.items.map((item, index) => (
                    <li key={`${group.title}-${index}`}>- {item}</li>
                  ))}
                </ul>
              </div>
            ))}

            <p className="text-xs leading-5 text-aicore-fg-subtle lg:col-span-2">
              {advisory.safety_note}
            </p>
          </div>
        )}
      </section>
    </div>
  );
}
