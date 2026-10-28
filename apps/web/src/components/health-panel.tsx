"use client";

import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { useCallback, useEffect, useState } from "react";

import type { HealthReport } from "@aicore/types";

type Phase = "loading" | "ok" | "degraded" | "unreachable" | "config-error";

interface State {
  phase: Phase;
  report: HealthReport | null;
}

const INITIAL_STATE: State = { phase: "loading", report: null };

function classify(report: HealthReport): Phase {
  if (!report.reachable) return "unreachable";
  const readinessOk = report.readiness?.status === "ok";
  return readinessOk ? "ok" : "degraded";
}

/**
 * Perform one health check against the same-origin proxy.
 *
 * Pure with respect to React state: it resolves to the next state instead of
 * calling setState, so it is safe to invoke from an effect or an event handler.
 */
async function loadHealth(): Promise<State> {
  try {
    const response = await fetch("/api/health", {
      cache: "no-store",
      headers: { accept: "application/json" },
    });

    if (response.status === 503) {
      const body = (await response.json().catch(() => null)) as HealthReport | null;
      if (body === null) return { phase: "unreachable", report: null };

      const isConfigError = body.errors.some((entry) => entry.startsWith("configuration:"));
      return { phase: isConfigError ? "config-error" : classify(body), report: body };
    }

    if (!response.ok) return { phase: "unreachable", report: null };

    const body = (await response.json()) as HealthReport;
    return { phase: classify(body), report: body };
  } catch {
    // The proxy itself could not be reached (offline, frontend restarting).
    return { phase: "unreachable", report: null };
  }
}

const phaseMeta: Record<Phase, { label: string; tone: string; dot: string }> = {
  loading: { label: "Checking…", tone: "text-aicore-fg-muted", dot: "bg-aicore-fg-subtle" },
  ok: { label: "Operational", tone: "text-aicore-ok", dot: "bg-aicore-ok" },
  degraded: {
    label: "Reachable, dependency degraded",
    tone: "text-aicore-warn",
    dot: "bg-aicore-warn",
  },
  unreachable: { label: "Backend unreachable", tone: "text-aicore-danger", dot: "bg-aicore-danger" },
  "config-error": {
    label: "Frontend misconfigured",
    tone: "text-aicore-danger",
    dot: "bg-aicore-danger",
  },
};

export function HealthPanel() {
  const [state, setState] = useState<State>(INITIAL_STATE);
  const reduceMotion = useReducedMotion();
  const isLoading = state.phase === "loading";

  useEffect(() => {
    let cancelled = false;

    void loadHealth().then((next) => {
      if (!cancelled) setState(next);
    });

    return () => {
      cancelled = true;
    };
  }, []);

  const refresh = useCallback(async () => {
    setState((previous) => ({ ...previous, phase: "loading" }));
    setState(await loadHealth());
  }, []);

  const meta = phaseMeta[state.phase];
  const report = state.report;

  return (
    <section aria-live="polite" className="rounded-xl border border-aicore-border bg-aicore-surface p-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <motion.span
            aria-hidden
            className={`size-2.5 rounded-full ${meta.dot}`}
            animate={reduceMotion || !isLoading ? { scale: 1 } : { scale: [1, 0.6, 1] }}
            transition={{ duration: 1.1, repeat: Infinity, ease: "easeInOut" }}
          />
          <div>
            <p className="text-sm font-medium">Backend status</p>
            <p className={`text-sm ${meta.tone}`}>{meta.label}</p>
          </div>
        </div>

        <button
          type="button"
          onClick={() => void refresh()}
          disabled={isLoading}
          className="rounded-lg border border-aicore-border bg-aicore-surface-raised px-3 py-1.5 text-sm text-aicore-fg transition hover:border-aicore-fg-subtle focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-aicore-accent disabled:cursor-not-allowed disabled:opacity-50"
        >
          {isLoading ? "Checking…" : "Check again"}
        </button>
      </div>

      <AnimatePresence mode="wait" initial={false}>
        <motion.div
          key={state.phase}
          initial={reduceMotion ? false : { opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          exit={reduceMotion ? undefined : { opacity: 0, y: -6 }}
          transition={{ duration: 0.18 }}
          className="mt-6"
        >
          <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[10rem_1fr]">
            <dt className="text-aicore-fg-subtle">API service</dt>
            <dd className="font-mono text-xs">
              {report?.api
                ? `${report.api.service} · v${report.api.version} · ${report.api.environment}`
                : "—"}
            </dd>

            <dt className="text-aicore-fg-subtle">Checked at</dt>
            <dd className="font-mono text-xs">{report?.checkedAt ?? "—"}</dd>
          </dl>

          {report?.readiness ? (
            <ul className="mt-4 space-y-2">
              {report.readiness.checks.map((result) => (
                <li key={result.name} className="flex items-start gap-2 text-sm">
                  <span
                    aria-hidden
                    className={`mt-1.5 size-1.5 shrink-0 rounded-full ${
                      result.status === "ok" ? "bg-aicore-ok" : "bg-aicore-danger"
                    }`}
                  />
                  <span className="text-aicore-fg-muted">
                    <span className="font-mono text-xs text-aicore-fg">{result.name}</span>
                    {result.detail ? ` — ${result.detail}` : null}
                  </span>
                </li>
              ))}
            </ul>
          ) : null}

          {report && report.errors.length > 0 ? (
            <ul className="mt-4 space-y-1 rounded-lg border border-aicore-border bg-aicore-bg p-3 font-mono text-xs text-aicore-danger">
              {report.errors.map((entry) => (
                <li key={entry}>{entry}</li>
              ))}
            </ul>
          ) : null}
        </motion.div>
      </AnimatePresence>
    </section>
  );
}
