"use client";

import { useEffect, useMemo, useState } from "react";

const incidents = [
  { id: "INC-1042", title: "Agent privilege burst", severity: "CRITICAL", status: "INVESTIGATING", signal: "4.8× unusual action frequency", time: "2 min ago" },
  { id: "INC-1041", title: "Novel production resource", severity: "HIGH", status: "ACKNOWLEDGED", signal: "New resource observed", time: "18 min ago" },
  { id: "INC-1039", title: "Repeated policy denials", severity: "MEDIUM", status: "CONTAINED", signal: "17 denied requests", time: "42 min ago" },
] as const;

const approvals = [
  { id: "APR-0081", action: "agent.posture_check", target: "prod-agent-7", requester: "Analyst", expires: "58 min" },
  { id: "APR-0079", action: "agent.posture_check", target: "staging-agent-2", requester: "Operator", expires: "21 min" },
] as const;

type Connection = {
  connected: boolean;
  reachable: boolean;
  liveness?: { status: number | null; latencyMs: number | null };
  readiness?: { status: number | null; latencyMs: number | null };
  openapi?: { status: number | null; latencyMs: number | null };
  error?: string;
};

export default function OperationsPage() {
  const [selectedId, setSelectedId] = useState<(typeof incidents)[number]["id"]>(incidents[0].id);
  const [tab, setTab] = useState<"overview" | "approvals">("overview");
  const [connection, setConnection] = useState<Connection | null>(null);
  const selected = incidents.find((incident) => incident.id === selectedId) ?? incidents[0];
  const selectedEvidence = useMemo(() => ["action_rate_spike", "unusual_frequency", "policy_denial_burst"], []);

  useEffect(() => {
    let cancelled = false;
    const checkConnection = async () => {
      try {
        const response = await fetch("/api/connection", { cache: "no-store" });
        const body = (await response.json()) as { backend?: Connection };
        if (!cancelled) setConnection(body.backend ?? { connected: false, reachable: false });
      } catch {
        if (!cancelled) setConnection({ connected: false, reachable: false, error: "Frontend proxy unavailable" });
      }
    };
    void checkConnection();
    const timer = window.setInterval(checkConnection, 30_000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  const connectionLabel = connection?.connected ? "Backend connected" : connection ? "Backend unavailable" : "Checking backend";
  const connectionClass = connection?.connected ? "text-emerald-300" : connection ? "text-amber-300" : "text-slate-400";

  return (
    <main className="min-h-screen bg-[#070b14] text-white">
      <div className="mx-auto max-w-[1500px] px-6 py-7 lg:px-10">
        <header className="mb-8 flex flex-col gap-5 md:flex-row md:items-center md:justify-between">
          <div>
            <div className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.25em] text-cyan-300"><span className="h-2 w-2 rounded-full bg-cyan-300 shadow-[0_0_18px_#22d3ee]"/>AICore Security Operations</div>
            <h1 className="text-3xl font-semibold tracking-tight md:text-4xl">Proof-Bound AI Security</h1>
            <p className="mt-2 max-w-3xl text-sm text-slate-400">Deterministic controls detect and enforce. NVIDIA Nemotron investigates bounded evidence. Humans approve consequential actions.</p>
          </div>
          <div className="rounded-2xl border border-emerald-400/20 bg-emerald-400/5 px-4 py-3 text-right">
            <div className="text-xs text-emerald-300">CONTROL PLANE</div>
            <div className={`mt-1 text-sm font-semibold ${connectionClass}`}>{connectionLabel}</div>
            <div className="mt-1 text-[11px] text-slate-500">Secrets remain server-side</div>
          </div>
        </header>

        <section className="grid gap-4 md:grid-cols-4">
          {[['3','Open incidents'],['1','Critical signal'],['2','Pending approvals'],['100%','AI advisory only']].map(([value,label]) => <div key={label} className="rounded-2xl border border-white/10 bg-white/[0.035] p-5 shadow-2xl shadow-black/20"><div className="text-2xl font-semibold">{value}</div><div className="mt-1 text-xs uppercase tracking-wider text-slate-500">{label}</div></div>)}
        </section>

        {connection && (
          <section className="mt-5 rounded-2xl border border-white/10 bg-white/[0.025] px-4 py-3 text-xs text-slate-400">
            <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
              <span className={connection.connected ? "text-emerald-300" : "text-amber-300"}>● {connectionLabel}</span>
              <span>API liveness: {connection.liveness?.status ?? "—"}</span>
              <span>Readiness: {connection.readiness?.status ?? "—"}</span>
              <span>OpenAPI: {connection.openapi?.status ?? "—"}</span>
              {connection.liveness?.latencyMs != null && <span>API latency: {connection.liveness.latencyMs} ms</span>}
              {connection.error && <span className="text-amber-300">{connection.error}</span>}
            </div>
          </section>
        )}

        <div className="mt-8 flex gap-2 border-b border-white/10"><button onClick={() => setTab('overview')} className={`px-4 py-3 text-sm ${tab==='overview'?'border-b-2 border-cyan-300 text-white':'text-slate-500'}`}>Detection & Investigation</button><button onClick={() => setTab('approvals')} className={`px-4 py-3 text-sm ${tab==='approvals'?'border-b-2 border-cyan-300 text-white':'text-slate-500'}`}>Human Approval Queue</button></div>

        {tab === 'overview' ? <div className="mt-6 grid gap-6 lg:grid-cols-[420px_1fr]">
          <section className="rounded-3xl border border-white/10 bg-white/[0.035] p-4">
            <div className="mb-3 flex items-center justify-between"><h2 className="font-semibold">Active incidents</h2><span className="rounded-full bg-white/10 px-2 py-1 text-[10px] text-slate-400">LIVE VIEW</span></div>
            <div className="space-y-2">{incidents.map(item => <button key={item.id} onClick={() => setSelectedId(item.id)} className={`w-full rounded-2xl border p-4 text-left transition ${selected.id===item.id?'border-cyan-300/40 bg-cyan-300/[0.07]':'border-white/5 bg-black/10 hover:border-white/15'}`}><div className="flex items-center justify-between gap-3"><span className="text-xs text-slate-500">{item.id}</span><span className="text-[10px] font-bold text-amber-300">{item.severity}</span></div><div className="mt-2 font-medium">{item.title}</div><div className="mt-1 text-xs text-slate-500">{item.signal} · {item.time}</div></button>)}</div>
          </section>

          <section className="rounded-3xl border border-white/10 bg-white/[0.035] p-6">
            <div className="flex flex-col justify-between gap-5 md:flex-row"><div><div className="text-xs text-slate-500">{selected.id} · {selected.status}</div><h2 className="mt-1 text-2xl font-semibold">{selected.title}</h2><p className="mt-2 text-sm text-slate-400">A deterministic detector identified a behavior outside the agent&apos;s historical profile.</p></div><button className="h-fit rounded-xl bg-cyan-300 px-4 py-2 text-sm font-semibold text-slate-950 shadow-lg shadow-cyan-300/10">Investigate with Nemotron</button></div>
            <div className="mt-7 grid gap-4 md:grid-cols-3">{[['Signal','4.8×','frequency deviation'],['Evidence','3','bounded references'],['Risk','Critical','deterministic finding']].map(([a,b,c])=><div key={a} className="rounded-2xl border border-white/8 bg-black/15 p-4"><div className="text-xs text-slate-500">{a}</div><div className="mt-2 text-xl font-semibold">{b}</div><div className="mt-1 text-xs text-slate-500">{c}</div></div>)}</div>
            <div className="mt-6 rounded-2xl border border-violet-400/20 bg-violet-400/[0.045] p-5"><div className="flex items-center justify-between"><h3 className="font-semibold">NVIDIA Nemotron investigation</h3><span className="rounded-full border border-violet-300/20 px-2 py-1 text-[10px] text-violet-200">ADVISORY ONLY</span></div><p className="mt-3 text-sm leading-6 text-slate-300">The model receives only server-generated, bounded evidence. It can explain plausible causes and propose reviewer questions, but it cannot authorize, change policy, or execute an action.</p><div className="mt-4 flex flex-wrap gap-2">{selectedEvidence.map(x=><span key={x} className="rounded-lg bg-white/5 px-3 py-2 font-mono text-xs text-slate-400">{x}</span>)}</div></div>
            <div className="mt-6 flex items-center gap-3 rounded-2xl border border-emerald-300/15 bg-emerald-300/[0.04] p-4 text-sm"><span className="h-2 w-2 rounded-full bg-emerald-300"/>Current policy is re-evaluated before any approved action reaches the firewall.</div>
          </section>
        </div> : <section className="mt-6 rounded-3xl border border-white/10 bg-white/[0.035] p-6"><div className="mb-5"><h2 className="text-2xl font-semibold">Human approval queue</h2><p className="mt-1 text-sm text-slate-500">Separation of duties: reviewers cannot approve their own requests.</p></div><div className="space-y-3">{approvals.map(item=><div key={item.id} className="grid gap-4 rounded-2xl border border-white/8 bg-black/15 p-5 md:grid-cols-[1fr_auto_auto] md:items-center"><div><div className="text-xs text-slate-500">{item.id} · {item.requester}</div><div className="mt-1 font-medium">{item.action} <span className="text-slate-600">→</span> {item.target}</div><div className="mt-1 text-xs text-amber-300">Expires in {item.expires}</div></div><button className="rounded-xl border border-white/10 px-4 py-2 text-sm text-slate-300 hover:bg-white/5">Deny</button><button className="rounded-xl bg-emerald-300 px-4 py-2 text-sm font-semibold text-slate-950">Approve</button></div>)}</div></section>}

        <footer className="mt-10 flex flex-col gap-2 border-t border-white/10 pt-5 text-xs text-slate-600 md:flex-row md:justify-between"><span>Deterministic enforcement · bounded evidence · human authority</span><span>Nebius Token Factory · NVIDIA Nemotron</span></footer>
      </div>
    </main>
  );
}
