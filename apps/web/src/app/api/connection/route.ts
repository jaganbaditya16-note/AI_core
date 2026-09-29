import { NextResponse } from "next/server";

import { getServerEnv } from "@/lib/env";

export const dynamic = "force-dynamic";

const TIMEOUT_MS = 4_000;

async function probe(baseUrl: string, path: string): Promise<{ ok: boolean; status: number | null; latencyMs: number | null }> {
  const started = performance.now();
  try {
    const response = await fetch(`${baseUrl}${path}`, {
      method: "GET",
      cache: "no-store",
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    return {
      ok: response.ok || response.status === 503,
      status: response.status,
      latencyMs: Math.round(performance.now() - started),
    };
  } catch {
    return { ok: false, status: null, latencyMs: null };
  }
}

export async function GET() {
  try {
    const { apiBaseUrl } = getServerEnv();
    const [health, readiness, openapi] = await Promise.all([
      probe(apiBaseUrl, "/health"),
      probe(apiBaseUrl, "/health/ready"),
      probe(apiBaseUrl, "/openapi.json"),
    ]);

    return NextResponse.json(
      {
        backend: {
          reachable: health.ok,
          liveness: health,
          readiness,
          openapi,
          connected: health.ok && readiness.ok && openapi.ok,
        },
        checkedAt: new Date().toISOString(),
      },
      { headers: { "cache-control": "no-store" } },
    );
  } catch (error) {
    return NextResponse.json(
      {
        backend: {
          reachable: false,
          connected: false,
          error: error instanceof Error ? error.message : "Backend configuration error",
        },
        checkedAt: new Date().toISOString(),
      },
      { status: 503, headers: { "cache-control": "no-store" } },
    );
  }
}
