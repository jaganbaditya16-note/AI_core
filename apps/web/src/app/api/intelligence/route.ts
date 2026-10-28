import { NextResponse } from "next/server";

import { getServerEnv } from "@/lib/env";
import { isIntelligenceRouteEnabled, isSameOriginRequest } from "@/lib/intelligence-guard";

export const dynamic = "force-dynamic";
export const revalidate = 0;

const MAX_BODY_BYTES = 8_000;
const INTELLIGENCE_TIMEOUT_MS = 25_000;

export async function POST(request: Request) {
  if (
    !isIntelligenceRouteEnabled(
      process.env.NODE_ENV,
      process.env.AICORE_INTELLIGENCE_PUBLIC_ENABLED,
    )
  ) {
    return NextResponse.json(
      { error: "AI advisory is disabled in production" },
      { status: 503, headers: { "cache-control": "no-store" } },
    );
  }

  if (
    process.env.NODE_ENV === "production" &&
    !isSameOriginRequest(request.url, request.headers.get("origin"))
  ) {
    return NextResponse.json(
      { error: "Forbidden request origin" },
      { status: 403, headers: { "cache-control": "no-store" } },
    );
  }

  const token = process.env.AICORE_INTELLIGENCE_SERVICE_TOKEN;
  if (!token) {
    return NextResponse.json({ error: "AI advisory is not configured" }, { status: 503 });
  }

  const contentLength = Number.parseInt(request.headers.get("content-length") ?? "0", 10);
  if (contentLength > MAX_BODY_BYTES) {
    return NextResponse.json({ error: "Request too large" }, { status: 413 });
  }

  const body = await request.text();
  if (new TextEncoder().encode(body).byteLength > MAX_BODY_BYTES) {
    return NextResponse.json({ error: "Request too large" }, { status: 413 });
  }

  let payload: unknown;
  try {
    payload = JSON.parse(body);
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  try {
    const { apiBaseUrl, apiTimeoutMs } = getServerEnv();
    const response = await fetch(`${apiBaseUrl}/intelligence/advisory`, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        "x-aicore-intelligence-token": token,
      },
      body: JSON.stringify(payload),
      cache: "no-store",
      signal: AbortSignal.timeout(Math.max(apiTimeoutMs, INTELLIGENCE_TIMEOUT_MS)),
    });
    const responseBody = await response.json().catch(() => ({ error: "Backend returned invalid JSON" }));
    return NextResponse.json(responseBody, {
      status: response.status,
      headers: { "cache-control": "no-store" },
    });
  } catch {
    return NextResponse.json({ error: "AICore backend is unavailable" }, { status: 502 });
  }
}
