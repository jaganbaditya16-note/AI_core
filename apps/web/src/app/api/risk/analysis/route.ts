import { NextResponse } from "next/server";

import { getServerEnv } from "@/lib/env";
import { isIntelligenceRouteEnabled } from "@/lib/intelligence-guard";

export const dynamic = "force-dynamic";
export const revalidate = 0;

const MIN_TIMEOUT_MS = 8_000;

export async function GET() {
  if (
    !isIntelligenceRouteEnabled(
      process.env.NODE_ENV,
      process.env.AICORE_DEMO_RISK_PUBLIC_ENABLED,
    )
  ) {
    return NextResponse.json(
      { error: "Demo risk analysis is disabled in production" },
      { status: 503, headers: { "cache-control": "no-store" } },
    );
  }

  const organizationId = process.env.AICORE_DEMO_ORGANIZATION_ID;
  const token = process.env.AICORE_DEMO_API_TOKEN;

  if (
    !organizationId ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(organizationId) ||
    !token
  ) {
    return NextResponse.json(
      { error: "Demo risk analysis is not configured" },
      { status: 503, headers: { "cache-control": "no-store" } },
    );
  }

  try {
    const { apiBaseUrl, apiTimeoutMs } = getServerEnv();
    const url = new URL(
      `/organizations/${organizationId}/risk/analysis`,
      apiBaseUrl,
    );

    // Local demo: hourly windows provide finer-grained activity analysis.
    // Engine minimum-history safeguards remain unchanged.
    url.search = new URLSearchParams({
      baseline: "7d",
      observation: "1h",
      limit: "20",
      total: "true",
    }).toString();

    const response = await fetch(url, {
      method: "GET",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${token}`,
      },
      cache: "no-store",
      signal: AbortSignal.timeout(Math.max(apiTimeoutMs, MIN_TIMEOUT_MS)),
    });

    const body = await response.json().catch(() => null);

    if (body === null) {
      return NextResponse.json(
        { error: "AICore returned an invalid risk-analysis response" },
        { status: 502, headers: { "cache-control": "no-store" } },
      );
    }

    return NextResponse.json(body, {
      status: response.status,
      headers: { "cache-control": "no-store" },
    });
  } catch {
    return NextResponse.json(
      { error: "AICore risk analysis is temporarily unavailable" },
      { status: 502, headers: { "cache-control": "no-store" } },
    );
  }
}
