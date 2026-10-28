import { NextResponse } from "next/server";

import { fetchHealthReport } from "@/lib/health";
import { getServerEnvSummary } from "@/lib/env";

/**
 * Same-origin health proxy.
 *
 * The browser calls this route; the server calls the AICore API. That keeps the
 * backend location (and any future credentials) out of the browser bundle, and
 * lets the frontend work unchanged whether the API is local or remote.
 *
 * Responds 200 when the API is reachable, 503 when it is not.
 */

export const dynamic = "force-dynamic";
export const revalidate = 0;

export async function GET() {
  const config = getServerEnvSummary();

  if (!config.configured) {
    return NextResponse.json(
      {
        reachable: false,
        checkedAt: new Date().toISOString(),
        api: null,
        readiness: null,
        errors: [`configuration: ${config.configError ?? "invalid server configuration"}`],
      },
      { status: 503, headers: { "cache-control": "no-store" } },
    );
  }

  const report = await fetchHealthReport();

  return NextResponse.json(report, {
    status: report.reachable ? 200 : 503,
    headers: { "cache-control": "no-store" },
  });
}
