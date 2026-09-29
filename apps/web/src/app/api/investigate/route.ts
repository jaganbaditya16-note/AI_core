import { NextResponse } from "next/server";

import { getServerEnv } from "@/lib/env";

export const dynamic = "force-dynamic";
export const revalidate = 0;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Same-origin investigation proxy.
 *
 * The browser supplies only an ephemeral bearer token and UUID path parameters.
 * The backend URL stays server-side. The proxy never accepts or forwards a Nebius key.
 */
export async function POST(request: Request) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  if (!body || typeof body !== "object") {
    return NextResponse.json({ error: "Invalid request body" }, { status: 400 });
  }

  const payload = body as Record<string, unknown>;
  const organizationId = payload.organization_id;
  const detectionId = payload.detection_id;
  if (
    typeof organizationId !== "string" ||
    typeof detectionId !== "string" ||
    !UUID.test(organizationId) ||
    !UUID.test(detectionId)
  ) {
    return NextResponse.json({ error: "organization_id and detection_id must be UUIDs" }, { status: 400 });
  }

  const authorization = request.headers.get("authorization");
  if (!authorization || !/^Bearer\s+\S+$/i.test(authorization)) {
    return NextResponse.json({ error: "Bearer authorization is required" }, { status: 401 });
  }

  let env;
  try {
    env = getServerEnv();
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Invalid API configuration" },
      { status: 503 },
    );
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), env.apiTimeoutMs);

  try {
    const upstream = await fetch(
      `${env.apiBaseUrl}/organizations/${organizationId}/risk/detections/${detectionId}/investigation`,
      {
        method: "POST",
        headers: {
          Accept: "application/json",
          Authorization: authorization,
        },
        cache: "no-store",
        signal: controller.signal,
      },
    );

    const text = await upstream.text();
    let responseBody: unknown;
    try {
      responseBody = JSON.parse(text);
    } catch {
      responseBody = { error: "Upstream returned a non-JSON response" };
    }

    return NextResponse.json(responseBody, {
      status: upstream.status,
      headers: { "cache-control": "no-store" },
    });
  } catch (error) {
    const message = error instanceof Error && error.name === "AbortError"
      ? "Investigation request timed out"
      : "Investigation API is unavailable";
    return NextResponse.json({ error: message }, { status: 503 });
  } finally {
    clearTimeout(timeout);
  }
}
