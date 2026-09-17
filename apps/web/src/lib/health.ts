import "server-only";

import type { HealthReport, HealthResponse, ReadinessResponse } from "@aicore/types";

import { getServerEnv } from "./env";

/**
 * Server-side access to the AICore API health endpoints.
 *
 * Only these two read-only endpoints are exposed in Phase 0. Everything the
 * browser sees goes through the same-origin proxy at /api/health.
 */

async function requestJson<T>(path: string, timeoutMs: number): Promise<T> {
  const { apiBaseUrl } = getServerEnv();

  const response = await fetch(`${apiBaseUrl}${path}`, {
    method: "GET",
    cache: "no-store",
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(timeoutMs),
  });

  const body: unknown = await response.json().catch(() => null);

  // 503 is a valid readiness answer ("dependency down"), not a transport error.
  if (!response.ok && response.status !== 503) {
    throw new Error(`${path} returned HTTP ${response.status}`);
  }
  if (body === null) {
    throw new Error(`${path} returned a non-JSON response`);
  }

  return body as T;
}

/** Query the API's liveness and readiness endpoints. Never throws. */
export async function fetchHealthReport(): Promise<HealthReport> {
  const { apiTimeoutMs } = getServerEnv();
  const errors: string[] = [];

  let api: HealthResponse | null = null;
  let readiness: ReadinessResponse | null = null;

  try {
    api = await requestJson<HealthResponse>("/health", apiTimeoutMs);
  } catch (error) {
    errors.push(`liveness: ${describeError(error)}`);
  }

  try {
    readiness = await requestJson<ReadinessResponse>("/health/ready", apiTimeoutMs);
  } catch (error) {
    errors.push(`readiness: ${describeError(error)}`);
  }

  return {
    reachable: api !== null,
    checkedAt: new Date().toISOString(),
    api,
    readiness,
    errors,
  };
}

function describeError(error: unknown): string {
  if (error instanceof Error) {
    if (error.name === "TimeoutError") return "request timed out";
    if (error.name === "AbortError") return "request aborted";
    return error.message;
  }
  return "unknown error";
}
