import "server-only";

/**
 * Server-side configuration.
 *
 * Everything here is server-only by construction: the `server-only` import makes
 * Next.js fail the build if this module is ever pulled into a Client Component.
 * Backend location, timeouts and any future API credentials must never reach the
 * browser — the browser talks to the same-origin proxy at /api/health instead.
 */

const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000";
const DEFAULT_TIMEOUT_MS = 4_000;
const MIN_TIMEOUT_MS = 250;
const MAX_TIMEOUT_MS = 30_000;

export interface ServerEnv {
  /** Base URL of the AICore API, without a trailing slash. */
  apiBaseUrl: string;
  /** Per-request timeout for API calls, in milliseconds. */
  apiTimeoutMs: number;
  nodeEnv: string;
  isProduction: boolean;
}

/** A non-secret summary that is safe to render in the UI. */
export interface ServerEnvSummary {
  apiBaseUrl: string;
  apiTimeoutMs: number;
  nodeEnv: string;
  configured: boolean;
  configError: string | null;
}

function parseTimeoutMs(raw: string | undefined): number {
  if (raw === undefined || raw.trim() === "") return DEFAULT_TIMEOUT_MS;

  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed < MIN_TIMEOUT_MS || parsed > MAX_TIMEOUT_MS) {
    throw new Error(
      `API_REQUEST_TIMEOUT_MS must be an integer between ${MIN_TIMEOUT_MS} and ${MAX_TIMEOUT_MS} (received "${raw}")`,
    );
  }
  return parsed;
}

function parseApiBaseUrl(raw: string | undefined): string {
  const value = raw === undefined || raw.trim() === "" ? DEFAULT_API_BASE_URL : raw.trim();

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`API base URL is not a valid URL (received "${value}")`);
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`API base URL must use http or https (received "${url.protocol}")`);
  }

  return url.origin;
}

/**
 * Resolve configuration from the environment.
 *
 * Precedence: API_INTERNAL_URL (server-only) → NEXT_PUBLIC_API_URL → localhost
 * default for development. Throws on invalid values so misconfiguration is loud
 * rather than silently pointing at the wrong backend.
 */
export function getServerEnv(): ServerEnv {
  const apiBaseUrl = parseApiBaseUrl(process.env.API_INTERNAL_URL ?? process.env.NEXT_PUBLIC_API_URL);
  const apiTimeoutMs = parseTimeoutMs(process.env.API_REQUEST_TIMEOUT_MS);
  const nodeEnv = process.env.NODE_ENV ?? "development";

  return {
    apiBaseUrl,
    apiTimeoutMs,
    nodeEnv,
    isProduction: nodeEnv === "production",
  };
}

/** Same as {@link getServerEnv} but never throws — for rendering. */
export function getServerEnvSummary(): ServerEnvSummary {
  try {
    const env = getServerEnv();
    return {
      apiBaseUrl: env.apiBaseUrl,
      apiTimeoutMs: env.apiTimeoutMs,
      nodeEnv: env.nodeEnv,
      configured: true,
      configError: null,
    };
  } catch (error) {
    return {
      apiBaseUrl: "(invalid configuration)",
      apiTimeoutMs: DEFAULT_TIMEOUT_MS,
      nodeEnv: process.env.NODE_ENV ?? "development",
      configured: false,
      configError: error instanceof Error ? error.message : "Unknown configuration error",
    };
  }
}
