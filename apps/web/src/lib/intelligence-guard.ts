/**
 * Guards for the public AI advisory proxy.
 *
 * Same-origin validation is a browser request guard, not authentication.
 * Public production use still requires hosting-level rate limiting.
 */
export function isIntelligenceRouteEnabled(
  nodeEnv: string | undefined,
  publicEnabled: string | undefined,
): boolean {
  return nodeEnv !== "production" || publicEnabled === "true";
}

export function isSameOriginRequest(
  requestUrl: string,
  originHeader: string | null,
): boolean {
  if (!originHeader) return false;

  try {
    const suppliedOrigin = new URL(originHeader).origin;
    const requestOrigin = new URL(requestUrl).origin;

    // Origin headers contain an origin, not a URL path or credentials.
    return suppliedOrigin === originHeader && suppliedOrigin === requestOrigin;
  } catch {
    return false;
  }
}
