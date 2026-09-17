/** Static service identity used in UI and health payloads. */

export const serviceName = "aicore-web";

/** Kept in sync with apps/web/package.json. Overridable at build time. */
export const appVersion = process.env.NEXT_PUBLIC_APP_VERSION ?? "0.1.0";
