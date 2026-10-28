import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Emits .next/standalone so the Docker image does not need node_modules.
  output: "standalone",
  reactStrictMode: true,
  // Do not advertise the framework version.
  poweredByHeader: false,
  // Fail the build on type errors instead of silently shipping them.
  typescript: { ignoreBuildErrors: false },
  // Note: the API location is read server-side per request (see src/lib/env.ts);
  // no rewrites or public API host are configured, by design.

  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          {
            key: "Permissions-Policy",
            value: "camera=(), microphone=(), geolocation=(), payment=()",
          },
          // Applies to any deployment that is not served over plain HTTP locally.
          {
            key: "Strict-Transport-Security",
            value: "max-age=31536000; includeSubDomains",
          },
        ],
      },
    ];
  },
};

export default nextConfig;
