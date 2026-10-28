"use client";

import Link from "next/link";
import { useEffect } from "react";

/**
 * Route-level error boundary.
 *
 * Next.js 16 passes `retry` (previously `reset`) to recover the segment.
 * The error digest is shown so it can be matched against server logs; no error
 * details are exposed beyond what Next.js already provides.
 */
export default function RouteError({
  error,
  retry,
}: {
  error: Error & { digest?: string };
  retry: () => void;
}) {
  useEffect(() => {
    console.error("Unhandled error in route segment:", error);
  }, [error]);

  return (
    <main className="mx-auto flex min-h-dvh w-full max-w-2xl flex-col justify-center gap-4 px-6">
      <h1 className="text-2xl font-semibold tracking-tight">Something went wrong</h1>
      <p className="text-sm text-aicore-fg-muted">
        This page failed to render. You can retry, or return to the overview.
      </p>
      {error.digest ? (
        <p className="font-mono text-xs text-aicore-fg-subtle">Reference: {error.digest}</p>
      ) : null}
      <div className="flex gap-3">
        <button
          type="button"
          onClick={() => retry()}
          className="rounded-lg bg-aicore-accent px-4 py-2 text-sm font-medium text-white transition hover:opacity-90 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-aicore-accent"
        >
          Try again
        </button>
        <Link
          href="/"
          className="rounded-lg border border-aicore-border px-4 py-2 text-sm transition hover:border-aicore-fg-subtle focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-aicore-accent"
        >
          Back to overview
        </Link>
      </div>
    </main>
  );
}
