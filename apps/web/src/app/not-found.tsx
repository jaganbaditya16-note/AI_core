import Link from "next/link";

export default function NotFound() {
  return (
    <main className="mx-auto flex min-h-dvh w-full max-w-2xl flex-col justify-center gap-4 px-6">
      <p className="font-mono text-xs tracking-[0.2em] text-aicore-fg-subtle uppercase">404</p>
      <h1 className="text-2xl font-semibold tracking-tight">Page not found</h1>
      <p className="text-sm text-aicore-fg-muted">
        That route does not exist in this build. Phase 0 ships an overview and a system health page.
      </p>
      <Link
        href="/"
        className="w-fit rounded-lg border border-aicore-border px-4 py-2 text-sm transition hover:border-aicore-fg-subtle focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-aicore-accent"
      >
        Back to overview
      </Link>
    </main>
  );
}
