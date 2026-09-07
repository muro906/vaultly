"use client";

export default function ErrorBoundary({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-4 p-6 text-center">
      <h1 className="text-xl font-semibold text-slate-100">Something went wrong</h1>
      <p className="max-w-md text-sm text-slate-400">
        The request could not be completed. If it keeps happening, the server logs will have the
        detail{error.digest ? ` under digest ${error.digest}` : ""}.
      </p>
      <button type="button" className="btn-primary" onClick={reset}>
        Try again
      </button>
    </main>
  );
}
