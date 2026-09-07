/** Shown while a Server Component in this group is fetching. */
export default function Loading() {
  return (
    <div className="animate-pulse space-y-4" aria-label="Loading">
      <div className="h-6 w-48 rounded bg-surface-raised" />
      <div className="h-24 rounded bg-surface-raised" />
      <div className="h-24 rounded bg-surface-raised" />
    </div>
  );
}
