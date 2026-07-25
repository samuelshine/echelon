export function ChartCard({
  eyebrow,
  title,
  subtitle,
  action,
  children,
}: {
  eyebrow: string;
  title: string;
  subtitle?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-[var(--radius-lg)] border border-[var(--color-line)] bg-[var(--color-surface)] p-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="eyebrow">{eyebrow}</div>
          <h2 className="mt-1 font-[family-name:var(--font-display)] text-xl leading-tight">
            {title}
          </h2>
          {subtitle ? (
            <p className="mt-1 text-xs text-[var(--color-muted)]">{subtitle}</p>
          ) : null}
        </div>
        {action}
      </div>
      <div className="mt-5">{children}</div>
    </section>
  );
}

/** A skeleton block sized to a chart, shown while data loads. */
export function ChartSkeleton({ height = 240 }: { height?: number }) {
  return (
    <div
      className="animate-pulse rounded-[var(--radius)] bg-[var(--color-surface-sunken)]"
      style={{ height }}
      aria-hidden
    />
  );
}
