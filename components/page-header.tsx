export function PageHeader({
  eyebrow,
  title,
  children,
}: {
  eyebrow: string;
  title: string;
  children?: React.ReactNode;
}) {
  return (
    <header className="flex items-end justify-between border-b border-[var(--color-line)] px-8 py-6">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1 className="mt-1 font-[family-name:var(--font-display)] text-3xl tracking-tight text-[var(--color-ink)]">
          {title}
        </h1>
      </div>
      {children ? <div className="flex items-center gap-3">{children}</div> : null}
    </header>
  );
}
