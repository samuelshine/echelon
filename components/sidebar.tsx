"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { NAV_ITEMS } from "@/components/nav";
import { ThemeToggle } from "@/components/theme-toggle";
import { cn } from "@/lib/cn";

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="flex w-[248px] shrink-0 flex-col border-r border-[var(--color-line)] bg-[var(--color-surface)]">
      {/* Wordmark */}
      <div className="flex items-center gap-3 border-b border-[var(--color-line)] px-6 py-5">
        <div
          aria-hidden
          className="grid h-8 w-8 place-items-center rounded-[var(--radius)] bg-[var(--color-brand)] text-[var(--color-surface)]"
        >
          <span className="font-[family-name:var(--font-display)] text-lg leading-none">
            E
          </span>
        </div>
        <div className="leading-tight">
          <div className="font-[family-name:var(--font-display)] text-lg tracking-tight">
            Echelon
          </div>
          <div className="eyebrow">Security Console</div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4">
        <ul className="space-y-1">
          {NAV_ITEMS.map((item) => {
            const active =
              item.href === "/"
                ? pathname === "/"
                : pathname.startsWith(item.href);
            const Icon = item.icon;
            return (
              <li key={item.href}>
                <Link
                  href={item.href}
                  aria-current={active ? "page" : undefined}
                  className={cn(
                    "group flex items-start gap-3 rounded-[var(--radius)] px-3 py-2.5 transition-colors",
                    active
                      ? "bg-[var(--color-brand-wash)] text-[var(--color-ink)]"
                      : "text-[var(--color-ink-soft)] hover:bg-[var(--color-surface-sunken)]",
                  )}
                >
                  <Icon
                    size={16}
                    className={cn(
                      "mt-0.5 shrink-0",
                      active
                        ? "text-[var(--color-brand)]"
                        : "text-[var(--color-faint)] group-hover:text-[var(--color-muted)]",
                    )}
                  />
                  <span className="min-w-0">
                    <span className="flex items-baseline gap-2">
                      <span className="text-sm font-medium">{item.label}</span>
                      <span className="font-[family-name:var(--font-mono)] text-[10px] text-[var(--color-faint)]">
                        {item.tag}
                      </span>
                    </span>
                    <span className="mt-0.5 block text-xs leading-snug text-[var(--color-muted)]">
                      {item.description}
                    </span>
                  </span>
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      {/* Footer status */}
      <div className="border-t border-[var(--color-line)] px-4 py-4">
        <div className="flex items-center gap-2 px-2">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-[var(--color-pass)] opacity-60" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-[var(--color-pass)]" />
          </span>
          <span className="text-xs text-[var(--color-muted)]">Firewall active</span>
        </div>
        <div className="mt-3 flex items-center justify-between">
          <ThemeToggle />
          <span className="flex items-center gap-1 px-2 font-[family-name:var(--font-mono)] text-[10px] text-[var(--color-faint)]">
            <kbd className="rounded border border-[var(--color-line-strong)] px-1">⌘</kbd>
            <kbd className="rounded border border-[var(--color-line-strong)] px-1">K</kbd>
          </span>
        </div>
      </div>
    </aside>
  );
}
