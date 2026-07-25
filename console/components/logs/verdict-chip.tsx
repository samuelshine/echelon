import { VERDICT_META } from "@/lib/logs";
import type { Verdict } from "@/types/echelon";

export function VerdictChip({ verdict, size = "sm" }: { verdict: Verdict; size?: "sm" | "md" }) {
  const m = VERDICT_META[verdict];
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full font-medium"
      style={{
        background: m.wash,
        color: m.color,
        fontSize: size === "md" ? 12 : 11,
        padding: size === "md" ? "3px 10px" : "2px 8px",
      }}
    >
      <span aria-hidden style={{ fontSize: size === "md" ? 11 : 10 }}>
        {m.glyph}
      </span>
      {m.label}
    </span>
  );
}
