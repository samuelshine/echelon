"use client";

import { useEffect, useState } from "react";
import { Moon, Sun } from "lucide-react";
import { currentTheme, toggleTheme, type Theme } from "@/lib/theme";

export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>("light");

  useEffect(() => setTheme(currentTheme()), []);

  return (
    <button
      type="button"
      onClick={() => setTheme(toggleTheme())}
      aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
      className="flex items-center gap-2 rounded-[var(--radius)] px-2 py-1.5 text-xs text-[var(--color-muted)] hover:bg-[var(--color-surface-sunken)]"
    >
      {theme === "dark" ? <Moon size={14} /> : <Sun size={14} />}
      {theme === "dark" ? "Dark" : "Light"}
    </button>
  );
}
