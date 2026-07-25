import {
  Gauge,
  ScrollText,
  SlidersHorizontal,
  KeyRound,
  type LucideIcon,
} from "lucide-react";

export interface NavItem {
  href: string;
  label: string;
  /** Short mono tag shown in the rail. */
  tag: string;
  description: string;
  icon: LucideIcon;
}

export const NAV_ITEMS: NavItem[] = [
  {
    href: "/",
    label: "Overview",
    tag: "00",
    description: "AI health, cost & attack posture at a glance",
    icon: Gauge,
  },
  {
    href: "/logs",
    label: "Threat Audit",
    tag: "01",
    description: "Every prompt, and exactly why it was judged",
    icon: ScrollText,
  },
  {
    href: "/config",
    label: "Thresholds",
    tag: "02",
    description: "Tune the 3-fold cascade and egress scanners",
    icon: SlidersHorizontal,
  },
  {
    href: "/keys",
    label: "Access",
    tag: "03",
    description: "API keys, rate limits & credit budgets",
    icon: KeyRound,
  },
];
