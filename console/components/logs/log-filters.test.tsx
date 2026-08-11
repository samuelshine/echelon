import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { LogFilters } from "./log-filters";
import { DEFAULT_FILTERS } from "@/lib/logs";
import type { ApiKey } from "@/types/echelon";

const KEYS: ApiKey[] = [
  {
    id: "key_1",
    label: "Prod key",
    last4: "ab12",
    createdAt: new Date().toISOString(),
    status: "active",
    rateLimitRpm: 60,
    creditBudget: 1000,
    creditsUsed: 0,
  },
];

function setup(overrides: Partial<React.ComponentProps<typeof LogFilters>> = {}) {
  const onChange = vi.fn();
  render(
    <LogFilters
      filters={DEFAULT_FILTERS}
      onChange={onChange}
      keys={KEYS}
      loadedCount={12}
      hasMore={false}
      {...overrides}
    />,
  );
  return { onChange };
}

describe("LogFilters", () => {
  it("shows how many events have loaded, with a + when more remain", () => {
    setup({ loadedCount: 12, hasMore: true });
    expect(screen.getByText("12")).toBeInTheDocument();
    expect(screen.getByText("+ loaded")).toBeInTheDocument();
  });

  it("omits the + once nothing more is available", () => {
    setup({ loadedCount: 12, hasMore: false });
    expect(screen.getByText("loaded")).toBeInTheDocument();
  });

  it("reports a query change without touching other filter fields", async () => {
    const user = userEvent.setup();
    const { onChange } = setup();
    await user.type(screen.getByPlaceholderText("prompt text or id…"), "x");
    expect(onChange).toHaveBeenCalledWith({ ...DEFAULT_FILTERS, query: "x" });
  });

  it("reports a verdict change", async () => {
    const user = userEvent.setup();
    const { onChange } = setup();
    await user.selectOptions(screen.getByLabelText("Verdict"), "block");
    expect(onChange).toHaveBeenCalledWith({ ...DEFAULT_FILTERS, verdict: "block" });
  });

  it("reports a min-risk preset click", async () => {
    const user = userEvent.setup();
    const { onChange } = setup();
    await user.click(screen.getByRole("button", { name: "≥ 0.60" }));
    expect(onChange).toHaveBeenCalledWith({ ...DEFAULT_FILTERS, minRisk: 0.6 });
  });

  it("lists every provided API key as an option", () => {
    setup();
    expect(screen.getByRole("option", { name: "Prod key" })).toBeInTheDocument();
  });
});
