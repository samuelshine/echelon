import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ThreatTable } from "./threat-table";
import { generateEvents } from "@/lib/api/mock";
import type { PromptEvent } from "@/types/echelon";

// react-virtual measures the scroll container via offsetWidth/offsetHeight on
// mount; jsdom reports 0 for both, which yields zero visible rows. Stub a
// real-looking size so virtualized rows actually render in tests.
let offsetHeightSpy: ReturnType<typeof vi.spyOn>;
let offsetWidthSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  offsetHeightSpy = vi
    .spyOn(HTMLElement.prototype, "offsetHeight", "get")
    .mockReturnValue(560);
  offsetWidthSpy = vi
    .spyOn(HTMLElement.prototype, "offsetWidth", "get")
    .mockReturnValue(800);
});

afterEach(() => {
  offsetHeightSpy.mockRestore();
  offsetWidthSpy.mockRestore();
});

function makeEvents(count: number): PromptEvent[] {
  return generateEvents(count, 7);
}

describe("ThreatTable", () => {
  it("shows an empty state when no events match the current filters", () => {
    render(<ThreatTable events={[]} onSelect={vi.fn()} />);
    expect(
      screen.getByText("No events match these filters. Loosen a filter to see traffic."),
    ).toBeInTheDocument();
  });

  it("renders a row per event and calls onSelect with the clicked event", async () => {
    const user = userEvent.setup();
    const events = makeEvents(5);
    const onSelect = vi.fn();
    render(<ThreatTable events={events} onSelect={onSelect} />);

    const rows = screen.getAllByRole("button").filter((b) => b.textContent?.includes(events[0].excerpt) || events.some((e) => b.textContent?.includes(e.excerpt)));
    expect(rows.length).toBeGreaterThan(0);

    await user.click(rows[0]);
    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(onSelect.mock.calls[0][0]).toHaveProperty("id");
  });

  it("marks the selected row distinctly from the rest", () => {
    const events = makeEvents(3);
    render(<ThreatTable events={events} selectedId={events[0].id} onSelect={vi.fn()} />);
    const selectedRow = screen.getAllByRole("button").find((b) => b.textContent?.includes(events[0].excerpt));
    expect(selectedRow?.className).toContain("bg-[var(--color-brand-wash)]");
  });

  it("highlights freshly-arrived rows via the freshIds set", () => {
    const events = makeEvents(3);
    render(<ThreatTable events={events} onSelect={vi.fn()} freshIds={new Set([events[1].id])} />);
    const freshRow = screen.getAllByRole("button").find((b) => b.textContent?.includes(events[1].excerpt));
    expect(freshRow?.className).toContain("bg-[var(--color-pass-wash)]");
  });

  it("toggles sort direction on repeated header clicks", async () => {
    const user = userEvent.setup();
    const events = makeEvents(4);
    render(<ThreatTable events={events} onSelect={vi.fn()} />);

    const riskHeader = screen.getByRole("button", { name: /Risk/ });
    // Default sort is by time desc; the arrow only appears on the active column.
    expect(within(riskHeader).queryByText("▼")).not.toBeInTheDocument();

    await user.click(riskHeader);
    expect(within(riskHeader).getByText("▼")).toBeInTheDocument();

    await user.click(riskHeader);
    expect(within(riskHeader).getByText("▲")).toBeInTheDocument();
  });
});
