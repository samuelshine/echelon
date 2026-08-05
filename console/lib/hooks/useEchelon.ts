"use client";

import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import {
  fetchApiKeys,
  fetchConfig,
  fetchDashboardSummary,
  fetchEvents,
  fetchEventsPage,
  fetchMetricSeries,
} from "@/lib/api/client";
import type { LogFilterState } from "@/lib/logs";

export function useDashboardSummary() {
  return useQuery({
    queryKey: ["dashboard-summary"],
    queryFn: fetchDashboardSummary,
  });
}

export function useMetricSeries(hours = 24) {
  return useQuery({
    queryKey: ["metrics", hours],
    queryFn: () => fetchMetricSeries(hours),
  });
}

export function useEvents(count = 500) {
  return useQuery({ queryKey: ["events", count], queryFn: () => fetchEvents(count) });
}

/**
 * Filter- and cursor-aware event feed for the logs page. The filter object is part
 * of the query key, so changing any filter triggers a fresh server-side query
 * rather than a client-side re-filter of a stale window. getNextPageParam reads the
 * gateway's cursor/hasMore so "load older" pages walk backward with no gaps.
 */
export function useEventsInfinite(filters: LogFilterState) {
  return useInfiniteQuery({
    queryKey: ["events-infinite", filters],
    queryFn: ({ pageParam }) => fetchEventsPage(filters, pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (lastPage) => (lastPage.hasMore ? lastPage.nextCursor : undefined),
  });
}

export function useApiKeys() {
  return useQuery({ queryKey: ["api-keys"], queryFn: fetchApiKeys });
}

export function useConfig() {
  return useQuery({ queryKey: ["config"], queryFn: fetchConfig });
}
