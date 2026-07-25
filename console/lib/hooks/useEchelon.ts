"use client";

import { useQuery } from "@tanstack/react-query";
import {
  fetchApiKeys,
  fetchConfig,
  fetchDashboardSummary,
  fetchEvents,
  fetchMetricSeries,
} from "@/lib/api/client";

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

export function useApiKeys() {
  return useQuery({ queryKey: ["api-keys"], queryFn: fetchApiKeys });
}

export function useConfig() {
  return useQuery({ queryKey: ["config"], queryFn: fetchConfig });
}
