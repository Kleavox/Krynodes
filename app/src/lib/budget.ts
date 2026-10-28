import type { NodeRecord } from "../types";

export interface Budget {
  requests: number;
  writes: number;
  reads: number;
}

export interface DailyUse {
  writes: number;
  requests: number;
  reads?: number;
}

const DAY_SECONDS = 86_400;
const DASHBOARD_REQUESTS = 3_000;
const STREAM_REQUESTS = 24;

export function estimateDailyUse(
  nodes: Pick<NodeRecord, "interval_seconds" | "disabled_at" | "enrolled_at">[],
): DailyUse {
  let writes = 0;
  let requests = DASHBOARD_REQUESTS;
  for (const node of nodes) {
    if (node.disabled_at || !node.enrolled_at) continue;
    writes += (3 * DAY_SECONDS) / Math.max(300, node.interval_seconds);
    requests += STREAM_REQUESTS;
  }
  return { writes: Math.round(writes), requests: Math.round(requests) };
}

const ratios = (use: DailyUse, budget: Budget) => ({
  writes: use.writes / budget.writes,
  requests: use.requests / budget.requests,
  reads: (use.reads ?? 0) / budget.reads,
});

export function budgetLevel(
  use: DailyUse,
  budget: Budget,
): "ok" | "warn" | "over" {
  const ratio = Math.max(...Object.values(ratios(use, budget)));
  if (ratio > 1) return "over";
  return ratio >= 0.8 ? "warn" : "ok";
}

const COMPACT = new Intl.NumberFormat("en", {
  notation: "compact",
  maximumFractionDigits: 1,
});

export function formatThousands(value: number): string {
  return COMPACT.format(value).replace("K", "k");
}

export function formatBytes(bytes: number): string {
  if (bytes < 1_000_000) return `${Math.round(bytes / 1_000)} KB`;
  const megabytes = bytes / 1_000_000;
  return `${megabytes < 10 ? megabytes.toFixed(1) : Math.round(megabytes)} MB`;
}

export function quotaLine(
  use: DailyUse,
  budget: Budget,
): { percent: number; detail: string } {
  const shares = ratios(use, budget);
  const [unit, ratio] = (Object.entries(shares) as [keyof Budget, number][])
    .sort((a, b) => b[1] - a[1])
    .at(0)!;
  return {
    percent: Math.round(ratio * 100),
    detail: `${formatThousands(use[unit] ?? 0)} of ${formatThousands(budget[unit])} ${unit}`,
  };
}
