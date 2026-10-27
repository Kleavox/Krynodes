import type { CheckRecord, NodeRecord } from "../types";
import { checkDisplayStatus, nodeState, percentage } from "./format";
import { quarantineReasons } from "./quarantine";

export type UsageLevel = "ok" | "warn" | "critical";
export type Severity = "critical" | "warning" | "healthy" | "idle";

export function usageLevel(value: number | null): UsageLevel | null {
  if (value === null) return null;
  if (value >= 90) return "critical";
  return value >= 80 ? "warn" : "ok";
}

export function nodeUsage(node: NodeRecord) {
  return [
    { label: "CPU", value: node.cpu_percent },
    {
      label: "RAM",
      value: percentage(node.memory_used_bytes, node.memory_total_bytes),
    },
    {
      label: "Disk",
      value: percentage(node.disk_used_bytes, node.disk_total_bytes),
    },
  ];
}

export function nodeHealth(
  node: NodeRecord,
  checks: CheckRecord[],
  now: number,
  raised: string[] = [],
): { severity: Severity; reasons: string[] } {
  const state = nodeState(node, now);
  if (state === "pending" || state === "disabled") {
    return { severity: "idle", reasons: [] };
  }
  const watched = quarantineReasons(node, now);
  if (watched.quarantined) {
    return { severity: "critical", reasons: watched.reasons };
  }
  if (state === "offline")
    return { severity: "critical", reasons: ["Offline"] };

  const down = checks.filter(
    (check) => check.enabled && check.status === "DOWN",
  ).length;
  const usage = nodeUsage(node)
    .map((item) => ({ ...item, level: usageLevel(item.value) }))
    .filter((item) => item.level === "warn" || item.level === "critical")
    .sort((a, b) => (b.value ?? 0) - (a.value ?? 0));

  const reasons = [
    ...(down > 0 ? [`${down} ${down === 1 ? "check" : "checks"} down`] : []),
    ...usage.map((item) => `${item.label} ${Math.round(item.value ?? 0)}%`),
    ...watched.reasons,
    ...raised,
  ];
  const critical = down > 0 || usage.some((item) => item.level === "critical");
  if (critical) return { severity: "critical", reasons };
  return { severity: reasons.length > 0 ? "warning" : "healthy", reasons };
}

const RANK: Record<Severity, number> = {
  critical: 0,
  warning: 1,
  healthy: 2,
  idle: 3,
};

export function bySeverity(
  a: { name: string; severity: Severity },
  b: { name: string; severity: Severity },
): number {
  return RANK[a.severity] - RANK[b.severity] || a.name.localeCompare(b.name);
}

export function fleetSummary(
  nodes: NodeRecord[],
  checks: CheckRecord[],
  now: number,
) {
  const states = new Map(nodes.map((node) => [node.id, nodeState(node, now)]));
  const quarantined = nodes.filter((node) => node.quarantine);
  const counted = nodes
    .filter((node) => !node.quarantine)
    .map((node) => states.get(node.id));
  const shown = checks.map((check) =>
    checkDisplayStatus(
      check.status,
      states.get(check.node_id) ?? "offline",
      check.enabled,
    ),
  );
  return {
    nodes: {
      total: nodes.length,
      online: counted.filter((state) => state === "online").length,
      offline: counted.filter((state) => state === "offline").length,
      quarantined: quarantined.length,
    },
    checks: {
      total: checks.length,
      up: shown.filter((status) => status === "UP").length,
      down: shown.filter((status) => status === "DOWN").length,
      offline: shown.filter(
        (status) => status === "OFFLINE" || status === "UNTRUSTED",
      ).length,
      stale: shown.filter((status) => status === "STALE").length,
    },
  };
}

export function serversTile(nodes: {
  total: number;
  online: number;
  offline: number;
  quarantined: number;
}): { value: string; detail: string; bad: boolean } {
  const apart = [
    nodes.offline > 0 ? `${nodes.offline} offline` : null,
    nodes.quarantined > 0 ? `${nodes.quarantined} quarantined` : null,
  ].filter((part): part is string => part !== null);
  return {
    value: `${nodes.online}/${nodes.total}`,
    detail: apart.length > 0 ? apart.join(" · ") : "None Offline",
    bad: apart.length > 0,
  };
}
