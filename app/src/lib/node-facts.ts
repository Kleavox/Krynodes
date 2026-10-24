import { metricText } from "./format";
import type { NodeRecord } from "@/types";

export function systemLine(node: NodeRecord): string {
  return [node.operating_system, node.architecture].filter(Boolean).join(" · ");
}

const UNITS = [
  ["day", 86_400],
  ["hour", 3_600],
  ["minute", 60],
  ["second", 1],
] as const;

function inWords(seconds: number, single: boolean): string {
  const [unit, size] =
    UNITS.find(([, length]) => seconds >= length) ?? UNITS[3];
  const count = Math.max(1, Math.floor(seconds / size));
  if (count === 1) return single ? unit : `1 ${unit}`;
  return `${count} ${unit}s`;
}

export function systemFacts(node: NodeRecord): string {
  return [
    node.operating_system,
    node.architecture,
    node.uptime_seconds === null
      ? null
      : `Up ${inWords(node.uptime_seconds, false)}`,
    `Reports every ${inWords(node.interval_seconds, true)}`,
    node.agent_version ? `Agent ${node.agent_version}` : null,
    node.hostname && node.hostname !== node.name
      ? `Host ${node.hostname}`
      : null,
  ]
    .filter(Boolean)
    .join(" · ");
}

export function rangeText(values: (number | null)[], suffix: string): string {
  const measured = values.filter(
    (value): value is number => value !== null && Number.isFinite(value),
  );
  if (measured.length === 0) return "--";
  const low = metricText(Math.min(...measured));
  const high = metricText(Math.max(...measured));
  return low === high ? `${low}${suffix}` : `${low}–${high}${suffix}`;
}
