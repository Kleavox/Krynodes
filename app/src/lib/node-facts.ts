import {
  clockTime,
  dayLabel,
  formatDuration,
  formatUptime,
  shortDate,
} from "./format";
import type { NodeRecord } from "@/types";

export function systemLine(node: NodeRecord): string {
  return [node.operating_system, node.architecture].filter(Boolean).join(" · ");
}

function liveSince(at: string, now: number): string {
  const time = clockTime(at);
  return dayLabel(at, now) === "Today" ? time : `${shortDate(at)}, ${time}`;
}

export function systemFacts(node: NodeRecord, now: number): string[] {
  return [
    node.hostname && node.hostname !== node.name ? `Host ${node.hostname}` : "",
    systemLine(node),
    `Up ${formatUptime(node.uptime_seconds)}`,
    node.connected_at
      ? `Live since ${liveSince(node.connected_at, now)}`
      : "Not connected",
    `Reports every ${formatDuration(node.interval_seconds * 1000)}`,
    `Agent ${node.agent_version ?? "--"}`,
  ].filter(Boolean);
}
