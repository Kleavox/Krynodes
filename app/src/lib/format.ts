import type { CheckRecord, CheckStatus, NodeRecord } from "../types";

export type NodeState = "disabled" | "pending" | "online" | "offline";

export function parseTimestamp(value: string): number {
  const normalized = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/u.test(value)
    ? `${value.replace(" ", "T")}Z`
    : value;
  return Date.parse(normalized);
}

export function graceSeconds(intervalSeconds: number): number {
  return Math.max(90, intervalSeconds * 3);
}

export function nodeState(
  node: Pick<
    NodeRecord,
    "disabled_at" | "enrolled_at" | "last_seen_at" | "interval_seconds"
  > & { grace_seconds?: number },
  now = Date.now(),
): NodeState {
  if (node.disabled_at) return "disabled";
  if (!node.enrolled_at) return "pending";
  if (!node.last_seen_at) return "offline";
  return now - parseTimestamp(node.last_seen_at) <=
    (node.grace_seconds ?? graceSeconds(node.interval_seconds)) * 1000
    ? "online"
    : "offline";
}

export type CheckDisplay = CheckStatus | "OFFLINE" | "STALE" | "PAUSED";

export function checkDisplayStatus(
  status: CheckStatus,
  node: NodeState,
  enabled: boolean | number = true,
): CheckDisplay {
  if (!enabled) return "PAUSED";
  if (status === "UNTRUSTED") return status;
  if (node === "offline") return "OFFLINE";
  if (node === "online" || status === "UNKNOWN") return status;
  return "STALE";
}

export function publicLabel(
  check: Pick<CheckRecord, "public" | "enabled">,
): string | null {
  if (!check.public) return null;
  return check.enabled ? "Public" : "Public · Paused";
}

export function percentage(
  used: number | null,
  total: number | null,
): number | null {
  if (used === null || total === null || total <= 0) return null;
  return (used / total) * 100;
}

export function metricText(value: number | null, suffix = ""): string {
  if (value === null || !Number.isFinite(value)) return "--";
  return `${value.toFixed(value >= 10 ? 0 : 1)}${suffix}`;
}

const BYTE_UNITS = ["B", "KB", "MB", "GB", "TB"] as const;

export function formatBytes(value: number | null): string {
  if (value === null || !Number.isFinite(value) || value < 0) return "--";
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < BYTE_UNITS.length - 1) {
    size /= 1024;
    unit += 1;
  }
  const shown =
    unit === 0 || size >= 10 ? String(Math.round(size)) : size.toFixed(1);
  return `${shown} ${BYTE_UNITS[unit]}`;
}

export function formatDuration(milliseconds: number): string {
  const seconds = Math.max(0, Math.floor(milliseconds / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24)
    return minutes % 60 ? `${hours}h ${minutes % 60}m` : `${hours}h`;
  const days = Math.floor(hours / 24);
  return hours % 24 ? `${days}d ${hours % 24}h` : `${days}d`;
}

export function formatUptime(seconds: number | null): string {
  return seconds === null ? "--" : formatDuration(seconds * 1000);
}

export function capitalize(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

const SMALL_WORDS = new Set([
  "a",
  "an",
  "the",
  "and",
  "or",
  "of",
  "on",
  "in",
  "to",
  "by",
  "for",
  "at",
  "with",
  "into",
  "from",
]);

export const titleCase = (text: string) =>
  text
    .split(" ")
    .map((word, index) =>
      index > 0 && SMALL_WORDS.has(word.toLowerCase())
        ? word.toLowerCase()
        : capitalize(word),
    )
    .join(" ");

export function timeAgo(value: string | null, now = Date.now()): string {
  if (!value) return "never";
  const elapsed = now - parseTimestamp(value);
  if (!Number.isFinite(elapsed)) return "--";
  return elapsed < 5_000 ? "just now" : `${formatDuration(elapsed)} ago`;
}

export function countdown(milliseconds: number): string {
  const total = Math.max(0, Math.floor(milliseconds / 1000));
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${pad(Math.floor(total / 60))}:${pad(total % 60)}`;
}

const CLOCK = new Intl.DateTimeFormat("en-GB", {
  hour: "2-digit",
  minute: "2-digit",
  hourCycle: "h23",
});
const MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
] as const;

function toEpoch(value: string | number): number {
  return typeof value === "number" ? value : parseTimestamp(value);
}

export function clockTime(value: string | number): string {
  return CLOCK.format(toEpoch(value));
}

export function shortDate(value: string | number): string {
  const date = new Date(toEpoch(value));
  return `${date.getDate()} ${MONTHS[date.getMonth()]}`;
}

export function stampTime(value: string | number, now = Date.now()): string {
  const at = toEpoch(value);
  return new Date(at).toDateString() === new Date(now).toDateString()
    ? clockTime(at)
    : `${shortDate(at)} ${clockTime(at)}`;
}

export function dayLabel(value: string, now = Date.now()): string {
  const at = parseTimestamp(value);
  const key = (epoch: number) => new Date(epoch).toDateString();
  if (key(at) === key(now)) return "Today";
  if (key(at) === key(now - 86_400_000)) return "Yesterday";
  return shortDate(at);
}

export function displayHandle(
  username?: string | null,
  email?: string | null,
): string {
  if (username) return username;
  const local = email?.split("@")[0];
  return local || "Account";
}

export const incidentReason = (summary: string | null): string | null => {
  if (summary === null) return null;
  const down = /^.+? is down(?:: |$)/u.exec(summary);
  return down ? summary.slice(down[0].length) || null : summary;
};
