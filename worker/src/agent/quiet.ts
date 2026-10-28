import { REBOOT_MS } from "../actions/store";
import { windowSize } from "./windows";

export interface QuietSpan {
  from: string;
  to: string | null;
  why: "offline" | "routine" | "quarantined";
}

const iso = (ms: number) => new Date(ms).toISOString();

export function quietSpans(input: {
  windows: { start: number; uptimeSeconds: number | null }[];
  windowMs: number;
  from: number;
  now: number;
  lastSeen: number | null;
  graceMs: number;
  rebootHour: number | null;
  rebootPending: boolean;
}): QuietSpan[] {
  const { windowMs, rebootHour } = input;
  const inRestartHour = (start: number) =>
    rebootHour !== null &&
    [start, start - 1].some(
      (moment) => new Date(moment).getUTCHours() === rebootHour,
    );
  const spans: QuietSpan[] = [];
  const quiet = (start: number, end: number | null, routine: boolean) => {
    const cut = start + REBOOT_MS;
    if (!routine) {
      spans.push({
        from: iso(start),
        to: end === null ? null : iso(end),
        why: "offline",
      });
      return;
    }
    spans.push({
      from: iso(start),
      to: iso(end === null ? cut : Math.min(end, cut)),
      why: "routine",
    });
    if (end === null ? input.now > cut : end > cut) {
      spans.push({
        from: iso(cut),
        to: end === null ? null : iso(end),
        why: "offline",
      });
    }
  };
  const windows = [...input.windows].sort((a, b) => a.start - b.start);
  let reached = input.from;
  for (const window of windows) {
    if (window.start > reached) {
      const booted =
        window.uptimeSeconds !== null &&
        window.start + windowMs - window.uptimeSeconds * 1000 >=
          reached - windowMs;
      quiet(reached, window.start, booted && inRestartHour(reached));
    }
    reached = Math.max(reached, window.start + windowMs);
  }
  const { lastSeen, now } = input;
  if (lastSeen !== null && now - lastSeen > input.graceMs) {
    const start = Math.max(reached, lastSeen);
    quiet(start, null, input.rebootPending && inRestartHour(start));
  }
  return spans;
}

export function restartOf(security: string | null): {
  hour: number | null;
  pending: boolean;
} {
  try {
    const report = JSON.parse(security ?? "null") as {
      rebootHour?: number | null;
      findings?: { id: string }[];
    } | null;
    return {
      hour: report?.rebootHour ?? null,
      pending: (report?.findings ?? []).some(
        (finding) => finding.id === "reboot-pending",
      ),
    };
  } catch {
    return { hour: null, pending: false };
  }
}

const epochOf = (value: string) =>
  Date.parse(
    /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/u.test(value)
      ? `${value.replace(" ", "T")}Z`
      : value,
  );

function quarantinedSpans(
  quarantines: string | null | undefined,
  from: number,
): QuietSpan[] {
  try {
    const entries = JSON.parse(quarantines ?? "[]") as {
      at: string;
      releasedAt: string | null;
    }[];
    return entries
      .filter(
        (entry) =>
          entry.releasedAt === null || epochOf(entry.releasedAt) > from,
      )
      .map((entry) => ({
        from: iso(Math.max(epochOf(entry.at), from)),
        to: entry.releasedAt === null ? null : iso(epochOf(entry.releasedAt)),
        why: "quarantined" as const,
      }));
  } catch {
    return [];
  }
}

export function quietByNode(
  windows: {
    node_id: string;
    window_start: string;
    uptime_seconds: number | null;
  }[],
  nodes: {
    id: string;
    interval_seconds: number;
    last_seen_at: string | null;
    security: string | null;
    grace_seconds?: number;
    quarantines?: string | null;
  }[],
  from: number,
  now: number,
): Record<string, { quiet: QuietSpan[] }> {
  return Object.fromEntries(
    nodes.map((node) => {
      const restart = restartOf(node.security);
      return [
        node.id,
        {
          quiet: [
            ...quietSpans({
              windows: windows
                .filter((window) => window.node_id === node.id)
                .map((window) => ({
                  start: epochOf(window.window_start),
                  uptimeSeconds: window.uptime_seconds,
                })),
              windowMs: windowSize(node.interval_seconds),
              from,
              now,
              lastSeen: node.last_seen_at ? epochOf(node.last_seen_at) : null,
              graceMs:
                (node.grace_seconds ??
                  Math.max(90, 3 * node.interval_seconds)) * 1000,
              rebootHour: restart.hour,
              rebootPending: restart.pending,
            }),
            ...quarantinedSpans(node.quarantines, from),
          ],
        },
      ];
    }),
  );
}
