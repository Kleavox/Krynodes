import { parseTimestamp } from "./format";

export interface Gap {
  from: number;
  to: number;
}

export function findGaps(
  times: number[],
  limitSeconds: number,
  range: { from: number; to: number },
  trailingSlackSeconds = 0,
): Gap[] {
  const limit = limitSeconds * 1000;
  const first = times[0];
  const last = times.at(-1);
  if (first === undefined || last === undefined) {
    return [{ from: range.from, to: range.to }];
  }
  const gaps: Gap[] = [];
  if (first - range.from > limit) gaps.push({ from: range.from, to: first });
  for (let index = 1; index < times.length; index += 1) {
    const previous = times[index - 1]!;
    const current = times[index]!;
    if (current - previous > limit) gaps.push({ from: previous, to: current });
  }
  if (range.to - last > limit + trailingSlackSeconds * 1000) {
    gaps.push({ from: last, to: range.to });
  }
  return gaps;
}

export function withGapBreaks<T extends { time: number }>(
  rows: T[],
  gaps: Gap[],
  blank: (time: number) => T,
): T[] {
  const times = new Set(rows.map((row) => row.time));
  const breaks = gaps
    .filter((gap) => times.has(gap.from) && times.has(gap.to))
    .map((gap) => blank((gap.from + gap.to) / 2));
  return [...rows, ...breaks].sort((a, b) => a.time - b.time);
}

export type SlotState =
  "received" | "missed" | "pending" | "none" | "maintenance";

export interface Span {
  from: number;
  to: number;
}

export const overlaps = (spans: Span[], start: number, size: number) =>
  spans.some((span) => span.from < start + size && span.to > start);

interface LaidSlot<T> {
  start: number;
  state: SlotState;
  sample: T | null;
}

export function layoutReportSlots<T extends { t: string }>(options: {
  slots: T[];
  slotSeconds: number;
  graceSeconds: number;
  settleSeconds?: number;
  since: number | null;
  now: number;
  asOf?: number;
  count?: number;
  maintenance?: Span[];
}): LaidSlot<T>[] {
  const count = options.count ?? 30;
  const reference = options.asOf ?? options.now;
  const size = options.slotSeconds * 1000;
  const current = Math.floor(options.now / size);
  const bySlot = new Map(
    options.slots.map((sample) => [
      Math.floor(parseTimestamp(sample.t) / size),
      sample,
    ]),
  );
  const lay = (slot: number): LaidSlot<T> => {
    const start = slot * size;
    const sample = bySlot.get(slot) ?? null;
    const state: SlotState = sample
      ? "received"
      : options.since === null || start + size <= options.since
        ? "none"
        : reference - start <
            (options.graceSeconds + (options.settleSeconds ?? 0)) * 1000
          ? "pending"
          : overlaps(options.maintenance ?? [], start, size)
            ? "maintenance"
            : "missed";
    return { start, state, sample };
  };
  let last = current;
  while (lay(last).state === "pending") last -= 1;
  return Array.from({ length: count }, (_, index) =>
    lay(last - (count - 1 - index)),
  );
}

export function untilWindowSettles(
  now: number,
  windowMs = 300_000,
  settleMs = 45_000,
): number {
  const settled = Math.floor((now - settleMs) / windowMs) * windowMs + settleMs;
  return settled + windowMs - now;
}

const FIRST_FAILURE_LEAD_MS = 60_000;

export function incidentDuring<
  T extends { started_at: string; resolved_at: string | null },
>(start: number, windowMs: number, incidents: T[]): T | undefined {
  return incidents.find((incident) => {
    const from = parseTimestamp(incident.started_at) - FIRST_FAILURE_LEAD_MS;
    const to =
      incident.resolved_at === null
        ? Infinity
        : parseTimestamp(incident.resolved_at);
    return from < start + windowMs && to > start;
  });
}

export type BarTone =
  "up" | "down" | "brief" | "missed" | "maintenance" | "empty";

export function barTone(
  state: SlotState,
  status: "UP" | "DOWN" | null,
  inIncident: boolean,
  inMaintenance = false,
): BarTone {
  if (status === "UP") return "up";
  if (status === "DOWN") {
    return inIncident ? "down" : inMaintenance ? "maintenance" : "brief";
  }
  if (state === "maintenance") return "maintenance";
  return state === "missed" ? "missed" : "empty";
}

export function slotTip(
  start: number,
  result: { status: "UP" | "DOWN"; latencyMs: number | null } | null,
  brief: boolean,
  clock: (value: number) => string,
  maintenance = false,
): string {
  if (!result) {
    return `${clock(start)} · ${maintenance ? "maintenance" : "no result"}`;
  }
  return [
    clock(start),
    maintenance && result.status === "DOWN"
      ? "DOWN, maintenance"
      : brief
        ? "DOWN, no incident"
        : result.status,
    result.latencyMs === null ? null : `${result.latencyMs}ms`,
  ]
    .filter(Boolean)
    .join(" · ");
}

export function heartbeatSummary(
  statuses: ("UP" | "DOWN" | null)[],
  span: string,
): string {
  const up = statuses.filter((status) => status === "UP").length;
  const down = statuses.filter((status) => status === "DOWN").length;
  if (up + down === 0) return `No results in the last ${span}`;
  return `${up} up, ${down} down, ${statuses.length - up - down} without results in the last ${span}`;
}

export function uptimeTip(
  results: { t: string; status: "UP" | "DOWN" }[],
  clock: (value: string) => string,
): string {
  const [first] = results;
  if (!first) return "No reports yet";
  const up = results.filter((result) => result.status === "UP").length;
  const lastDown = results.findLast((result) => result.status === "DOWN");
  return [
    `Since ${clock(first.t)}`,
    `${up} of ${results.length} reports up`,
    lastDown ? `Last down ${clock(lastDown.t)}` : "No downtime recorded",
  ].join("\n");
}

export function seriesSummary(
  values: (number | null)[],
  format: (value: number) => string,
): string {
  const present = values.filter(
    (value): value is number => value !== null && Number.isFinite(value),
  );
  const last = present.at(-1);
  if (last === undefined) return "No data in this range";
  const average =
    present.reduce((sum, value) => sum + value, 0) / present.length;
  return `now ${format(last)}, min ${format(Math.min(...present))}, max ${format(Math.max(...present))}, average ${format(average)}`;
}

const round = (value: number) => Math.round(value * 100) / 100;

export function sparklineSegments(
  values: (number | null)[],
  max: number,
  width = 100,
  height = 28,
): string[] {
  const step = values.length > 1 ? width / (values.length - 1) : 0;
  const top = max > 0 ? max : 1;
  const segments: string[] = [];
  let current: string[] = [];
  const close = () => {
    if (current.length === 1) current.push(current[0]!);
    if (current.length > 0) segments.push(current.join(" "));
    current = [];
  };
  values.forEach((value, index) => {
    if (value === null || !Number.isFinite(value)) {
      close();
      return;
    }
    const clamped = Math.min(Math.max(value, 0), top);
    current.push(
      `${round(index * step)},${round(height - (clamped / top) * height)}`,
    );
  });
  close();
  return segments;
}

export function isLonePoint(values: (number | null)[], index: number): boolean {
  const measured = (at: number) =>
    values[at] !== null &&
    values[at] !== undefined &&
    Number.isFinite(values[at]);
  return measured(index) && !measured(index - 1) && !measured(index + 1);
}
