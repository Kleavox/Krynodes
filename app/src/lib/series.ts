import type { QuietSpan } from "../types";
import { formatDuration, parseTimestamp, titleCase } from "./format";

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
  | "received"
  | "missed"
  | "pending"
  | "none"
  | "work"
  | "routine"
  | "offline"
  | "quarantined";

export interface Span {
  from: number;
  to: number;
}

export interface WorkSpan extends Span {
  label: string;
}

export const overlaps = (spans: Span[], start: number, size: number) =>
  spans.some((span) => span.from < start + size && span.to > start);

const quietOverlaps = (
  spans: QuietSpan[],
  why: QuietSpan["why"],
  start: number,
  size: number,
) =>
  overlaps(
    spans
      .filter((span) => span.why === why)
      .map((span) => ({
        from: parseTimestamp(span.from),
        to: span.to === null ? Infinity : parseTimestamp(span.to),
      })),
    start,
    size,
  );

interface LaidSlot<T> {
  start: number;
  state: SlotState;
  sample: T | null;
}

interface LayoutOptions<T> {
  slots: T[];
  slotSeconds: number;
  graceSeconds: number;
  settleSeconds?: number;
  since: number | null;
  now: number;
  asOf?: number;
  count?: number;
  work?: Span[];
  quiet?: QuietSpan[];
}

export function layoutReportSlots<T extends { t: string }>(
  options: LayoutOptions<T>,
): LaidSlot<T>[] {
  const count = options.count ?? 30;
  const reference = options.asOf ?? options.now;
  const size = options.slotSeconds * 1000;
  const current = Math.floor(options.now / size);
  const quiet = options.quiet ?? [];
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
          : quietOverlaps(quiet, "quarantined", start, size)
            ? "quarantined"
            : overlaps(options.work ?? [], start, size)
              ? "work"
              : quietOverlaps(quiet, "offline", start, size)
                ? "offline"
                : quietOverlaps(quiet, "routine", start, size)
                  ? "routine"
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
  | "up"
  | "down"
  | "brief"
  | "missed"
  | "work"
  | "routine"
  | "offline"
  | "quarantined"
  | "empty";

export function barTone(
  state: SlotState,
  status: "UP" | "DOWN" | null,
  inIncident: boolean,
  inWork = false,
): BarTone {
  if (status === "UP") return "up";
  if (status === "DOWN") {
    return inIncident ? "down" : inWork ? "work" : "brief";
  }
  if (
    state === "work" ||
    state === "routine" ||
    state === "offline" ||
    state === "quarantined" ||
    state === "missed"
  ) {
    return state;
  }
  return "empty";
}

interface HeartbeatSlot<T> extends LaidSlot<T> {
  tone: BarTone;
  work: WorkSpan | undefined;
}

export function heartbeatSlots<
  T extends { t: string; status: "UP" | "DOWN" },
  I extends { started_at: string; resolved_at: string | null },
>(
  options: Omit<LayoutOptions<T>, "work"> & {
    incidents: I[];
    work?: WorkSpan[];
  },
): (HeartbeatSlot<T> & { incident: I | undefined })[] {
  const size = options.slotSeconds * 1000;
  return layoutReportSlots(options).map((slot) => {
    const incident =
      slot.sample?.status === "DOWN"
        ? incidentDuring(slot.start, size, options.incidents)
        : undefined;
    const work = (options.work ?? []).find((span) =>
      overlaps([span], slot.start, size),
    );
    return {
      ...slot,
      incident,
      work,
      tone: barTone(
        slot.state,
        slot.sample?.status ?? null,
        Boolean(incident),
        Boolean(work),
      ),
    };
  });
}

const SLOT_WORDS: Record<BarTone, string> = {
  up: "Up",
  down: "Down",
  brief: "Down, no incident",
  work: "By You",
  routine: "Routine Restart",
  offline: "Offline",
  quarantined: "Quarantined",
  missed: "No Result",
  empty: "Not Measured",
};

export function slotTip(
  slot: {
    start: number;
    sample: { latencyMs: number | null } | null;
    work?: { label: string } | undefined;
  },
  tone: BarTone,
  clock: (value: number) => string,
): string {
  const latency = slot.sample?.latencyMs;
  return [
    clock(slot.start),
    tone === "work" && slot.work
      ? titleCase(`${slot.work.label} by you`)
      : SLOT_WORDS[tone],
    latency === null || latency === undefined ? null : `${latency}ms`,
  ]
    .filter(Boolean)
    .join(" · ");
}

export interface Uptime {
  percent: number | null;
  up: number;
  down: number;
  offline: number;
  routine: number;
  work: number;
  quarantined: number;
  since: number | null;
  lastDown: number | null;
}

export function uptimeOf(slots: { start: number; tone: BarTone }[]): Uptime {
  const count = (...tones: BarTone[]) =>
    slots.filter((slot) => tones.includes(slot.tone)).length;
  const up = count("up");
  const down = count("down", "brief");
  const offline = count("offline");
  const counted = up + down + offline;
  return {
    percent: counted === 0 ? null : (up / counted) * 100,
    up,
    down,
    offline,
    routine: count("routine"),
    work: count("work"),
    quarantined: count("quarantined"),
    since:
      slots.find((slot) => slot.tone !== "empty" && slot.tone !== "missed")
        ?.start ?? null,
    lastDown:
      slots.findLast((slot) => slot.tone === "down" || slot.tone === "brief")
        ?.start ?? null,
  };
}

export function uptimeTip(
  uptime: Uptime,
  windowMs: number,
  clock: (value: number) => string,
): string {
  if (uptime.since === null) return "No Reports Yet";
  const counted = uptime.up + uptime.down + uptime.offline;
  const span = (windows: number) => formatDuration(windows * windowMs);
  return [
    `Since ${clock(uptime.since)}`,
    `${uptime.up} of ${counted} ${counted === 1 ? "window" : "windows"} up`,
    uptime.offline > 0 ? `Offline ${span(uptime.offline)}` : null,
    uptime.routine > 0
      ? `Routine Restart ${span(uptime.routine)}, not counted`
      : null,
    uptime.work > 0 ? `Restart by You ${span(uptime.work)}, not counted` : null,
    uptime.quarantined > 0
      ? `Quarantined ${span(uptime.quarantined)}, not counted`
      : null,
    uptime.lastDown !== null
      ? `Last Down ${clock(uptime.lastDown)}`
      : uptime.offline === 0
        ? "No Downtime Recorded"
        : null,
  ]
    .filter(Boolean)
    .join("\n");
}

export function heartbeatSummary(uptime: Uptime, span: string): string {
  if (uptime.since === null) return `No results in the last ${span}`;
  const skipped = uptime.routine + uptime.work + uptime.quarantined;
  return [
    `${uptime.up} up`,
    `${uptime.down} down`,
    uptime.offline > 0 ? `${uptime.offline} offline` : null,
    skipped > 0 ? `${skipped} not counted` : null,
  ]
    .filter(Boolean)
    .join(", ")
    .concat(` in the last ${span}`);
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
  return `Now ${format(last)}, min ${format(Math.min(...present))}, max ${format(Math.max(...present))}, average ${format(average)}`;
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

export function sparklineArea(segment: string, height = 28): string {
  const points = segment.split(" ");
  const x = (point: string) => point.split(",")[0];
  return `${x(points[0]!)},${height} ${segment} ${x(points.at(-1)!)},${height}`;
}

export function isLonePoint(values: (number | null)[], index: number): boolean {
  const measured = (at: number) =>
    values[at] !== null &&
    values[at] !== undefined &&
    Number.isFinite(values[at]);
  return measured(index) && !measured(index - 1) && !measured(index + 1);
}
