import { expandResults, staleAfterMs, type WindowRow } from "../agent/windows";

const DAY = 86_400_000;
const WINDOW_DAYS = 90;
const INCIDENT_DAYS = 30;
const STALE_MS = 180_000;
const SLOT_MS = 30 * 60_000;
const SLOTS = 48;

export type ServiceState = "up" | "down" | "nodata";
type DayState = "up" | "partial" | "down" | "none";
type SlotState = "up" | "partial" | "down" | "nodata" | "none";

export interface DayBar {
  start: number;
  state: DayState;
  downMs: number;
}

export interface SlotBar {
  start: number;
  state: SlotState;
  up: number;
  down: number;
}

export interface RecentInfo {
  since: number;
  up: number;
  total: number;
  lastDown: number | null;
}

export interface LongInfo {
  since: number;
  incidents: number;
  downMs: number;
  lastDown: number | null;
}

export interface Service {
  name: string;
  note: string | null;
  state: ServiceState;
  uptime: number | null;
  latencyMs: number | null;
  days: DayBar[];
  recent: SlotBar[];
  recentUptime: number | null;
  recentInfo: RecentInfo;
  longInfo: LongInfo;
}

interface PublicUpdate {
  status: string;
  message: string;
  at: number;
}

interface PublicIncident {
  name: string;
  startedAt: number;
  resolvedAt: number | null;
  updates: PublicUpdate[];
}

export interface StatusView {
  services: Service[];
  incidents: PublicIncident[];
}

interface Span {
  start: number;
  end: number;
}

interface Result {
  at: number;
  status: "UP" | "DOWN";
}

interface CheckRow {
  id: string;
  name: string;
  public_note: string | null;
  status: string;
  last_seen_at: string | null;
  created_at: string;
  interval_seconds: number | null;
}

interface IncidentRow {
  id: string;
  check_id: string;
  started_at: string;
  resolved_at: string | null;
}

interface UpdateRow {
  incident_id: string;
  status: string;
  message: string;
  created_at: string;
}

function toMs(value: string): number {
  return Date.parse(
    /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/u.test(value)
      ? `${value.replace(" ", "T")}Z`
      : value,
  );
}

function overlap(span: Span, from: number, to: number): number {
  return Math.max(0, Math.min(span.end, to) - Math.max(span.start, from));
}

function touches(span: Span, from: number, to: number): boolean {
  return span.start < to && (span.end > from || span.start >= from);
}

function windowStart(now: number): number {
  return Math.floor(now / DAY) * DAY - (WINDOW_DAYS - 1) * DAY;
}

export function dayBars(
  spans: Span[],
  createdAt: number,
  now: number,
): DayBar[] {
  const first = windowStart(now);
  return Array.from({ length: WINDOW_DAYS }, (_, index) => {
    const start = first + index * DAY;
    const end = Math.min(start + DAY, now);
    if (start + DAY <= createdAt) return { start, state: "none", downMs: 0 };
    const hit = spans.filter((span) => touches(span, start, end));
    const downMs = hit.reduce(
      (sum, span) => sum + overlap(span, start, end),
      0,
    );
    const monitored = end - Math.max(start, createdAt);
    return {
      start,
      state:
        hit.length === 0 ? "up" : downMs * 2 > monitored ? "down" : "partial",
      downMs,
    };
  });
}

export function uptime(
  spans: Span[],
  createdAt: number,
  now: number,
): number | null {
  const from = Math.max(windowStart(now), createdAt);
  if (now <= from) return null;
  const down = spans.reduce((sum, span) => sum + overlap(span, from, now), 0);
  return (1 - down / (now - from)) * 100;
}

export function longInfo(
  spans: Span[],
  createdAt: number,
  now: number,
): LongInfo {
  const since = Math.max(windowStart(now), createdAt);
  const seen = spans.filter((span) => touches(span, since, now));
  return {
    since,
    incidents: seen.length,
    downMs: seen.reduce((sum, span) => sum + overlap(span, since, now), 0),
    lastDown:
      seen.length > 0 ? Math.max(...seen.map((span) => span.start)) : null,
  };
}

export function recentBars(
  results: Result[],
  createdAt: number,
  now: number,
): SlotBar[] {
  const inSlot = (start: number) =>
    results.filter(
      (result) => result.at >= start && result.at < start + SLOT_MS,
    );
  const current = Math.floor(now / SLOT_MS) * SLOT_MS;
  const last = inSlot(current).length > 0 ? current : current - SLOT_MS;
  return Array.from({ length: SLOTS }, (_, index) => {
    const start = last - (SLOTS - 1 - index) * SLOT_MS;
    if (start + SLOT_MS <= createdAt) {
      return { start, state: "none", up: 0, down: 0 };
    }
    const hit = inSlot(start);
    const down = hit.filter((result) => result.status === "DOWN").length;
    const up = hit.length - down;
    return {
      start,
      state:
        down * 2 > up + down
          ? "down"
          : down > 0
            ? "partial"
            : up > 0
              ? "up"
              : "nodata",
      up,
      down,
    };
  });
}

export function recentInfo(results: Result[], since: number): RecentInfo {
  const counted = results.filter((result) => result.at >= since);
  const down = counted
    .filter((result) => result.status === "DOWN")
    .map((result) => result.at);
  return {
    since,
    up: counted.length - down.length,
    total: counted.length,
    lastDown: down.length > 0 ? Math.max(...down) : null,
  };
}

export function serviceState(
  status: string,
  lastSeenAt: string | null,
  now: number,
  staleMs = STALE_MS,
): ServiceState {
  if (!lastSeenAt || now - toMs(lastSeenAt) > staleMs) return "nodata";
  if (status === "UP") return "up";
  return status === "DOWN" ? "down" : "nodata";
}

export async function statusVersion(db: D1Database): Promise<string> {
  const row = await db
    .prepare(
      `SELECT COUNT(*) AS count, MAX(updated_at) AS changed,
         (SELECT COUNT(*) || ':' || COALESCE(MAX(created_at), '') FROM incident_updates) AS said
       FROM checks WHERE public = 1`,
    )
    .first<{ count: number; changed: string | null; said: string | null }>();
  return `${row?.count ?? 0}:${row?.changed ?? ""}:${row?.said ?? ""}`;
}

export async function loadStatus(
  db: D1Database,
  now: number,
): Promise<StatusView> {
  const since = new Date(windowStart(now)).toISOString();
  const recentSince = new Date(
    (Math.floor(now / SLOT_MS) - SLOTS) * SLOT_MS,
  ).toISOString();
  const [checks, incidents, results, updates] = await Promise.all([
    db
      .prepare(
        `SELECT c.id, c.name, c.public_note, c.status, n.last_seen_at, c.created_at,
                n.interval_seconds
         FROM checks c LEFT JOIN nodes n ON n.id = c.node_id
         WHERE c.public = 1 AND c.enabled = 1 ORDER BY c.name`,
      )
      .all<CheckRow>(),
    db
      .prepare(
        `SELECT i.id, i.check_id, i.started_at, i.resolved_at
         FROM incidents i
         WHERE i.check_id IN (SELECT id FROM checks WHERE public = 1 AND enabled = 1)
           AND (i.resolved_at IS NULL OR datetime(i.resolved_at) >= datetime(?))`,
      )
      .bind(since)
      .all<IncidentRow>(),
    db
      .prepare(
        `SELECT w.window_start, w.checks
         FROM node_windows w
         WHERE w.node_id IN (SELECT node_id FROM checks WHERE public = 1 AND enabled = 1)
           AND w.window_start >= ?`,
      )
      .bind(recentSince)
      .all<WindowRow>(),
    db
      .prepare(
        `SELECT u.incident_id, u.status, u.message, u.created_at
         FROM incident_updates u
         WHERE u.incident_id IN (
           SELECT i.id FROM incidents i
           WHERE i.check_id IN (SELECT id FROM checks WHERE public = 1 AND enabled = 1)
             AND (i.resolved_at IS NULL OR datetime(i.resolved_at) >= datetime(?)))
         ORDER BY u.created_at DESC, u.id DESC`,
      )
      .bind(new Date(now - INCIDENT_DAYS * DAY).toISOString())
      .all<UpdateRow>(),
  ]);
  const said = new Map<string, PublicUpdate[]>();
  for (const row of updates.results) {
    said.set(row.incident_id, [
      ...(said.get(row.incident_id) ?? []),
      { status: row.status, message: row.message, at: toMs(row.created_at) },
    ]);
  }

  const spans = new Map<string, Span[]>();
  for (const row of incidents.results) {
    const start = toMs(row.started_at);
    const end = row.resolved_at ? Math.max(start, toMs(row.resolved_at)) : now;
    spans.set(row.check_id, [
      ...(spans.get(row.check_id) ?? []),
      { start, end },
    ]);
  }
  const expanded = expandResults(
    results.results,
    new Set(checks.results.map((row) => row.id)),
  );
  const outcomes = new Map<string, Result[]>();
  const latency = new Map<string, number | null>();
  for (const [checkId, list] of expanded) {
    outcomes.set(
      checkId,
      list.map((result) => ({ at: toMs(result.t), status: result.status })),
    );
    latency.set(checkId, list.at(-1)?.latencyMs ?? null);
  }
  const names = new Map(checks.results.map((row) => [row.id, row.name]));

  return {
    services: checks.results.map((row) => {
      const own = spans.get(row.id) ?? [];
      const reports = outcomes.get(row.id) ?? [];
      const createdAt = toMs(row.created_at);
      const recent = recentBars(reports, createdAt, now);
      const info = recentInfo(reports, Math.max(recent[0]!.start, createdAt));
      return {
        name: row.name,
        note: row.public_note,
        state: serviceState(
          row.status,
          row.last_seen_at,
          now,
          staleAfterMs(row.interval_seconds ?? 60),
        ),
        uptime: uptime(own, createdAt, now),
        latencyMs: latency.get(row.id) ?? null,
        days: dayBars(own, createdAt, now),
        recent,
        recentUptime: info.total > 0 ? (info.up / info.total) * 100 : null,
        recentInfo: info,
        longInfo: longInfo(own, createdAt, now),
      };
    }),
    incidents: incidents.results
      .filter(
        (row) =>
          row.resolved_at === null ||
          toMs(row.started_at) >= now - INCIDENT_DAYS * DAY,
      )
      .map((row) => ({
        name: names.get(row.check_id) ?? "",
        startedAt: toMs(row.started_at),
        resolvedAt: row.resolved_at ? toMs(row.resolved_at) : null,
        updates: said.get(row.id) ?? [],
      }))
      .sort((a, b) => b.startedAt - a.startedAt),
  };
}
