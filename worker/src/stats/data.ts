const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const WINDOW_DAYS = 90;
const HOURS = 24;

export type ServiceState = "up" | "down" | "nodata" | "paused";
type BarState = "up" | "partial" | "down" | "paused" | "nodata";

export interface Interval {
  start: number;
  end: number;
  state: "up" | "down" | "paused";
}

export interface Bar {
  start: number;
  state: BarState;
  downMs: number;
}

export interface Summary {
  since: number;
  downMs: number;
  lastDown: number | null;
}

export interface Service {
  name: string;
  note: string | null;
  state: ServiceState;
  uptime: number | null;
  days: Bar[];
  recent: Bar[];
  recentUptime: number | null;
  recentInfo: Summary;
  longInfo: Summary;
}

export interface StatusView {
  services: Service[];
}

interface Transition {
  state: string;
  cause: string | null;
  at: number;
}

interface CheckRow {
  id: string;
  name: string;
  note: string | null;
  state: string;
  cause: string | null;
}

interface TransitionRow {
  id: number;
  check_id: string;
  state: string;
  cause: string | null;
  at: string;
}

function stateOf(state: string, cause: string | null): ServiceState {
  if (state === "up") return "up";
  if (state === "down") return cause === "owner" ? "paused" : "down";
  return "nodata";
}

export function intervals(
  transitions: Transition[],
  until: number,
): Interval[] {
  return transitions.flatMap((transition, index) => {
    const state = stateOf(transition.state, transition.cause);
    const end = Math.min(transitions[index + 1]?.at ?? until, until);
    return state === "nodata" || end <= transition.at
      ? []
      : [{ start: transition.at, end, state }];
  });
}

function spent(
  list: Interval[],
  from: number,
  to: number,
  state: Interval["state"],
): number {
  return list
    .filter((interval) => interval.state === state)
    .reduce(
      (sum, interval) =>
        sum +
        Math.max(
          0,
          Math.min(interval.end, to) - Math.max(interval.start, from),
        ),
      0,
    );
}

export function uptime(
  list: Interval[],
  from: number,
  to: number,
): number | null {
  const up = spent(list, from, to, "up");
  const down = spent(list, from, to, "down");
  return up + down > 0 ? (up / (up + down)) * 100 : null;
}

function bar(list: Interval[], start: number, end: number): Bar {
  const up = spent(list, start, end, "up");
  const downMs = spent(list, start, end, "down");
  const state: BarState =
    downMs * 2 > up + downMs
      ? "down"
      : downMs > 0
        ? "partial"
        : up > 0
          ? "up"
          : spent(list, start, end, "paused") > 0
            ? "paused"
            : "nodata";
  return { start, state, downMs };
}

function windowStart(now: number): number {
  return Math.floor(now / DAY) * DAY - (WINDOW_DAYS - 1) * DAY;
}

function dayBars(list: Interval[], now: number): Bar[] {
  const first = windowStart(now);
  return Array.from({ length: WINDOW_DAYS }, (_, index) => {
    const start = first + index * DAY;
    return bar(list, start, Math.min(start + DAY, now));
  });
}

function hourBars(list: Interval[], now: number): Bar[] {
  const last = Math.ceil(now / HOUR) * HOUR - HOUR;
  return Array.from({ length: HOURS }, (_, index) => {
    const start = last - (HOURS - 1 - index) * HOUR;
    return bar(list, start, Math.min(start + HOUR, now));
  });
}

function summary(list: Interval[], from: number, to: number): Summary {
  const down = list.filter(
    (interval) =>
      interval.state === "down" && interval.start < to && interval.end > from,
  );
  return {
    since: from,
    downMs: spent(down, from, to, "down"),
    lastDown:
      down.length > 0
        ? Math.max(...down.map((interval) => interval.start))
        : null,
  };
}

async function digest(text: string): Promise<string> {
  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return [...new Uint8Array(hash).slice(0, 12)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function statusVersion(db: D1Database): Promise<string> {
  const { results } = await db
    .prepare(
      "SELECT id, name, note, state, cause, since FROM checks WHERE public = 1 ORDER BY id",
    )
    .all<Record<string, string | null>>();
  return digest(JSON.stringify(results.map((row) => Object.values(row))));
}

export async function loadStatus(
  db: D1Database,
  now: number,
): Promise<StatusView> {
  const since = new Date(windowStart(now)).toISOString();
  const [checks, transitions] = await Promise.all([
    db
      .prepare(
        "SELECT id, name, note, state, cause FROM checks WHERE public = 1 ORDER BY name, id",
      )
      .all<CheckRow>(),
    db
      .prepare(
        `SELECT t.id, t.check_id, t.state, t.cause, t.at
         FROM checks c JOIN check_transitions t ON t.check_id = c.id
         WHERE c.public = 1 AND t.at >= ?1
         UNION ALL
         SELECT t.id, t.check_id, t.state, t.cause, t.at
         FROM checks c JOIN check_transitions t ON t.id = (
           SELECT p.id FROM check_transitions p
           WHERE p.check_id = c.id AND p.at < ?1
           ORDER BY p.at DESC, p.id DESC LIMIT 1)
         WHERE c.public = 1`,
      )
      .bind(since)
      .all<TransitionRow>(),
  ]);
  const history = new Map<string, TransitionRow[]>();
  for (const row of transitions.results) {
    history.set(row.check_id, [...(history.get(row.check_id) ?? []), row]);
  }
  return {
    services: checks.results.map((row) => {
      const list = intervals(
        (history.get(row.id) ?? [])
          .sort((a, b) => Date.parse(a.at) - Date.parse(b.at) || a.id - b.id)
          .map((transition) => ({
            state: transition.state,
            cause: transition.cause,
            at: Date.parse(transition.at),
          })),
        now,
      );
      const recent = hourBars(list, now);
      const from = windowStart(now);
      return {
        name: row.name,
        note: row.note,
        state: stateOf(row.state, row.cause),
        uptime: uptime(list, from, now),
        days: dayBars(list, now),
        recent,
        recentUptime: uptime(list, recent[0]!.start, now),
        recentInfo: summary(list, recent[0]!.start, now),
        longInfo: summary(list, from, now),
      };
    }),
  };
}
