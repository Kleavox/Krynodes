import type { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import { seedCheck, seedNode, seedResult } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";
import {
  dayBars,
  loadStatus,
  longInfo,
  recentBars,
  recentInfo,
  serviceState,
  statusVersion,
  uptime,
} from "./data";
import { serveStats, type StatsEnv } from "./index";
import { banner, formatDuration, LOCAL_TIMES } from "./page";

const DAY = 86_400_000;
const HOUR = 3_600_000;
const NOW = Date.parse("2026-09-28T12:00:00Z");
const TODAY = Date.parse("2026-09-28T00:00:00Z");
const LONG_AGO = NOW - 200 * DAY;
const NODE = "11111111-1111-4111-8111-111111111111";

function publish(
  sqlite: DatabaseSync,
  id: string,
  fields: {
    name: string;
    note?: string | null;
    status?: string;
    lastCheckedAt?: string | null;
    createdAt?: string;
    enabled?: boolean;
    public?: boolean;
  },
): void {
  seedCheck(sqlite, { id, nodeId: NODE });
  sqlite
    .prepare(
      `UPDATE checks SET name = ?, public = ?, public_note = ?, status = ?,
         last_checked_at = ?, created_at = ?, enabled = ?
       WHERE id = ?`,
    )
    .run(
      fields.name,
      fields.public === false ? 0 : 1,
      fields.note ?? null,
      fields.status ?? "UP",
      fields.lastCheckedAt === undefined
        ? "2026-09-28T11:59:30.000Z"
        : fields.lastCheckedAt,
      fields.createdAt ?? "2026-01-01 00:00:00",
      fields.enabled === false ? 0 : 1,
      id,
    );
}

function incident(
  sqlite: DatabaseSync,
  checkId: string,
  startedAt: string,
  resolvedAt: string | null,
): void {
  sqlite
    .prepare(
      `INSERT INTO incidents (id, check_id, status, started_at, resolved_at, summary)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .run(
      crypto.randomUUID(),
      checkId,
      resolvedAt ? "RESOLVED" : "OPEN",
      startedAt,
      resolvedAt,
      `${checkId} is down: dial tcp 10.0.0.5:22: connection refused`,
    );
}

function fleet() {
  const { db, sqlite } = createTestDb();
  seedNode(sqlite, { id: NODE });
  sqlite
    .prepare("UPDATE nodes SET last_seen_at = ? WHERE id = ?")
    .run("2026-09-28 11:59:30", NODE);
  return { db, sqlite };
}

function recordStatements(sqlite: DatabaseSync): string[] {
  const statements: string[] = [];
  const prepare = sqlite.prepare.bind(sqlite);
  sqlite.prepare = ((sql: string) => {
    statements.push(sql);
    return prepare(sql);
  }) as typeof sqlite.prepare;
  return statements;
}

describe("daily bars and uptime", () => {
  it("shows 90 green days and 100% without incidents", () => {
    const bars = dayBars([], LONG_AGO, NOW);
    expect(bars).toHaveLength(90);
    expect(bars[0]!.start).toBe(TODAY - 89 * DAY);
    expect(bars.every((bar) => bar.state === "up")).toBe(true);
    expect(uptime([], LONG_AGO, NOW)).toBe(100);
  });

  it("splits an incident across midnight", () => {
    const spans = [{ start: TODAY - HOUR, end: TODAY + HOUR }];
    const bars = dayBars(spans, LONG_AGO, NOW);
    expect(bars[87]!.state).toBe("up");
    expect(bars[88]).toMatchObject({ state: "partial", downMs: HOUR });
    expect(bars[89]).toMatchObject({ state: "partial", downMs: HOUR });
    expect(uptime(spans, LONG_AGO, NOW)).toBeCloseTo(
      (1 - (2 * HOUR) / (89 * DAY + 12 * HOUR)) * 100,
      6,
    );
  });

  it("greys the days before the check existed and measures uptime from its creation", () => {
    const createdAt = TODAY - 10 * DAY + 6 * HOUR;
    const spans = [{ start: NOW - 2 * HOUR, end: NOW - HOUR }];
    const bars = dayBars(spans, createdAt, NOW);
    expect(bars.slice(0, 79).every((bar) => bar.state === "none")).toBe(true);
    expect(bars[79]!.state).toBe("up");
    expect(uptime(spans, createdAt, NOW)).toBeCloseTo(
      (1 - HOUR / (NOW - createdAt)) * 100,
      6,
    );
  });

  it("marks the day of an instant incident without adding downtime", () => {
    const at = TODAY - DAY + 5_000;
    const bars = dayBars([{ start: at, end: at }], LONG_AGO, NOW);
    expect(bars[88]).toMatchObject({ state: "partial", downMs: 0 });
    expect(bars[89]!.state).toBe("up");
  });

  it("measures uptime over the same days the bars show", () => {
    const spans = [
      {
        start: TODAY - 90 * DAY + 13 * HOUR,
        end: TODAY - 90 * DAY + 14 * HOUR,
      },
    ];
    expect(uptime(spans, LONG_AGO, NOW)).toBe(100);
    expect(
      dayBars(spans, LONG_AGO, NOW).every((bar) => bar.state === "up"),
    ).toBe(true);
  });

  it("clips an incident that began before the window", () => {
    const spans = [{ start: NOW - 100 * DAY, end: NOW - 89 * DAY }];
    expect(uptime(spans, LONG_AGO, NOW)).toBeCloseTo(
      (1 - (12 * HOUR) / (89 * DAY + 12 * HOUR)) * 100,
      6,
    );
    expect(dayBars(spans, LONG_AGO, NOW)[0]).toMatchObject({
      state: "partial",
      downMs: 12 * HOUR,
    });
  });

  it("colors a day orange until most of its monitored time was down", () => {
    const MIN = 60_000;
    const yesterday = TODAY - DAY;
    const day = (start: number, end: number, createdAt = LONG_AGO) =>
      dayBars([{ start, end }], createdAt, NOW);
    expect(day(yesterday, yesterday + 12 * HOUR)[88]!.state).toBe("partial");
    expect(day(yesterday, yesterday + 12 * HOUR + MIN)[88]!.state).toBe("down");
    expect(day(TODAY, TODAY + 6 * HOUR + MIN)[89]!.state).toBe("down");
    expect(
      day(
        yesterday + 20 * HOUR,
        yesterday + 22 * HOUR + MIN,
        yesterday + 20 * HOUR,
      )[88]!.state,
    ).toBe("down");
  });

  it("summarizes the 90 days behind the uptime", () => {
    const spans = [
      { start: NOW - 120 * DAY, end: NOW - 119 * DAY },
      { start: NOW - 100 * DAY, end: NOW - 89 * DAY },
      { start: NOW - 2 * DAY, end: NOW - 2 * DAY + 14 * 60_000 },
      { start: NOW - HOUR / 2, end: NOW },
    ];
    expect(longInfo(spans, LONG_AGO, NOW)).toEqual({
      since: TODAY - 89 * DAY,
      incidents: 3,
      downMs: 12 * HOUR + 14 * 60_000 + HOUR / 2,
      lastDown: NOW - HOUR / 2,
    });
    const createdAt = TODAY - 10 * DAY + 6 * HOUR;
    expect(longInfo([], createdAt, NOW)).toEqual({
      since: createdAt,
      incidents: 0,
      downMs: 0,
      lastDown: null,
    });
  });
});

describe("24-hour bars", () => {
  const MIN = 60_000;
  const every = (from: number, to: number, status: "UP" | "DOWN" = "UP") =>
    Array.from({ length: Math.floor((to - from) / (5 * MIN)) }, (_, i) => ({
      at: from + i * 5 * MIN,
      status,
    }));

  it("fills 48 half-hour bars from a day of results and leaves out the slot still waiting", () => {
    const bars = recentBars(every(NOW - DAY, NOW), LONG_AGO, NOW);
    expect(bars).toHaveLength(48);
    expect(bars[47]!.start).toBe(NOW - 30 * MIN);
    expect(bars[0]!.start).toBe(NOW - DAY);
    expect(bars.every((bar) => bar.state === "up")).toBe(true);
    expect(bars[47]).toMatchObject({ up: 6, down: 0 });
  });

  it("ends at the current slot once it has a result", () => {
    const later = NOW + 10 * MIN;
    const bars = recentBars(every(NOW - DAY, later), LONG_AGO, later);
    expect(bars[47]!.start).toBe(NOW);
  });

  it("marks down slots, silent slots, and slots before the check existed", () => {
    const results = [
      ...every(NOW - 3 * HOUR, NOW - 2 * HOUR),
      { at: NOW - 90 * MIN, status: "DOWN" as const },
      { at: NOW - 85 * MIN, status: "UP" as const },
      ...every(NOW - 30 * MIN, NOW),
    ];
    const bars = recentBars(results, NOW - 3 * HOUR, NOW);
    const at = (start: number) => bars.find((bar) => bar.start === start)!;
    expect(at(NOW - 4 * HOUR).state).toBe("none");
    expect(at(NOW - 3 * HOUR).state).toBe("up");
    expect(at(NOW - 90 * MIN)).toMatchObject({
      state: "partial",
      up: 1,
      down: 1,
    });
    expect(at(NOW - 60 * MIN).state).toBe("nodata");
  });

  it("colors a slot orange until most of its results are down", () => {
    const slot = (down: number, total = 6) =>
      recentBars(
        Array.from({ length: total }, (_, i) => ({
          at: NOW - 30 * MIN + i * 5 * MIN,
          status: i < down ? ("DOWN" as const) : ("UP" as const),
        })),
        LONG_AGO,
        NOW,
      )[47]!.state;
    expect(slot(0)).toBe("up");
    expect(slot(1)).toBe("partial");
    expect(slot(3)).toBe("partial");
    expect(slot(4)).toBe("down");
    expect(slot(6)).toBe("down");
    expect(slot(1, 1)).toBe("down");
  });

  it("summarizes the results behind the uptime from where the bars begin", () => {
    const down = new Set([
      NOW - DAY - 10 * MIN,
      NOW - 95 * MIN,
      NOW - 3 * HOUR,
    ]);
    const results = every(NOW - DAY - 30 * MIN, NOW).map((result) => ({
      at: result.at,
      status: down.has(result.at) ? ("DOWN" as const) : ("UP" as const),
    }));
    expect(recentInfo(results, NOW - DAY)).toEqual({
      since: NOW - DAY,
      up: 286,
      total: 288,
      lastDown: NOW - 95 * MIN,
    });
    expect(recentInfo([], NOW - DAY)).toEqual({
      since: NOW - DAY,
      up: 0,
      total: 0,
      lastDown: null,
    });
  });
});

describe("serviceState", () => {
  it("reads both timestamp formats and treats silence as no data", () => {
    expect(serviceState("UP", "2026-09-28 11:58:30", NOW)).toBe("up");
    expect(serviceState("DOWN", "2026-09-28T11:59:00.000Z", NOW)).toBe("down");
    expect(serviceState("UP", "2026-09-28T11:56:59.000Z", NOW)).toBe("nodata");
    expect(serviceState("UP", null, NOW)).toBe("nodata");
    expect(serviceState("UNKNOWN", "2026-09-28T11:59:00.000Z", NOW)).toBe(
      "nodata",
    );
  });

  it("gives a streaming server a window and two reports before no data", () => {
    expect(serviceState("UP", "2026-09-28T11:54:00.000Z", NOW, 420_000)).toBe(
      "up",
    );
    expect(serviceState("UP", "2026-09-28T11:52:59.000Z", NOW, 420_000)).toBe(
      "nodata",
    );
  });
});

describe("loadStatus", () => {
  it("judges freshness by the server's last report, not the check's last change", async () => {
    const { db, sqlite } = fleet();
    publish(sqlite, "a", {
      name: "Steady",
      lastCheckedAt: "2026-09-28T10:00:00.000Z",
    });
    publish(sqlite, "b", {
      name: "Down",
      status: "DOWN",
      lastCheckedAt: "2026-09-28T11:00:00.000Z",
    });
    expect(
      (await loadStatus(db, NOW)).services.map((service) => service.state),
    ).toEqual(["down", "up"]);
    sqlite
      .prepare("UPDATE nodes SET last_seen_at = ? WHERE id = ?")
      .run("2026-09-28 11:50:00", NODE);
    expect(
      (await loadStatus(db, NOW)).services.map((service) => service.state),
    ).toEqual(["nodata", "nodata"]);
  });

  it("reads incidents through the public checks instead of scanning the table", async () => {
    const { db, sqlite } = fleet();
    const statements: string[] = [];
    const prepare = sqlite.prepare.bind(sqlite);
    sqlite.prepare = ((sql: string) => {
      statements.push(sql);
      return prepare(sql);
    }) as typeof sqlite.prepare;
    await loadStatus(db, NOW);
    const query = statements.find((sql) => sql.includes("incidents"));
    const plan = prepare(`EXPLAIN QUERY PLAN ${query}`)
      .all()
      .map((row) => String(row.detail))
      .join(" | ");
    expect(plan).not.toMatch(/SCAN (TABLE )?(incidents|i)\b/u);
    expect(plan).toMatch(/SEARCH (TABLE )?(incidents|i) USING INDEX/u);

    const recent = statements.find((sql) => sql.includes("node_windows"));
    const recentPlan = prepare(`EXPLAIN QUERY PLAN ${recent}`)
      .all()
      .map((row) => String(row.detail))
      .join(" | ");
    expect(recentPlan).not.toMatch(/SCAN (TABLE )?(node_windows|w)\b/u);
    expect(recentPlan).toMatch(
      /SEARCH (TABLE )?(node_windows|w) USING PRIMARY KEY \(node_id=\? AND window_start>\?\)/u,
    );

    statements.length = 0;
    await statusVersion(db);
    const versionPlan = prepare(`EXPLAIN QUERY PLAN ${statements[0]}`)
      .all()
      .map((row) => String(row.detail))
      .join(" | ");
    expect(versionPlan).toMatch(/COVERING INDEX idx_checks_public_updated/u);
  });

  it("builds the 24-hour bars and uptime from the public checks' results", async () => {
    const { db, sqlite } = fleet();
    publish(sqlite, "a", { name: "Website" });
    publish(sqlite, "b", { name: "Hidden", public: false });
    for (let minutes = 5; minutes <= 24 * 60; minutes += 5) {
      const at = new Date(NOW - minutes * 60_000).toISOString();
      seedResult(sqlite, "a", at, minutes === 60 ? "DOWN" : "UP");
      seedResult(sqlite, "b", at, "DOWN");
    }
    const [service] = (await loadStatus(db, NOW)).services;
    expect(service!.recent).toHaveLength(48);
    expect(
      service!.recent.filter((bar) => bar.state === "partial"),
    ).toHaveLength(1);
    expect(service!.recent.filter((bar) => bar.state === "up")).toHaveLength(
      47,
    );
    expect(service!.recentUptime).toBeCloseTo((287 / 288) * 100, 6);
    expect(service!.recentInfo).toEqual({
      since: NOW - DAY,
      up: 287,
      total: 288,
      lastDown: NOW - HOUR,
    });
  });

  it("counts only the results the 24-hour bars show", async () => {
    const { db, sqlite } = fleet();
    publish(sqlite, "a", { name: "Website" });
    const later = NOW + 10 * 60_000;
    for (let minutes = 5; minutes <= 24 * 60 + 10; minutes += 5) {
      const at = new Date(later - minutes * 60_000).toISOString();
      seedResult(sqlite, "a", at, minutes > 24 * 60 ? "DOWN" : "UP");
    }
    const [service] = (await loadStatus(db, later)).services;
    expect(service!.recent[0]!.start).toBe(NOW - DAY + 30 * 60_000);
    expect(service!.recentUptime).toBe(100);
    expect(service!.recentInfo).toMatchObject({
      since: NOW - DAY + 30 * 60_000,
      lastDown: null,
    });
  });

  it("starts the 24-hour summary when a newer check was created", async () => {
    const { db, sqlite } = fleet();
    publish(sqlite, "a", { name: "Website", createdAt: "2026-09-28 09:47:00" });
    const [service] = (await loadStatus(db, NOW)).services;
    expect(service!.recentInfo.since).toBe(Date.parse("2026-09-28T09:47:00Z"));
  });

  it("returns only public, enabled checks with their incidents, newest first", async () => {
    const { db, sqlite } = fleet();
    publish(sqlite, "a", { name: "Website", note: "Main website" });
    publish(sqlite, "b", { name: "Hidden", public: false });
    publish(sqlite, "c", { name: "Paused", enabled: false });
    incident(
      sqlite,
      "a",
      "2026-09-26T10:00:00.000Z",
      "2026-09-26T10:14:00.000Z",
    );
    incident(sqlite, "a", "2026-09-28T11:30:00.000Z", null);
    incident(
      sqlite,
      "a",
      "2026-08-19T10:00:00.000Z",
      "2026-08-19T11:00:00.000Z",
    );
    incident(sqlite, "b", "2026-09-28T11:00:00.000Z", null);
    incident(sqlite, "c", "2026-09-27T11:00:00.000Z", null);

    const view = await loadStatus(db, NOW);

    expect(view.services.map((service) => service.name)).toEqual(["Website"]);
    expect(view.services[0]).toMatchObject({
      note: "Main website",
      state: "up",
    });
    expect(view.services[0]!.days[89]!.state).toBe("partial");
    expect(view.services[0]!.days[89 - 40]!.state).toBe("partial");
    expect(view.incidents).toEqual([
      {
        name: "Website",
        startedAt: Date.parse("2026-09-28T11:30:00.000Z"),
        resolvedAt: null,
      },
      {
        name: "Website",
        startedAt: Date.parse("2026-09-26T10:00:00.000Z"),
        resolvedAt: Date.parse("2026-09-26T10:14:00.000Z"),
      },
    ]);
  });
});

const ALLOW = {
  limit: async () => ({ success: true }),
} as unknown as RateLimit;

const UNREADABLE = {
  prepare() {
    throw new Error("D1 was read");
  },
} as unknown as D1Database;

function memoryCache(): Cache {
  const store = new Map<string, Response>();
  return {
    match: async (request: Request) => store.get(request.url)?.clone(),
    put: async (request: Request, response: Response) => {
      store.set(request.url, response);
    },
  } as unknown as Cache;
}

function visit(
  db: D1Database,
  path = "/",
  init?: RequestInit,
  limiter: RateLimit = ALLOW,
): Promise<Response> {
  const env: StatsEnv = { DB: db, STATS_RATE_LIMIT: limiter };
  return serveStats(new Request(`https://stats.test${path}`, init), env, {
    now: NOW,
  });
}

describe("formatDuration and banner", () => {
  it("formats durations compactly", () => {
    expect(formatDuration(30_000)).toBe("<1m");
    expect(formatDuration(14 * 60_000)).toBe("14m");
    expect(formatDuration(HOUR)).toBe("1h");
    expect(formatDuration(2 * HOUR + 5 * 60_000)).toBe("2h 5m");
    expect(formatDuration(3 * DAY + 4 * HOUR)).toBe("3d 4h");
  });

  it("sums up the services in one line", () => {
    const service = (state: "up" | "down" | "nodata") => ({
      name: state,
      note: null,
      state,
      uptime: 100,
      latencyMs: null,
      days: [],
      recent: [],
      recentUptime: null,
      recentInfo: { since: 0, up: 0, total: 0, lastDown: null },
      longInfo: { since: 0, incidents: 0, downMs: 0, lastDown: null },
    });
    expect(banner([]).text).toBe("Nothing to show yet");
    expect(banner([service("up"), service("nodata")]).text).toBe(
      "All systems operational",
    );
    expect(banner([service("down"), service("up")]).text).toBe(
      "1 service down",
    );
    expect(banner([service("down"), service("down")]).text).toBe(
      "2 services down",
    );
    expect(banner([service("nodata")]).text).toBe("No recent data");
  });
});

describe("serveStats", () => {
  it("serves the page with its cache and security headers", async () => {
    const { db, sqlite } = fleet();
    publish(sqlite, "a", { name: "Website", note: "Main website" });
    const response = await visit(db);
    const html = await response.text();
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe(
      "text/html; charset=utf-8",
    );
    expect(response.headers.get("cache-control")).toBe("no-cache");
    expect(response.headers.get("x-robots-tag")).toBe("noindex, nofollow");
    expect(response.headers.get("content-security-policy")).toContain(
      "img-src data:",
    );
    expect(response.headers.get("content-security-policy")).toContain(
      "default-src 'none'",
    );
    expect(html).toContain("All systems operational");
    expect(html).toContain("Website");
    expect(html).toContain("Main website");
    expect(html).toContain('content="600;url=/?r=1"');
    expect(html).not.toContain("Updates paused");
    expect(html).toContain('<meta name="robots" content="noindex, nofollow">');
    expect(html).toContain(
      '<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,',
    );
    expect(html).toContain("100.00% uptime");
    expect(html).toContain(
      '<input type="radio" name="range" id="range-day" class="range" checked>',
    );
    expect(html).toContain('<label for="range-day">24 hours</label>');
    expect(html).toContain('<label for="range-90">90 days</label>');
    expect(html).toContain("24 hours ago");
    expect(html).toContain("90 days ago");
    expect(html).toContain('data-tip="11:30–12:00 UTC · no data"');
    expect(html).toContain('data-tip="Mon, 28 Sep · no incidents"');
    expect(html).toContain(
      'tabindex="0" data-tip="Since Sun, 27 Sep 12:00 UTC\nNo reports yet" data-local="Since {w:1790510400000}\nNo reports yet">-- uptime</span>',
    );
    expect(html).toContain(
      'tabindex="0" data-tip="Since Wed, 1 Jul\nNo downtime recorded">100.00% uptime</span>',
    );
  });

  it("colors partial outages orange and explains each uptime on hover", async () => {
    const { db, sqlite } = fleet();
    publish(sqlite, "a", { name: "Website" });
    for (let minutes = 5; minutes <= 60; minutes += 5) {
      const at = new Date(NOW - minutes * 60_000).toISOString();
      seedResult(sqlite, "a", at, minutes === 45 ? "DOWN" : "UP");
    }
    incident(
      sqlite,
      "a",
      "2026-09-28T09:00:00.000Z",
      "2026-09-28T09:20:00.000Z",
    );
    const html = await (await visit(db)).text();
    expect(html).toContain(".bar-partial{background:var(--partial)}");
    expect(html).toContain(
      '<span class="bar bar-partial" data-tip="11:00–11:30 UTC · down 1 of 6" data-local="{w:1790593200000}–{c:1790595000000} · down 1 of 6">',
    );
    expect(html).toContain(
      '<span class="bar bar-partial" data-tip="Mon, 28 Sep · down 20m">',
    );
    expect(html).toContain(
      'tabindex="0" data-tip="Since Sun, 27 Sep 12:00 UTC\n11 of 12 reports up\nLast down 11:15 UTC" data-local="Since {w:1790510400000}\n11 of 12 reports up\nLast down {w:1790594100000}">91.66% uptime</span>',
    );
    expect(html).toContain(
      'tabindex="0" data-tip="Since Wed, 1 Jul\n1 incident, down 20m\nLast down Mon, 28 Sep 09:00 UTC" data-local="Since Wed, 1 Jul\n1 incident, down 20m\nLast down {d:1790586000000} {c:1790586000000}">99.98% uptime</span>',
    );
  });

  it("shows times in the visitor's time zone, with UTC for browsers without script", async () => {
    const { db, sqlite } = fleet();
    publish(sqlite, "a", { name: "Website" });
    incident(
      sqlite,
      "a",
      "2026-09-28T09:00:00.000Z",
      "2026-09-28T09:20:00.000Z",
    );
    const response = await visit(db);
    const html = await response.text();
    const script = /<script>([\s\S]*?)<\/script>/u.exec(html)?.[1] ?? "";
    expect(script).toBe(LOCAL_TIMES);
    const digest = createHash("sha256").update(script).digest("base64");
    expect(response.headers.get("content-security-policy")).toContain(
      `script-src 'sha256-${digest}'`,
    );
    expect(html).toContain(
      '<time datetime="2026-09-28T09:00:00.000Z" data-local="{t:1790586000000}">28 Sep 2026, 09:00 UTC</time>',
    );
    expect(html).toContain('<span data-zone="">Times are UTC.</span>');
  });

  it("fills the templates with the browser's zone", () => {
    const elements = [
      {
        tagName: "SPAN",
        attributes: {
          "data-local": "{c:1790593200000}–{c:1790595000000} · up",
        },
      },
      {
        tagName: "TIME",
        attributes: { "data-local": "{t:1790586000000}" },
        textContent: "",
      },
      {
        tagName: "SPAN",
        attributes: { "data-local": "Last down {w:1790586000000}" },
      },
    ].map((element) => ({
      ...element,
      getAttribute(name: string) {
        return (this.attributes as Record<string, string>)[name] ?? null;
      },
      setAttribute(name: string, value: string) {
        (this.attributes as Record<string, string>)[name] = value;
      },
    }));
    const zone = { textContent: "Times are UTC." };
    const document = {
      querySelectorAll: (selector: string) =>
        selector === "[data-local]" ? elements : [zone],
    };
    const RealFormat = Intl.DateTimeFormat;
    const intl = {
      DateTimeFormat(locale?: string, options?: Intl.DateTimeFormatOptions) {
        return locale === undefined
          ? { resolvedOptions: () => ({ timeZone: "Asia/Jakarta" }) }
          : RealFormat(locale, { ...options, timeZone: "Asia/Jakarta" });
      },
    };
    const clock = { now: () => Date.parse("2026-09-28T13:00:00Z") };
    new Function("document", "Intl", "Date", LOCAL_TIMES)(
      document,
      intl,
      Object.assign(function () {}, { now: clock.now }),
    );
    expect(elements[0]!.attributes["data-tip" as never]).toBe(
      "18:00–18:30 · up",
    );
    expect(elements[1]!.textContent).toBe("28 Sep 2026, 16:00");
    expect(elements[2]!.attributes["data-tip" as never]).toBe(
      "Last down 16:00",
    );
    expect(zone.textContent).toBe(
      "Times are in your time zone (Asia/Jakarta).",
    );
  });

  it("never shows what a check is, where it points, or its server", async () => {
    const { db, sqlite } = fleet();
    sqlite
      .prepare("UPDATE nodes SET name = 'pivox-secret-node' WHERE id = ?")
      .run(NODE);
    publish(sqlite, "a", { name: "Website", status: "DOWN" });
    sqlite
      .prepare(
        `UPDATE checks SET target = 'https://secret.internal:8443/health',
           last_message = 'dial tcp 10.0.0.5:22: connection refused'
         WHERE id = 'a'`,
      )
      .run();
    incident(sqlite, "a", "2026-09-28T11:30:00.000Z", null);
    const html = await (await visit(db)).text();
    expect(html).toContain("1 service down");
    for (const secret of [
      "secret.internal",
      "10.0.0.5",
      "pivox-secret-node",
      "HTTP",
      "connection refused",
    ]) {
      expect(html).not.toContain(secret);
    }
  });

  it("escapes names and notes in text and attributes", async () => {
    const { db, sqlite } = fleet();
    publish(sqlite, "a", {
      name: "<script>alert(1)</script>",
      note: '"quoted" & <b>',
    });
    const html = await (await visit(db)).text();
    expect(html).not.toContain("<script>alert");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).toContain("&quot;quoted&quot; &amp; &lt;b&gt;");
  });

  it("says No data when the server behind a check stops reporting", async () => {
    const { db, sqlite } = fleet();
    publish(sqlite, "a", { name: "Website" });
    sqlite
      .prepare("UPDATE nodes SET last_seen_at = ? WHERE id = ?")
      .run("2026-09-28 11:50:00", NODE);
    const html = await (await visit(db)).text();
    expect(html).toContain("No data");
    expect(html).toContain("No recent data");
  });

  it("lists incidents with their durations and without their messages", async () => {
    const { db, sqlite } = fleet();
    publish(sqlite, "a", { name: "Website" });
    incident(
      sqlite,
      "a",
      "2026-09-26T10:00:00.000Z",
      "2026-09-26T10:14:00.000Z",
    );
    incident(sqlite, "a", "2026-09-28T11:30:00.000Z", null);
    const html = await (await visit(db)).text();
    expect(html).toContain("Ongoing for 30m");
    expect(html).toContain("Resolved after 14m");
    expect(html).toContain("26 Sep 2026, 10:00 UTC");
    expect(html).not.toContain("refused");
  });

  it("refuses a visitor over the limit before reading D1", async () => {
    const db = UNREADABLE;
    const limiter = {
      limit: async () => ({ success: false }),
    } as unknown as RateLimit;
    const response = await visit(db, "/", undefined, limiter);
    expect(response.status).toBe(429);
    expect(response.headers.get("retry-after")).toBe("60");
  });

  it("fails closed when the rate limiter is missing", async () => {
    const response = await serveStats(
      new Request("https://stats.test/"),
      { DB: UNREADABLE } as unknown as StatsEnv,
      { now: NOW },
    );
    expect(response.status).toBe(503);
  });

  it("serves the cached page while nothing changed, reading only the version", async () => {
    const { db, sqlite } = fleet();
    publish(sqlite, "a", { name: "Website" });
    const cache = memoryCache();
    const env = { DB: db, STATS_RATE_LIMIT: ALLOW };
    const first = await serveStats(new Request("https://stats.test/"), env, {
      now: NOW,
      cache,
    });
    expect(first.headers.get("cache-control")).toBe("no-cache");
    expect(await first.text()).toContain("Website");

    const statements = recordStatements(sqlite);
    const again = await serveStats(new Request("https://stats.test/"), env, {
      now: NOW + 240_000,
      cache,
    });
    expect(await again.text()).toContain("Website");
    expect(statements).toHaveLength(1);
    expect(statements[0]).toContain("COUNT(*)");

    const head = await serveStats(
      new Request("https://stats.test/?r=1", { method: "HEAD" }),
      env,
      { now: NOW + 240_000, cache },
    );
    expect(head.status).toBe(200);
    expect(await head.text()).toBe("");
  });

  it("asks the database at most twice a minute while the page is busy", async () => {
    const { db, sqlite } = fleet();
    publish(sqlite, "a", { name: "Website" });
    const cache = memoryCache();
    const env = { DB: db, STATS_RATE_LIMIT: ALLOW };
    await serveStats(new Request("https://stats.test/"), env, {
      now: NOW,
      cache,
    });
    const statements = recordStatements(sqlite);
    for (let index = 1; index <= 20; index++) {
      await serveStats(new Request("https://stats.test/"), env, {
        now: NOW + index * 1_000,
        cache,
      });
    }
    expect(statements).toHaveLength(0);
    await serveStats(new Request("https://stats.test/"), env, {
      now: NOW + 31_000,
      cache,
    });
    expect(statements).toHaveLength(1);
  });

  it("re-renders at once when a public check changes or a new one is published", async () => {
    const { db, sqlite } = fleet();
    publish(sqlite, "a", { name: "Website" });
    const cache = memoryCache();
    const env = { DB: db, STATS_RATE_LIMIT: ALLOW };
    await serveStats(new Request("https://stats.test/"), env, {
      now: NOW,
      cache,
    });

    sqlite
      .prepare(
        "UPDATE checks SET name = 'Renamed', updated_at = '2026-09-28 12:01:00' WHERE id = 'a'",
      )
      .run();
    const renamed = await serveStats(new Request("https://stats.test/"), env, {
      now: NOW + 60_000,
      cache,
    });
    expect(await renamed.text()).toContain("Renamed");

    publish(sqlite, "b", { name: "Mail" });
    const published = await serveStats(
      new Request("https://stats.test/?r=1"),
      env,
      { now: NOW + 120_000, cache },
    );
    expect(await published.text()).toContain("Mail");
  });

  it("re-renders a copy older than five minutes", async () => {
    const { db, sqlite } = fleet();
    publish(sqlite, "a", { name: "Website" });
    const cache = memoryCache();
    const env = { DB: db, STATS_RATE_LIMIT: ALLOW };
    await serveStats(new Request("https://stats.test/"), env, {
      now: NOW,
      cache,
    });
    const statements = recordStatements(sqlite);
    await serveStats(new Request("https://stats.test/"), env, {
      now: NOW + 301_000,
      cache,
    });
    expect(statements.length).toBeGreaterThan(1);
  });

  it("shows the latest latency of a service that is up", async () => {
    const { db, sqlite } = fleet();
    publish(sqlite, "a", { name: "Website" });
    publish(sqlite, "b", { name: "Mail", status: "DOWN" });
    seedResult(sqlite, "a", "2026-09-28T11:50:00.000Z", "UP", 80);
    seedResult(sqlite, "a", "2026-09-28T11:55:00.000Z", "UP", 42);
    seedResult(sqlite, "b", "2026-09-28T11:55:00.000Z", "DOWN", 999);
    const html = await (await visit(db)).text();
    expect(html).toContain("42 ms");
    expect(html).not.toContain("80 ms");
    expect(html).not.toContain("999 ms");
  });

  it("refreshes twice, then pauses with a way to resume", async () => {
    const { db, sqlite } = fleet();
    publish(sqlite, "a", { name: "Website" });
    const page = async (query: string) => (await visit(db, `/${query}`)).text();

    const second = await page("?r=1");
    expect(second).toContain('content="600;url=/?r=2"');
    expect(second).not.toContain("Updates paused");

    const paused = await page("?r=2");
    expect(paused).not.toContain('http-equiv="refresh"');
    expect(paused).toContain("Updates paused");
    expect(paused).toContain("stopped refreshing after 20 minutes");
    expect(paused).toContain("28 Sep 2026, 12:00 UTC");
    expect(paused).toContain('<a class="resume" href="/">Resume updates</a>');
    expect(paused).toContain("Website");

    for (const odd of ["?r=abc", "?r=-5", "?r=1.5x"]) {
      expect(await page(odd)).toContain('content="600;url=/?r=1"');
    }
    expect(await page("?r=99")).toContain("Updates paused");
    for (const html of [second, paused]) {
      expect(html).not.toContain("<!--");
    }
  });

  it("personalizes a cached copy with only the version query", async () => {
    const { db, sqlite } = fleet();
    publish(sqlite, "a", { name: "Website" });
    const cache = memoryCache();
    await serveStats(
      new Request("https://stats.test/"),
      { DB: db, STATS_RATE_LIMIT: ALLOW },
      { now: NOW, cache },
    );
    const statements = recordStatements(sqlite);
    const later = { DB: db, STATS_RATE_LIMIT: ALLOW };
    const next = await serveStats(
      new Request("https://stats.test/?r=1"),
      later,
      { now: NOW + 60_000, cache },
    );
    expect(await next.text()).toContain('content="600;url=/?r=2"');
    const paused = await serveStats(
      new Request("https://stats.test/?r=2"),
      later,
      { now: NOW + 120_000, cache },
    );
    expect(await paused.text()).toContain("Updates paused");
    expect(statements.every((sql) => sql.includes("COUNT(*)"))).toBe(true);
  });

  it("answers only / and only GET or HEAD", async () => {
    const { db } = fleet();
    expect((await visit(db, "/admin")).status).toBe(404);
    const post = await visit(db, "/", { method: "POST" });
    expect(post.status).toBe(405);
    expect(post.headers.get("allow")).toBe("GET, HEAD");
    const head = await visit(db, "/", { method: "HEAD" });
    expect(head.status).toBe(200);
    expect(await head.text()).toBe("");
  });
});
