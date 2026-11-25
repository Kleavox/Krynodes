import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { freshDb } from "../test/db";
import { addNode } from "../test/env";
import { intervals, loadStatus, uptime } from "./data";
import { serveStats, type StatsEnv } from "./index";
import { banner, formatDuration, LOCAL_TIMES } from "./page";

const DAY = 86_400_000;
const HOUR = 3_600_000;
const NOW = Date.parse("2026-09-28T12:00:00Z");
const TODAY = Date.parse("2026-09-28T00:00:00Z");
const NODE = "11111111-1111-4111-8111-111111111111";
const iso = (ms: number) => new Date(ms).toISOString();

const ALLOW = {
  limit: async () => ({ success: true }),
} as unknown as RateLimit;

const UNREADABLE = {
  prepare() {
    throw new Error("D1 was read");
  },
} as unknown as D1Database;

async function fleet() {
  const db = freshDb();
  await addNode(db, NODE, "server-1-secret-node");
  const statements: string[] = [];
  const DB = {
    prepare: (sql: string) => {
      statements.push(sql);
      return db.prepare(sql);
    },
    batch: db.batch.bind(db),
  } as unknown as D1Database;
  const env: StatsEnv = { DB, STATS_RATE_LIMIT: ALLOW };
  const status = () => loadStatus(DB, NOW);
  return { db, env, statements, status };
}

async function publish(
  db: D1Database,
  id: string,
  fields: {
    name: string;
    note?: string | null;
    public?: boolean;
    container?: string;
  },
) {
  await db
    .prepare(
      "INSERT INTO checks (id, node_id, container, name, public, note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(
      id,
      NODE,
      fields.container ?? `web-app-${id}`,
      fields.name,
      fields.public === false ? 0 : 1,
      fields.note ?? null,
      iso(NOW - 200 * DAY),
    )
    .run();
}

async function transition(
  db: D1Database,
  id: string,
  state: "up" | "down" | "gone" | "unknown",
  at: number,
  cause: "owner" | "offline" | null = null,
) {
  await db.batch([
    db
      .prepare("UPDATE checks SET state = ?, cause = ?, since = ? WHERE id = ?")
      .bind(state, cause, iso(at), id),
    db
      .prepare(
        "INSERT INTO check_transitions (check_id, state, cause, at) VALUES (?, ?, ?, ?)",
      )
      .bind(id, state, cause, iso(at)),
  ]);
}

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
  env: StatsEnv,
  path = "/",
  init?: RequestInit,
  options: { now?: number; cache?: Cache } = {},
): Promise<Response> {
  return serveStats(new Request(`https://stats.test${path}`, init), env, {
    now: options.now ?? NOW,
    cache: options.cache,
  });
}

describe("the status page's states and bars", () => {
  it("a check up all day shows 100%", async () => {
    const { db, env, status } = await fleet();
    await publish(db, "a", { name: "Website" });
    await transition(db, "a", "up", NOW - 2 * DAY);

    const [service] = (await status()).services;
    expect(service!.state).toBe("up");
    expect(service!.recentUptime).toBe(100);
    expect(service!.uptime).toBe(100);
    expect(service!.recent).toHaveLength(24);
    expect(service!.recent[0]!.start).toBe(NOW - DAY);
    expect(service!.recent.every((bar) => bar.state === "up")).toBe(true);
    expect(service!.days).toHaveLength(90);
    expect(service!.days[0]!.start).toBe(TODAY - 89 * DAY);
    expect(service!.days.slice(87).every((bar) => bar.state === "up")).toBe(
      true,
    );
    expect(
      service!.days.slice(0, 87).every((bar) => bar.state === "nodata"),
    ).toBe(true);

    const html = await (await visit(env)).text();
    expect(html).toContain("All Systems Operational");
    expect(html).toContain(">100.00% uptime</span>");
  });

  it("a check down for six hours shows 75% and a red bar for those hours", async () => {
    const { db, env, status } = await fleet();
    await publish(db, "a", { name: "Website" });
    await transition(db, "a", "up", NOW - 2 * DAY);
    await transition(db, "a", "down", NOW - 12 * HOUR);
    await transition(db, "a", "up", NOW - 6 * HOUR);

    const [service] = (await status()).services;
    expect(service!.state).toBe("up");
    expect(service!.recentUptime).toBe(75);
    expect(service!.recent.map((bar) => bar.state)).toEqual([
      ...Array<string>(12).fill("up"),
      ...Array<string>(6).fill("down"),
      ...Array<string>(6).fill("up"),
    ]);
    expect(service!.recentInfo).toEqual({
      since: NOW - DAY,
      downMs: 6 * HOUR,
      lastDown: NOW - 12 * HOUR,
    });
    expect(service!.days[89]).toMatchObject({
      state: "partial",
      downMs: 6 * HOUR,
    });

    const html = await (await visit(env)).text();
    expect(html).toContain(">75.00% uptime</span>");
    expect(html).toContain(
      '<span class="bar bar-down" data-tip="00:00–01:00 UTC · Down 1h"',
    );
    expect(html).toContain(
      'data-tip="Since Sun, 27 Sep 12:00 UTC\nDown 6h\nLast Down 00:00 UTC"',
    );
  });

  it("the owner's stop shows paused, not down", async () => {
    const { db, env, status } = await fleet();
    await publish(db, "a", { name: "Website" });
    await transition(db, "a", "up", NOW - 2 * DAY);
    await transition(db, "a", "down", NOW - 6 * HOUR, "owner");

    const [service] = (await status()).services;
    expect(service!.state).toBe("paused");
    expect(service!.recentUptime).toBe(100);
    expect(
      service!.recent.slice(18).every((bar) => bar.state === "paused"),
    ).toBe(true);
    expect(service!.recent.some((bar) => bar.state === "down")).toBe(false);
    expect(service!.days.some((bar) => bar.state === "down")).toBe(false);

    const html = await (await visit(env)).text();
    expect(html).toContain('<span class="state state-paused">Paused</span>');
    expect(html).not.toContain("banner banner-down");
    expect(html).not.toContain("bar bar-down");
  });

  it("a check with no transition yet shows no data", async () => {
    const { db, env, status } = await fleet();
    await publish(db, "a", { name: "Website" });

    const [service] = (await status()).services;
    expect(service!.state).toBe("nodata");
    expect(service!.uptime).toBeNull();
    expect(service!.recentUptime).toBeNull();
    expect(service!.recent.every((bar) => bar.state === "nodata")).toBe(true);
    expect(service!.days.every((bar) => bar.state === "nodata")).toBe(true);

    const html = await (await visit(env)).text();
    expect(html).toContain("No Recent Data");
    expect(html).toContain(">-- uptime</span>");
    expect(html).not.toContain("0.00%");
    expect(html).toContain('data-tip="11:00–12:00 UTC · No Data"');
  });

  it("a removed container shows no data", async () => {
    const { db, status } = await fleet();
    await publish(db, "a", { name: "Website" });
    await transition(db, "a", "up", NOW - 2 * DAY);
    await transition(db, "a", "gone", NOW - 2 * HOUR, "owner");

    const [service] = (await status()).services;
    expect(service!.state).toBe("nodata");
    expect(
      service!.recent.slice(22).every((bar) => bar.state === "nodata"),
    ).toBe(true);
  });

  it("a server that went offline shows no data from when it left, never up", async () => {
    const { db, env, status } = await fleet();
    await publish(db, "a", { name: "Website" });
    await transition(db, "a", "up", NOW - 2 * DAY);
    await transition(db, "a", "unknown", NOW - 3 * HOUR, "offline");

    const [service] = (await status()).services;
    expect(service!.state).toBe("nodata");
    expect(
      service!.recent.slice(0, 21).every((bar) => bar.state === "up"),
    ).toBe(true);
    expect(
      service!.recent.slice(21).every((bar) => bar.state === "nodata"),
    ).toBe(true);
    expect(service!.recentUptime).toBe(100);

    const html = await (await visit(env)).text();
    expect(html).toContain('<span class="state state-nodata">No data</span>');
    expect(html).not.toContain("All Systems Operational");
    expect(html).not.toContain("state state-up");
  });

  it("shows the hours a server was away as no data after it returns", async () => {
    const { db, status } = await fleet();
    await publish(db, "a", { name: "Website" });
    await transition(db, "a", "up", NOW - 2 * DAY);
    await transition(db, "a", "unknown", NOW - 10 * HOUR, "offline");
    await transition(db, "a", "up", NOW - 6 * HOUR);

    const [service] = (await status()).services;
    expect(service!.state).toBe("up");
    expect(service!.recent.map((bar) => bar.state)).toEqual([
      ...Array<string>(14).fill("up"),
      ...Array<string>(4).fill("nodata"),
      ...Array<string>(6).fill("up"),
    ]);
    expect(service!.recentUptime).toBe(100);
    expect(service!.days[89]!.state).toBe("up");
  });

  it("never calls the fleet all clear while one server is silent", () => {
    const service = (state: "up" | "down" | "nodata" | "paused") => ({
      name: state,
      note: null,
      state,
      uptime: 100,
      days: [],
      recent: [],
      recentUptime: null,
      recentInfo: { since: 0, downMs: 0, lastDown: null },
      longInfo: { since: 0, downMs: 0, lastDown: null },
    });
    expect(banner([]).text).toBe("Nothing to Show Yet");
    expect(banner([service("up"), service("paused")]).text).toBe(
      "All Systems Operational",
    );
    expect(banner([service("up"), service("nodata")])).toEqual({
      text: "1 service has no recent data",
      tone: "nodata",
    });
    expect(banner([service("down"), service("nodata")]).text).toBe(
      "1 service down",
    );
    expect(banner([service("down"), service("down")]).text).toBe(
      "2 services down",
    );
    expect(banner([service("nodata"), service("paused")]).text).toBe(
      "No Recent Data",
    );
  });

  it("carries the state from before the window into its first day", async () => {
    const { db, status } = await fleet();
    await publish(db, "a", { name: "Website" });
    await transition(db, "a", "up", NOW - 150 * DAY);
    await transition(db, "a", "down", NOW - 100 * DAY);
    await transition(db, "a", "up", TODAY - 89 * DAY + 6 * HOUR);

    const [service] = (await status()).services;
    expect(service!.days[0]).toMatchObject({
      state: "partial",
      downMs: 6 * HOUR,
    });
    expect(service!.uptime).toBeCloseTo(
      (1 - (6 * HOUR) / (89 * DAY + 12 * HOUR)) * 100,
      6,
    );
  });

  it("measures uptime over the time a check was up or down", () => {
    const list = intervals(
      [
        { state: "up", cause: null, at: 0 },
        { state: "down", cause: null, at: 3 * HOUR },
        { state: "down", cause: "owner", at: 4 * HOUR },
        { state: "gone", cause: null, at: 5 * HOUR },
        { state: "up", cause: null, at: 6 * HOUR },
      ],
      8 * HOUR,
    );
    expect(list).toEqual([
      { start: 0, end: 3 * HOUR, state: "up" },
      { start: 3 * HOUR, end: 4 * HOUR, state: "down" },
      { start: 4 * HOUR, end: 5 * HOUR, state: "paused" },
      { start: 6 * HOUR, end: 8 * HOUR, state: "up" },
    ]);
    expect(uptime(list, 0, 10 * HOUR)).toBeCloseTo((5 / 6) * 100, 6);
    expect(uptime(list, 4 * HOUR, 6 * HOUR)).toBeNull();
  });
});

describe("serveStats", () => {
  it("only public checks and their notes are shown", async () => {
    const { db, env } = await fleet();
    await publish(db, "a", {
      name: "Website",
      note: "Main website",
      container: "web-app-secret-1",
    });
    await publish(db, "b", {
      name: "Hidden",
      note: "Private note",
      public: false,
    });
    await transition(db, "a", "down", NOW - HOUR);
    await transition(db, "b", "down", NOW - HOUR);

    const html = await (await visit(env)).text();
    expect(html).toContain("Website");
    expect(html).toContain('<p class="note">Main website</p>');
    expect(html).toContain("1 service down");
    for (const secret of [
      "Hidden",
      "Private note",
      "web-app-secret-1",
      "web-app-b",
      "server-1-secret-node",
      NODE,
    ]) {
      expect(html).not.toContain(secret);
    }
  });

  it("escapes names and notes in text and attributes", async () => {
    const { db, env } = await fleet();
    await publish(db, "a", {
      name: "<script>alert(1)</script>",
      note: '"quoted" & <b>',
    });
    const html = await (await visit(env)).text();
    expect(html).not.toContain("<script>alert");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).toContain("&quot;quoted&quot; &amp; &lt;b&gt;");
  });

  it("serves the page with its cache and security headers", async () => {
    const { db, env } = await fleet();
    await publish(db, "a", { name: "Website", note: "Main website" });
    await transition(db, "a", "up", NOW - 2 * DAY);
    const response = await visit(env);
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
    expect(html).toContain('content="600;url=/?r=1"');
    expect(html).not.toContain("Updates paused");
    expect(html).toContain(
      "--bg:#0c0c10;--card:#14141a;--border:#282831;--fg:#ececf1;--muted:#92929f;--up:#5dcb9a;--partial:#ebba62;--down:#ed7477",
    );
    expect(html).toContain(".bar-up{background:rgba(93,203,154,.85)}");
    expect(html).toContain('<meta name="robots" content="noindex, nofollow">');
    const favicon = readFileSync(
      new URL("../../../tooling/vite-config/favicon.svg", import.meta.url),
      "utf8",
    ).trim();
    expect(html).toContain(
      `<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,${encodeURIComponent(favicon)}">`,
    );
    expect(html).toContain('<label for="range-day">24 Hours</label>');
    expect(html).toContain('<label for="range-90">90 Days</label>');
    expect(html).toContain(
      'data-tip="11:00–12:00 UTC · Up" data-local="{w:1790593200000}–{c:1790596800000} · Up"',
    );
    expect(html).toContain('data-tip="Mon, 28 Sep · Up"');
    expect(html).toContain(
      'tabindex="0" data-tip="Since Sun, 27 Sep 12:00 UTC\nNo Downtime Recorded" data-local="Since {w:1790510400000}\nNo Downtime Recorded">100.00% uptime</span>',
    );
    expect(html).not.toMatch(/incident/iu);
  });

  it("shows times in the visitor's time zone, with UTC for browsers without script", async () => {
    const { db, env } = await fleet();
    await publish(db, "a", { name: "Website" });
    const response = await visit(env);
    const html = await response.text();
    const script = /<script>([\s\S]*?)<\/script>/u.exec(html)?.[1] ?? "";
    expect(script).toBe(LOCAL_TIMES);
    const digest = createHash("sha256").update(script).digest("base64");
    expect(response.headers.get("content-security-policy")).toContain(
      `script-src 'sha256-${digest}'`,
    );
    expect(html).toContain(
      '<time datetime="2026-09-28T12:00:00.000Z" data-local="{t:1790596800000}">28 Sep 2026, 12:00 UTC</time>',
    );
    expect(html).toContain('<span data-zone="">Times are UTC.</span>');
  });

  it("fills the templates with the browser's zone", () => {
    const elements = [
      {
        tagName: "SPAN",
        attributes: {
          "data-local": "{c:1790593200000}–{c:1790595000000} · Up",
        },
      },
      {
        tagName: "TIME",
        attributes: { "data-local": "{t:1790586000000}" },
        textContent: "",
      },
      {
        tagName: "SPAN",
        attributes: { "data-local": "Last Down {w:1790586000000}" },
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
      "18:00–18:30 · Up",
    );
    expect(elements[1]!.textContent).toBe("28 Sep 2026, 16:00");
    expect(elements[2]!.attributes["data-tip" as never]).toBe(
      "Last Down 16:00",
    );
    expect(zone.textContent).toBe(
      "Times are in your time zone (Asia/Jakarta).",
    );
  });

  it("formats durations compactly", () => {
    expect(formatDuration(30_000)).toBe("<1m");
    expect(formatDuration(14 * 60_000)).toBe("14m");
    expect(formatDuration(HOUR)).toBe("1h");
    expect(formatDuration(2 * HOUR + 5 * 60_000)).toBe("2h 5m");
    expect(formatDuration(3 * DAY + 4 * HOUR)).toBe("3d 4h");
  });

  it("refuses a visitor over the limit before reading D1", async () => {
    const limiter = {
      limit: async () => ({ success: false }),
    } as unknown as RateLimit;
    const response = await serveStats(
      new Request("https://stats.test/"),
      { DB: UNREADABLE, STATS_RATE_LIMIT: limiter } as unknown as StatsEnv,
      { now: NOW },
    );
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

  it("runs only SELECT statements", async () => {
    const { db, env, statements } = await fleet();
    await publish(db, "a", { name: "Website" });
    await transition(db, "a", "up", NOW - 2 * DAY);
    await visit(env, "/", undefined, { cache: memoryCache() });
    expect(statements.length).toBeGreaterThan(0);
    expect(statements.every((sql) => /^\s*SELECT\b/iu.test(sql))).toBe(true);
  });

  it("reads transitions through the index instead of scanning the table", async () => {
    const { db, env, statements } = await fleet();
    await publish(db, "a", { name: "Website" });
    await visit(env);
    const query = statements.find((sql) => sql.includes("check_transitions"))!;
    const plan = (
      await db
        .prepare(`EXPLAIN QUERY PLAN ${query}`)
        .bind(iso(NOW))
        .all<{ detail: string }>()
    ).results
      .map((row) => row.detail)
      .join(" | ");
    expect(plan).not.toMatch(/SCAN (TABLE )?(check_transitions|t|p)\b/u);
    expect(plan).toMatch(/USING (COVERING )?INDEX check_transitions_check_at/u);
  });

  it("an unchanged page answers 304", async () => {
    const { db, env, statements } = await fleet();
    await publish(db, "a", { name: "Website" });
    await transition(db, "a", "up", NOW - 2 * DAY);
    const cache = memoryCache();
    const first = await visit(env, "/", undefined, { cache });
    const etag = first.headers.get("etag");
    expect(etag).toMatch(/^"[0-9a-f]{24}-\d+-0"$/u);
    expect(await first.text()).toContain("Website");

    statements.length = 0;
    const again = await visit(
      env,
      "/",
      { headers: { "If-None-Match": etag! } },
      {
        now: NOW + 60_000,
        cache,
      },
    );
    expect(again.status).toBe(304);
    expect(await again.text()).toBe("");
    expect(again.headers.get("etag")).toBe(etag);

    const weak = await visit(
      env,
      "/",
      { headers: { "If-None-Match": `W/${etag}` } },
      { now: NOW + 60_000, cache },
    );
    expect(weak.status).toBe(304);
    expect(statements).toHaveLength(1);
    expect(statements[0]).toContain("FROM checks WHERE public = 1");

    const round = await visit(
      env,
      "/?r=1",
      { headers: { "If-None-Match": etag! } },
      { now: NOW + 60_000, cache },
    );
    expect(round.status).toBe(200);

    await transition(db, "a", "down", NOW + 70_000);
    const changed = await visit(
      env,
      "/",
      { headers: { "If-None-Match": etag! } },
      { now: NOW + 100_000, cache },
    );
    expect(changed.status).toBe(200);
    expect(await changed.text()).toContain("1 service down");
  });

  it("serves the cached page while nothing changed, reading only the version", async () => {
    const { db, env, statements } = await fleet();
    await publish(db, "a", { name: "Website" });
    const cache = memoryCache();
    const first = await visit(env, "/", undefined, { cache });
    expect(first.headers.get("cache-control")).toBe("no-cache");
    expect(await first.text()).toContain("Website");

    statements.length = 0;
    const again = await visit(env, "/", undefined, {
      now: NOW + 240_000,
      cache,
    });
    expect(await again.text()).toContain("Website");
    expect(statements).toHaveLength(1);
    expect(statements[0]).toContain("FROM checks WHERE public = 1");

    const head = await visit(
      env,
      "/?r=1",
      { method: "HEAD" },
      {
        now: NOW + 240_000,
        cache,
      },
    );
    expect(head.status).toBe(200);
    expect(await head.text()).toBe("");
  });

  it("asks the database at most twice a minute while the page is busy", async () => {
    const { db, env, statements } = await fleet();
    await publish(db, "a", { name: "Website" });
    const cache = memoryCache();
    await visit(env, "/", undefined, { cache });
    statements.length = 0;
    for (let index = 1; index <= 20; index++) {
      await visit(env, "/", undefined, { now: NOW + index * 1_000, cache });
    }
    expect(statements).toHaveLength(0);
    await visit(env, "/", undefined, { now: NOW + 31_000, cache });
    expect(statements).toHaveLength(1);
  });

  it("re-renders at once when a public check changes, is published or its server leaves", async () => {
    const { db, env } = await fleet();
    await publish(db, "a", { name: "Website" });
    await transition(db, "a", "up", NOW - 2 * DAY);
    const cache = memoryCache();
    await visit(env, "/", undefined, { cache });

    await db.prepare("UPDATE checks SET name = 'Renamed' WHERE id = 'a'").run();
    const renamed = await visit(env, "/", undefined, {
      now: NOW + 60_000,
      cache,
    });
    expect(await renamed.text()).toContain("Renamed");

    await db
      .prepare("UPDATE checks SET note = 'New note' WHERE id = 'a'")
      .run();
    const noted = await visit(env, "/", undefined, {
      now: NOW + 120_000,
      cache,
    });
    expect(await noted.text()).toContain("New note");

    await publish(db, "b", { name: "Mail" });
    const published = await visit(env, "/?r=1", undefined, {
      now: NOW + 180_000,
      cache,
    });
    expect(await published.text()).toContain("Mail");

    await transition(db, "a", "unknown", NOW + 200_000, "offline");
    const left = await visit(env, "/", undefined, {
      now: NOW + 240_000,
      cache,
    });
    expect(await left.text()).not.toContain("state state-up");
  });

  it("re-renders a copy older than five minutes", async () => {
    const { db, env, statements } = await fleet();
    await publish(db, "a", { name: "Website" });
    const cache = memoryCache();
    await visit(env, "/", undefined, { cache });
    statements.length = 0;
    await visit(env, "/", undefined, { now: NOW + 301_000, cache });
    expect(statements.length).toBeGreaterThan(1);
  });

  it("refreshes twice, then pauses with a way to resume", async () => {
    const { db, env } = await fleet();
    await publish(db, "a", { name: "Website" });
    const page = async (query: string) =>
      (await visit(env, `/${query}`)).text();

    const second = await page("?r=1");
    expect(second).toContain('content="600;url=/?r=2"');
    expect(second).not.toContain("Updates paused");

    const paused = await page("?r=2");
    expect(paused).not.toContain('http-equiv="refresh"');
    expect(paused).toContain("Updates paused");
    expect(paused).toContain("stopped refreshing after 20 minutes");
    expect(paused).toContain("28 Sep 2026, 12:00 UTC");
    expect(paused).toContain('<a class="resume" href="/">Resume Updates</a>');
    expect(paused).toContain("Website");

    for (const odd of ["?r=abc", "?r=-5", "?r=1.5x"]) {
      expect(await page(odd)).toContain('content="600;url=/?r=1"');
    }
    expect(await page("?r=99")).toContain("Updates paused");
    for (const html of [second, paused]) {
      expect(html).not.toContain("<!--");
    }
  });

  it("answers only / and only GET or HEAD", async () => {
    const { env } = await fleet();
    expect((await visit(env, "/admin")).status).toBe(404);
    const post = await visit(env, "/", { method: "POST" });
    expect(post.status).toBe(405);
    expect(post.headers.get("allow")).toBe("GET, HEAD");
    const head = await visit(env, "/", { method: "HEAD" });
    expect(head.status).toBe(200);
    expect(await head.text()).toBe("");
  });
});
