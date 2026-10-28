import { describe, expect, it } from "vitest";

import { app } from "../app";
import type { Env } from "../env";
import {
  OWNER,
  seedCheck,
  seedIncident,
  seedNode,
  seedResult,
  sqliteTime,
} from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";
import { CHECK_RESULTS_SQL } from "./check-results";

type Results = {
  windowSeconds: number;
  from: string;
  checks: Record<
    string,
    {
      results: {
        t: string;
        status: string;
        latencyMs: number | null;
        message: string | null;
      }[];
    }
  >;
  nodes: Record<
    string,
    { quiet: { from: string; to: string | null; why: string }[] }
  >;
};

async function results(db: D1Database): Promise<Results> {
  const response = await app.request(
    "https://kry.example.test/api/checks/results",
    {},
    { DB: db } as unknown as Env,
  );
  expect(response.status).toBe(200);
  return (await response.json()) as Results;
}

const ago = (milliseconds: number) =>
  new Date(Date.now() - milliseconds).toISOString();

function setup() {
  const { db, sqlite } = createTestDb();
  seedNode(sqlite, { id: "n1" });
  seedCheck(sqlite, { id: "c1", nodeId: "n1" });
  return { db, sqlite };
}

describe("GET /api/checks/results", () => {
  it("returns the windows of the last four hours and the two before, oldest first", async () => {
    const { db, sqlite } = setup();
    for (let index = 0; index < 60; index += 1) {
      seedResult(sqlite, "c1", ago(index * 300_000 + 30_000), "UP", index);
    }

    const body = await results(db);
    expect(body.windowSeconds).toBe(300);
    const entry = body.checks.c1!;
    const oldest =
      (Math.floor((Date.now() - 4 * 3_600_000) / 300_000) - 2) * 300_000;
    expect(Date.parse(entry.results[0]!.t)).toBe(oldest);
    expect(entry.results.length).toBeGreaterThanOrEqual(50);
    expect(entry.results.at(-1)?.latencyMs).toBe(0);
  });

  it("names when each server went quiet instead of a percentage", async () => {
    const { db, sqlite } = setup();
    for (const minutes of [5, 10, 30, 35]) {
      seedResult(sqlite, "c1", ago(minutes * 60_000), "UP");
    }
    const start = (minutes: number) =>
      new Date(
        Math.floor((Date.now() - minutes * 60_000) / 300_000) * 300_000,
      ).toISOString();

    const body = await results(db);
    expect(body.checks.c1).not.toHaveProperty("up4h");
    expect(body.nodes.n1?.quiet).toEqual([
      { from: body.from, to: start(35), why: "offline" },
      {
        from: new Date(Date.parse(start(30)) + 300_000).toISOString(),
        to: start(10),
        why: "offline",
      },
    ]);
  });

  it("names a quarantine as a quiet span of its own server only", async () => {
    const { db, sqlite } = setup();
    seedNode(sqlite, { id: "n2" });
    const at = ago(30 * 60_000);
    sqlite
      .prepare(
        "INSERT INTO quarantines (id, node_id, why, at, timeline) VALUES ('q1', 'n1', 'why', ?, '{}')",
      )
      .run(at);

    const body = await results(db);
    expect(body.nodes.n1?.quiet).toContainEqual({
      from: at,
      to: null,
      why: "quarantined",
    });
    expect(
      body.nodes.n2?.quiet.filter((span) => span.why === "quarantined"),
    ).toEqual([]);
  });

  it("leaves out a check whose results are all older than four hours", async () => {
    const { db, sqlite } = setup();
    seedResult(sqlite, "c1", ago(5 * 3_600_000), "UP");

    expect((await results(db)).checks.c1).toBeUndefined();
  });

  it("keeps another owner's checks out", async () => {
    const { db, sqlite } = setup();
    seedNode(sqlite, { id: "n2", owner: "other" });
    seedCheck(sqlite, { id: "c2", nodeId: "n2" });
    seedResult(sqlite, "c2", ago(60_000), "UP");

    expect((await results(db)).checks).toEqual({});
  });

  it("seeks the window primary key per server, not a table scan", async () => {
    const { db } = setup();
    const plan = await db
      .prepare(`EXPLAIN QUERY PLAN ${CHECK_RESULTS_SQL}`)
      .bind(OWNER, ago(4 * 3_600_000))
      .all<{ detail: string }>();
    const details = plan.results.map((row) => row.detail).join(" | ");
    expect(details).not.toMatch(/SCAN w\b/u);
    expect(details).toMatch(
      /SEARCH w USING PRIMARY KEY \(node_id=\? AND window_start>\?\)/u,
    );
  });
});

describe("GET /api/incidents/:id", () => {
  const open = (db: D1Database, id: string) =>
    app.request(`https://kry.example.test/api/incidents/${id}`, {}, {
      DB: db,
    } as unknown as Env);

  it("returns the incident with the results around it, newest first", async () => {
    const { db, sqlite } = setup();
    seedIncident(sqlite, {
      id: "i1",
      checkId: "c1",
      status: "OPEN",
      startedAt: sqliteTime(new Date(Date.now() - 30 * 60_000)),
    });
    seedResult(sqlite, "c1", ago(2 * 3_600_000), "UP");
    seedResult(sqlite, "c1", ago(35 * 60_000), "DOWN", null);
    seedResult(sqlite, "c1", ago(20 * 60_000), "DOWN", null);
    seedResult(sqlite, "c1", ago(10 * 60_000), "UP", 42);
    const response = await open(db, "i1");
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      incident: Record<string, unknown>;
      results: {
        status: string;
        latencyMs: number | null;
        message: string | null;
      }[];
    };
    expect(body.incident).toMatchObject({
      id: "i1",
      status: "OPEN",
      check_name: "c1",
      check_kind: "HTTP",
      check_target: "https://example.com/health",
      node_id: "n1",
    });
    expect(body.results.map((result) => result.status)).toEqual([
      "UP",
      "DOWN",
      "DOWN",
    ]);
    expect(body.results[1]).toMatchObject({
      latencyMs: null,
      message: "timeout",
    });
    const start = (minutes: number) =>
      Math.floor((Date.now() - minutes * 60_000) / 300_000) * 300_000;
    expect(
      (body as unknown as { quiet: { from: string; to: string }[] }).quiet,
    ).toContainEqual({
      from: new Date(start(35) + 300_000).toISOString(),
      to: new Date(start(20)).toISOString(),
      why: "offline",
    });
  });

  function umami() {
    const { db, sqlite } = createTestDb();
    seedNode(sqlite, { id: "n1" });
    sqlite
      .prepare(
        "INSERT INTO checks (id, node_id, name, kind, target) VALUES ('web', 'n1', 'Umami', 'HTTP', 'https://umami.example.test/')",
      )
      .run();
    sqlite
      .prepare(
        `INSERT INTO stacks (node_id, project, directory, running, total, compose, rollback, updated_at, containers)
         VALUES ('n1', 'umami', '/var/lib/kry-exec/compose/umami', 1, 2, 1, 1, datetime('now'), '["umami-app-1","umami-db-1"]')`,
      )
      .run();
    sqlite
      .prepare(
        `INSERT INTO web_addresses (hostname, node_id, project, service, port, mode, created_by, created_at)
         VALUES ('umami.example.test', 'n1', 'umami', 'app', 3000, 'allow', 'o', '2026-10-01')`,
      )
      .run();
    const opened = Date.now() - 30 * 60_000;
    const minutes = (offset: number) =>
      new Date(opened + offset * 60_000).toISOString();
    seedIncident(sqlite, {
      id: "i1",
      checkId: "web",
      status: "OPEN",
      startedAt: minutes(0),
    });
    const act = (
      id: string,
      kind: string,
      name: string,
      action: string,
      offset: number,
    ) =>
      sqlite
        .prepare(
          `INSERT INTO actions (id, batch_id, position, mode, node_id, kind, name, action, status, requested_by, requested_at)
           VALUES (?, ?, 0, 'rolling', 'n1', ?, ?, ?, 'done', 'o', ?)`,
        )
        .run(id, id, kind, name, action, minutes(offset));
    return { db, sqlite, minutes, act };
  }

  it("lists the actions on what its check watches, oldest first", async () => {
    const t = umami();
    t.act("deploy", "compose", "umami", "deploy", -2);
    t.act("blog", "compose", "blog", "restart", 5);
    t.act("reboot", "host", "server", "reboot", 10);
    t.act("logs", "compose", "umami", "logs", 12);
    t.act("old", "compose", "umami", "restart", -120);
    t.act("container", "docker", "umami-app-1", "restart", 15);
    const body = (await (await open(t.db, "i1")).json()) as {
      actions: { id: string }[];
    };
    expect(body.actions.map((action) => action.id)).toEqual([
      "deploy",
      "reboot",
      "container",
    ]);
  });

  it("tells its last good check before it opened", async () => {
    const t = umami();
    seedResult(t.sqlite, "web", t.minutes(-12), "UP", 192);
    seedResult(t.sqlite, "web", t.minutes(-2), "DOWN", null);
    seedResult(t.sqlite, "web", t.minutes(10), "UP", 40);
    const body = (await (await open(t.db, "i1")).json()) as {
      lastGood: { t: string; latencyMs: number | null } | null;
    };
    expect(body.lastGood?.latencyMs).toBe(192);
    const at = Date.parse(body.lastGood!.t);
    expect(at).toBeLessThan(Date.parse(t.minutes(0)));
    expect(at).toBeGreaterThan(Date.parse(t.minutes(-20)));
  });

  it("answers 404 for an unknown incident or someone else's", async () => {
    const { db, sqlite } = setup();
    seedNode(sqlite, { id: "n2", owner: "someone-else" });
    seedCheck(sqlite, { id: "c2", nodeId: "n2" });
    seedIncident(sqlite, {
      id: "i2",
      checkId: "c2",
      status: "RESOLVED",
      startedAt: sqliteTime(new Date()),
    });
    expect((await open(db, "missing")).status).toBe(404);
    expect((await open(db, "i2")).status).toBe(404);
  });
});

describe("GET /api/incidents/board", () => {
  const MINUTE = 60_000;
  function board() {
    const { db, sqlite } = createTestDb();
    seedNode(sqlite, { id: "n1" });
    seedNode(sqlite, { id: "n2", owner: "someone-else" });
    const check = (id: string, node: string, kind: string, target: string) =>
      sqlite
        .prepare(
          "INSERT INTO checks (id, node_id, name, kind, target) VALUES (?, ?, ?, ?, ?)",
        )
        .run(id, node, id, kind, target);
    const incident = (
      id: string,
      checkId: string,
      started: number,
      resolved: number | null,
    ) =>
      sqlite
        .prepare(
          `INSERT INTO incidents (id, check_id, status, started_at, resolved_at, summary)
           VALUES (?, ?, ?, ?, ?, 'down')`,
        )
        .run(
          id,
          checkId,
          resolved === null ? "OPEN" : "RESOLVED",
          ago(started),
          resolved === null ? null : ago(resolved),
        );
    const update = (incidentId: string, minutes: number) =>
      sqlite
        .prepare(
          `INSERT INTO incident_updates (id, incident_id, status, message, author, created_at)
           VALUES (?, ?, 'investigating', ?, ?, ?)`,
        )
        .run(
          crypto.randomUUID(),
          incidentId,
          `looking at it ${minutes}`,
          OWNER,
          ago(minutes * MINUTE),
        );
    const read = async () =>
      (await (
        await app.request("https://kry.example.test/api/incidents/board", {}, {
          DB: db,
        } as unknown as Env)
      ).json()) as {
        latest: Record<
          string,
          {
            at: string;
            updates: number;
            update: { message: string } | null;
            action: { id: string; status: string } | null;
          }
        >;
        last30: { count: number; downMs: number };
      };
    return { sqlite, check, incident, update, read };
  }

  it("gives each open incident its newest line and counts the updates", async () => {
    const t = board();
    t.check("pihole", "n1", "SERVICE", "pihole-FTL.service");
    t.sqlite
      .prepare(
        "INSERT INTO services (node_id, kind, name, state) VALUES ('n1', 'systemd', 'pihole-FTL.service', 'failed')",
      )
      .run();
    t.incident("i1", "pihole", 60 * MINUTE, null);
    t.update("i1", 50);
    t.update("i1", 40);
    const healed = ago(30 * MINUTE);
    t.sqlite
      .prepare(
        `INSERT INTO actions (id, batch_id, position, mode, node_id, kind, name, action, status, requested_by, requested_at, output)
         VALUES ('heal', 'heal', 0, 'rolling', 'n1', 'systemd', 'pihole-FTL.service', 'heal', 'failed', 'o', ?, 'port 53 is already allocated')`,
      )
      .run(healed);
    t.check("blog", "n1", "HTTP", "https://blog.example.test");
    t.incident("i2", "blog", 20 * MINUTE, null);
    t.update("i2", 5);
    t.check("theirs", "n2", "HTTP", "https://theirs.example.test");
    t.incident("i3", "theirs", 20 * MINUTE, null);
    const body = await t.read();
    expect(Object.keys(body.latest).sort()).toEqual(["i1", "i2"]);
    expect(body.latest.i1).toMatchObject({
      at: healed,
      updates: 2,
      update: null,
      action: { id: "heal", status: "failed" },
    });
    expect(body.latest.i2).toMatchObject({
      updates: 1,
      update: { message: "looking at it 5" },
      action: null,
    });
  });

  it("adds up the last 30 days, the open one up to now", async () => {
    const t = board();
    t.check("blog", "n1", "HTTP", "https://blog.example.test");
    t.incident("a", "blog", 3 * 86_400_000, 3 * 86_400_000 - 10 * MINUTE);
    t.incident("b", "blog", 2 * 86_400_000, 2 * 86_400_000 - 20 * MINUTE);
    t.incident("c", "blog", 86_400_000, 86_400_000 - 17 * MINUTE);
    t.incident("old", "blog", 40 * 86_400_000, 40 * 86_400_000 - MINUTE);
    t.incident("open", "blog", 10 * MINUTE, null);
    const { last30 } = await t.read();
    expect(last30.count).toBe(4);
    expect(last30.downMs).toBeGreaterThanOrEqual(57 * MINUTE);
    expect(last30.downMs).toBeLessThan(57 * MINUTE + 5_000);
  });
});
