import type { AgentHeartbeat, CheckResult } from "@krynodes/protocol";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { Env } from "../env";
import { FakeSocket, FakeStorage } from "../test/hub";
import { seedCheck, seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";
import { FleetHub } from "./hub";

const NODE = "11111111-1111-4111-8111-111111111111";
const CHECK = "22222222-2222-4222-8222-222222222222";
const WINDOW = 300_000;
const BASE = Math.floor(Date.parse("2026-10-01T08:00:00Z") / WINDOW) * WINDOW;

const heartbeat = (
  cpu: number,
  results: CheckResult[] = [],
): AgentHeartbeat => ({
  nodeId: NODE,
  hostname: "pivox",
  operatingSystem: "linux",
  architecture: "amd64",
  agentVersion: "0.6.0",
  metrics: {
    cpuPercent: cpu,
    memoryUsedBytes: 4,
    memoryTotalBytes: 8,
    diskUsedBytes: 1,
    diskTotalBytes: 2,
    load1: 0.5,
    load5: 0.4,
    load15: 0.3,
    uptimeSeconds: 100,
  },
  results,
});

const result = (status: "UP" | "DOWN"): CheckResult => ({
  checkId: CHECK,
  status,
  latencyMs: status === "UP" ? 30 : null,
  message: status === "DOWN" ? "refused" : null,
});

function setup() {
  const { db, sqlite } = createTestDb();
  seedNode(sqlite, { id: NODE });
  seedCheck(sqlite, { id: CHECK, nodeId: NODE });
  const accepted: { ws: FakeSocket; tags: string[] }[] = [];
  const ctx = {
    acceptWebSocket(ws: FakeSocket, tags: string[]) {
      accepted.push({ ws, tags });
    },
    getWebSockets(tag?: string) {
      return accepted
        .filter(
          (entry) =>
            (!entry.ws.closed || entry.ws.lingers) &&
            (!tag || entry.tags.includes(tag)),
        )
        .map((entry) => entry.ws);
    },
    getWebSocketAutoResponseTimestamp(ws: FakeSocket) {
      return ws.pinged === null ? null : new Date(ws.pinged);
    },
    setWebSocketAutoResponse() {},
    storage: new FakeStorage(),
  };
  const mail: { subject: string; text: string }[] = [];
  let mailFails = false;
  const hub = new FleetHub(
    ctx as unknown as DurableObjectState,
    {
      DB: db,
      ALERT_EMAIL: "owner@example.test",
      FROM_EMAIL: "kry@example.test",
      PUBLIC_ORIGIN: "https://kry.example.test",
      EMAIL: {
        send: async (message: { subject: string; text: string }) => {
          if (mailFails) throw new Error("destination address not verified");
          mail.push(message);
        },
      },
    } as unknown as Env,
  );
  const connect = async () => {
    const ws = new FakeSocket();
    await hub.accept(ws as unknown as WebSocket, NODE, "standalone", 60);
    return ws;
  };
  let requests = 0;
  const send = (ws: FakeSocket, at: number, beat: AgentHeartbeat) => {
    vi.setSystemTime(at);
    requests += 1;
    return hub.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({ id: requests, type: "heartbeat", heartbeat: beat }),
    );
  };
  const node = () =>
    sqlite
      .prepare("SELECT last_seen_at, cpu_percent FROM nodes WHERE id = ?")
      .get(NODE) as {
      last_seen_at: string;
      cpu_percent: number;
    };
  const windows = () =>
    sqlite
      .prepare(
        "SELECT window_start, samples, cpu_percent, checks FROM node_windows ORDER BY window_start",
      )
      .all() as {
      window_start: string;
      samples: number;
      cpu_percent: number;
      checks: string;
    }[];
  const changes = () =>
    (sqlite.prepare("SELECT total_changes() AS n").get() as { n: number }).n;
  return {
    db,
    sqlite,
    hub,
    accepted,
    connect,
    send,
    node,
    windows,
    changes,
    mail,
    failMail: (on: boolean) => {
      mailFails = on;
    },
    storage: ctx.storage,
  };
}

class AutoResponse {
  request: string;
  response: string;
  constructor(request: string, response: string) {
    this.request = request;
    this.response = response;
  }
}

beforeEach(() => {
  vi.useFakeTimers({ now: BASE, toFake: ["Date"] });
  vi.stubGlobal("WebSocketRequestResponsePair", AutoResponse);
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("FleetHub", () => {
  it("answers a heartbeat and writes the server row once per connection", async () => {
    const t = setup();
    const ws = await t.connect();
    expect(t.accepted[0]?.tags).toEqual([NODE]);
    await t.send(ws, BASE + 5_000, heartbeat(10, [result("UP")]));
    expect(ws.replies()[0]).toMatchObject({
      type: "heartbeat",
      response: { ok: true, intervalSeconds: 60 },
    });
    expect(t.node()).toMatchObject({ cpu_percent: 10 });
    expect(t.windows()).toEqual([]);
    const before = t.changes();
    await t.send(ws, BASE + 65_000, heartbeat(30, [result("UP")]));
    expect(t.changes() - before).toBe(0);
    expect(ws.replies()).toHaveLength(2);
  });

  it("writes one averaged history row when the next window starts", async () => {
    const t = setup();
    const ws = await t.connect();
    await t.send(ws, BASE + 5_000, heartbeat(10, [result("UP")]));
    await t.send(ws, BASE + 65_000, heartbeat(30, [result("DOWN")]));
    await t.send(ws, BASE + WINDOW + 5_000, heartbeat(50, [result("UP")]));
    expect(t.windows()).toEqual([
      {
        window_start: new Date(BASE).toISOString(),
        samples: 2,
        cpu_percent: 20,
        checks: JSON.stringify({ [CHECK]: ["DOWN", null, "refused"] }),
      },
    ]);
    expect(t.node().cpu_percent).toBe(50);
  });

  it("flushes the open window and the last sighting when the agent leaves", async () => {
    const t = setup();
    const ws = await t.connect();
    await t.send(ws, BASE + 5_000, heartbeat(10, [result("UP")]));
    await t.send(ws, BASE + 65_000, heartbeat(20));
    await t.hub.webSocketClose(ws as unknown as WebSocket);
    expect(t.windows()).toMatchObject([{ samples: 2, cpu_percent: 15 }]);
    expect(t.node().last_seen_at).toBe(
      new Date(BASE + 65_000).toISOString().replace("T", " ").slice(0, 19),
    );
  });

  it("resumes the window after a reconnect, keeping an earlier failure", async () => {
    const t = setup();
    const first = await t.connect();
    await t.send(first, BASE + 5_000, heartbeat(10, [result("DOWN")]));
    await t.hub.webSocketClose(first as unknown as WebSocket);
    const second = await t.connect();
    await t.send(second, BASE + 125_000, heartbeat(30, [result("UP")]));
    await t.send(second, BASE + WINDOW + 5_000, heartbeat(40, [result("UP")]));
    expect(t.windows()[0]).toMatchObject({
      samples: 2,
      cpu_percent: 20,
      checks: JSON.stringify({ [CHECK]: ["DOWN", null, "refused"] }),
    });
  });

  it("replaces an older connection of the same server and flushes it", async () => {
    const t = setup();
    const old = await t.connect();
    await t.send(old, BASE + 5_000, heartbeat(10));
    await t.connect();
    expect(old.closed).toEqual({
      code: 4000,
      reason: "Replaced by a newer connection",
    });
    expect(t.windows()).toMatchObject([{ samples: 1 }]);
  });

  it("refuses a malformed message without closing, and closes for a disabled server", async () => {
    const t = setup();
    const ws = await t.connect();
    await t.hub.webSocketMessage(ws as unknown as WebSocket, "not json");
    await t.hub.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({
        type: "heartbeat",
        heartbeat: { nodeId: "someone-else" },
      }),
    );
    expect(ws.replies()).toEqual([
      { type: "error", code: "INVALID_MESSAGE" },
      { type: "error", code: "INVALID_MESSAGE" },
    ]);
    expect(ws.closed).toBeNull();
    t.sqlite
      .prepare("UPDATE nodes SET disabled_at = '2026-10-01 00:00:00'")
      .run();
    await t.send(ws, BASE + 5_000, heartbeat(10));
    expect(ws.closed).toEqual({
      code: 4401,
      reason: "Unknown or disabled server",
    });
  });

  it("delivers queued actions and opens incidents like the HTTP route", async () => {
    const t = setup();
    const ws = await t.connect();
    await t.send(ws, BASE + 5_000, heartbeat(10, [result("DOWN")]));
    await t.send(ws, BASE + 65_000, heartbeat(10, [result("DOWN")]));
    expect(t.sqlite.prepare("SELECT status FROM incidents").all()).toEqual([
      { status: "OPEN" },
    ]);
  });

  it("mails a confirmed failure at once and never its recovery", async () => {
    const t = setup();
    const ws = await t.connect();
    await t.send(ws, BASE + 5_000, heartbeat(10, [result("DOWN")]));
    expect(t.mail).toEqual([]);
    await t.send(ws, BASE + 65_000, heartbeat(10, [result("DOWN")]));
    expect(t.mail.map((message) => message.subject)).toEqual([
      `[Krynodes] ${NODE}: 1 check down — ${CHECK}`,
    ]);
    await t.send(ws, BASE + 125_000, heartbeat(10, [result("UP")]));
    await t.send(ws, BASE + 185_000, heartbeat(10, [result("DOWN")]));
    await t.send(ws, BASE + 245_000, heartbeat(10, [result("DOWN")]));
    vi.setSystemTime(BASE + 300_000);
    await t.hub.alarm();
    expect(t.mail).toHaveLength(1);
  });

  it("says in the failure mail when Krynodes restarts the unit by itself", async () => {
    const t = setup();
    t.sqlite
      .prepare(
        "UPDATE checks SET kind = 'SERVICE', target = 'nginx', name = 'nginx', auto_restart = 1 WHERE id = ?",
      )
      .run(CHECK);
    const ws = await t.connect();
    const newer = (beat: AgentHeartbeat) => ({
      ...beat,
      agentVersion: "0.6.0",
    });
    await t.send(ws, BASE + 5_000, newer(heartbeat(10, [result("DOWN")])));
    await t.send(ws, BASE + 65_000, newer(heartbeat(10, [result("DOWN")])));
    expect(t.mail).toHaveLength(1);
    expect(t.mail[0]!.text).toContain("restarting it automatically");
  });

  it("does not claim a restart when auto-restart is off", async () => {
    const t = setup();
    t.sqlite
      .prepare(
        "UPDATE checks SET kind = 'SERVICE', target = 'nginx', name = 'nginx' WHERE id = ?",
      )
      .run(CHECK);
    const ws = await t.connect();
    const newer = (beat: AgentHeartbeat) => ({
      ...beat,
      agentVersion: "0.6.0",
    });
    await t.send(ws, BASE + 5_000, newer(heartbeat(10, [result("DOWN")])));
    await t.send(ws, BASE + 65_000, newer(heartbeat(10, [result("DOWN")])));
    expect(t.mail).toHaveLength(1);
    expect(t.mail[0]!.text).not.toContain("automatically");
  });

  it("mails at once when a server stops reporting, once an hour, and never that it is back", async () => {
    const t = setup();
    const ws = await t.connect();
    await t.send(ws, BASE + 5_000, heartbeat(10));
    expect(t.storage.alarm).toBe(BASE + 185_000);

    vi.setSystemTime(BASE + 120_000);
    await t.hub.alarm();
    expect(t.mail).toEqual([]);

    vi.setSystemTime(BASE + 186_000);
    await t.hub.alarm();
    expect(t.mail.map((message) => message.subject)).toEqual([
      `[Krynodes] ${NODE}: offline`,
    ]);

    await t.send(ws, BASE + 300_000, heartbeat(10));
    vi.setSystemTime(BASE + 600_000);
    await t.hub.alarm();
    expect(t.mail).toHaveLength(1);

    ws.close(1006, "gone");
    await t.hub.webSocketClose(ws as unknown as WebSocket);
    const again = await t.connect();
    await t.send(again, BASE + 3_700_000, heartbeat(10));
    vi.setSystemTime(BASE + 3_900_000);
    await t.hub.alarm();
    expect(t.mail.map((message) => message.subject).at(-1)).toBe(
      `[Krynodes] ${NODE}: offline`,
    );
    expect(t.mail).toHaveLength(2);
  });

  it("mails a full disk once the database takes the report again", async () => {
    const t = setup();
    const disk = (used: number): AgentHeartbeat => ({
      ...heartbeat(10),
      metrics: {
        ...heartbeat(10).metrics,
        diskUsedBytes: used,
        diskTotalBytes: 100,
      },
    });
    const ws = await t.connect();
    await t.send(ws, BASE + 5_000, disk(80));
    const prepare = t.db.prepare.bind(t.db);
    let broken = true;
    t.db.prepare = ((sql: string) => {
      if (
        broken &&
        sql.includes("FROM checks WHERE node_id = ? AND enabled = 1")
      ) {
        broken = false;
        throw new Error("D1 is unavailable");
      }
      return prepare(sql);
    }) as typeof t.db.prepare;
    await t.send(ws, BASE + 65_000, disk(97));
    expect(broken).toBe(false);
    expect(t.mail).toEqual([]);
    await t.send(ws, BASE + 125_000, disk(97));
    expect(t.mail.map((message) => message.subject)).toEqual([
      `[Krynodes] ${NODE}: disk 97% full`,
    ]);
  });

  it("mails once when the disk reaches 95%, and again only after it went below 90%", async () => {
    const t = setup();
    const disk = (used: number): AgentHeartbeat => ({
      ...heartbeat(10),
      metrics: {
        ...heartbeat(10).metrics,
        diskUsedBytes: used,
        diskTotalBytes: 100,
      },
    });
    const ws = await t.connect();
    await t.send(ws, BASE + 5_000, disk(80));
    await t.send(ws, BASE + 65_000, disk(96));
    await t.send(ws, BASE + 125_000, disk(97));
    const again = await t.connect();
    await t.send(again, BASE + 185_000, disk(97));
    expect(t.mail.map((message) => message.subject)).toEqual([
      `[Krynodes] ${NODE}: disk 96% full`,
    ]);
    expect(t.mail[0]!.text).toContain("almost full");

    const third = await t.connect();
    await t.send(third, BASE + 245_000, disk(85));
    await t.send(third, BASE + 4_000_000, disk(95));
    expect(t.mail.map((message) => message.subject)).toEqual([
      `[Krynodes] ${NODE}: disk 96% full`,
      `[Krynodes] ${NODE}: disk 95% full`,
    ]);
  });

  it("accepts a new connection even when closing a lingering one throws", async () => {
    const t = setup();
    const old = await t.connect();
    old.lingers = true;
    old.close(1006, "gone");
    old.close = () => {
      throw new TypeError("Can't call WebSocket close() after close().");
    };
    const fresh = await t.connect();
    await t.send(fresh, BASE + 5_000, heartbeat(10));
    expect(fresh.replies().at(-1)).toMatchObject({ type: "heartbeat" });
  });

  it("follows the newest connection when a replaced one lingers while closing", async () => {
    const t = setup();
    const old = await t.connect();
    old.lingers = true;
    await t.send(old, BASE + 5_000, heartbeat(10));
    const fresh = await t.connect();
    await t.send(fresh, BASE + 120_000, heartbeat(10));
    vi.setSystemTime(BASE + 200_000);
    await t.hub.alarm();
    expect(t.mail).toEqual([]);
  });

  it("counts the agent's keepalive pings, so a report that fails to store is no outage", async () => {
    const t = setup();
    const ws = await t.connect();
    await t.send(ws, BASE + 5_000, heartbeat(10));
    ws.pinged = BASE + 170_000;
    vi.setSystemTime(BASE + 200_000);
    await t.hub.alarm();
    expect(t.mail).toEqual([]);
    expect(t.storage.alarm).toBe(BASE + 350_000);

    vi.setSystemTime(BASE + 360_000);
    await t.hub.alarm();
    expect(t.mail.map((message) => message.subject)).toEqual([
      `[Krynodes] ${NODE}: offline`,
    ]);
  });

  it("keeps the newer report when a replaced connection finally closes", async () => {
    const t = setup();
    const old = await t.connect();
    old.lingers = true;
    await t.send(old, BASE + 5_000, heartbeat(10));
    const fresh = await t.connect();
    await t.send(fresh, BASE + 30_000, heartbeat(20));
    vi.setSystemTime(BASE + 60_000);
    await t.hub.webSocketClose(old as unknown as WebSocket);
    expect(t.node().cpu_percent).toBe(20);
  });

  it("pokes the newest connection past one that is still closing", async () => {
    const t = setup();
    const old = await t.connect();
    old.lingers = true;
    const fresh = await t.connect();
    const poke = await t.hub.fetch(
      new Request("https://fleet/poke", {
        method: "POST",
        body: JSON.stringify({ nodeIds: [NODE] }),
      }),
    );
    expect(await poke.json()).toEqual({ poked: 1 });
    expect(fresh.replies()).toEqual([{ type: "poke" }]);
  });

  it("waits while the server restarts in its reboot window, then mails if it stays away", async () => {
    const t = setup();
    t.sqlite.prepare("UPDATE nodes SET security = ? WHERE id = ?").run(
      JSON.stringify({
        checkedAt: new Date(BASE).toISOString(),
        findings: [
          {
            id: "reboot-pending",
            severity: "note",
            detail: "A restart is waiting",
          },
        ],
        recipes: [],
        lockdown: false,
        rebootHour: new Date(BASE).getUTCHours(),
      }),
      NODE,
    );
    const ws = await t.connect();
    await t.send(ws, BASE + 5_000, heartbeat(10));
    ws.close(1006, "rebooting");
    await t.hub.webSocketClose(ws as unknown as WebSocket);

    vi.setSystemTime(BASE + 200_000);
    await t.hub.alarm();
    expect(t.mail).toEqual([]);

    vi.setSystemTime(BASE + 660_000);
    await t.hub.alarm();
    expect(t.mail.map((message) => message.subject)).toEqual([
      `[Krynodes] ${NODE}: offline`,
    ]);
  });

  it("mails one list when more than five servers go offline at once", async () => {
    const t = setup();
    const ids = Array.from(
      { length: 7 },
      (_, index) => `00000000-0000-4000-8000-00000000000${index}`,
    );
    for (const id of ids) {
      seedNode(t.sqlite, { id });
      const ws = new FakeSocket();
      await t.hub.accept(ws as unknown as WebSocket, id, "standalone", 60);
      await t.send(ws, BASE + 5_000, { ...heartbeat(10), nodeId: id });
      ws.close(1006, "gone");
      await t.hub.webSocketClose(ws as unknown as WebSocket);
    }
    vi.setSystemTime(BASE + 200_000);
    await t.hub.alarm();
    expect(t.mail.map((message) => message.subject)).toEqual([
      "[Krynodes] 7 servers offline",
    ]);
    for (const id of ids) expect(t.mail[0]!.text).toContain(id);
  });

  it("checks 40 silent servers with a few statements and calls them all offline", async () => {
    const t = setup();
    const ids = Array.from(
      { length: 40 },
      (_, index) =>
        `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`,
    );
    for (const id of ids) {
      seedNode(t.sqlite, { id });
      const ws = new FakeSocket();
      await t.hub.accept(ws as unknown as WebSocket, id, "standalone", 60);
      await t.send(ws, BASE + 5_000, { ...heartbeat(10), nodeId: id });
      ws.close(1006, "gone");
      await t.hub.webSocketClose(ws as unknown as WebSocket);
    }
    let statements = 0;
    const prepare = t.db.prepare.bind(t.db);
    t.db.prepare = ((sql: string) => {
      statements += 1;
      return prepare(sql);
    }) as typeof t.db.prepare;
    vi.setSystemTime(BASE + 200_000);
    await t.hub.alarm();
    expect(statements).toBeLessThanOrEqual(10);
    expect(t.mail.map((message) => message.subject)).toEqual([
      "[Krynodes] 40 servers offline",
    ]);
  });

  it("keeps watching when the database fails during a check, and mails once it is back", async () => {
    const t = setup();
    const ws = await t.connect();
    await t.send(ws, BASE + 5_000, heartbeat(10));
    ws.close(1006, "gone");
    await t.hub.webSocketClose(ws as unknown as WebSocket);
    const prepare = t.db.prepare.bind(t.db);
    t.db.prepare = (() => {
      throw new Error("D1 is unavailable");
    }) as typeof t.db.prepare;
    vi.setSystemTime(BASE + 200_000);
    await t.hub.alarm();
    expect(t.storage.alarm).toBe(BASE + 260_000);
    t.db.prepare = prepare;
    vi.setSystemTime(BASE + 260_000);
    await t.hub.alarm();
    expect(t.mail.map((message) => message.subject)).toEqual([
      `[Krynodes] ${NODE}: offline`,
    ]);
  });

  it("mails a server it found offline even when the next alarm cannot be set", async () => {
    const t = setup();
    const ws = await t.connect();
    await t.send(ws, BASE + 5_000, heartbeat(10));
    ws.close(1006, "gone");
    await t.hub.webSocketClose(ws as unknown as WebSocket);
    const other = "00000000-0000-4000-8000-000000000099";
    seedNode(t.sqlite, { id: other });
    const live = new FakeSocket();
    await t.hub.accept(live as unknown as WebSocket, other, "standalone", 60);
    await t.send(live, BASE + 190_000, { ...heartbeat(10), nodeId: other });
    const setAlarm = t.storage.setAlarm.bind(t.storage);
    let failed = false;
    t.storage.setAlarm = async (at: number) => {
      if (!failed) {
        failed = true;
        throw new Error("storage is unavailable");
      }
      return setAlarm(at);
    };
    vi.setSystemTime(BASE + 200_000);
    await t.hub.alarm();
    expect(t.mail.map((message) => message.subject)).toEqual([
      `[Krynodes] ${NODE}: offline`,
    ]);
    expect(t.storage.alarm).toBe(BASE + 260_000);
  });

  it("still calls a silent server offline when its stored security report is unreadable", async () => {
    const t = setup();
    t.sqlite
      .prepare("UPDATE nodes SET security = ? WHERE id = ?")
      .run("{not json", NODE);
    const ws = await t.connect();
    await t.send(ws, BASE + 5_000, heartbeat(10));
    ws.close(1006, "gone");
    await t.hub.webSocketClose(ws as unknown as WebSocket);
    vi.setSystemTime(BASE + 200_000);
    await t.hub.alarm();
    expect(t.mail.map((message) => message.subject)).toEqual([
      `[Krynodes] ${NODE}: offline`,
    ]);
  });

  it("waits while a restart from the dashboard runs, then mails if the server stays away", async () => {
    const t = setup();
    const ws = await t.connect();
    await t.send(ws, BASE + 5_000, heartbeat(10));
    t.sqlite
      .prepare(
        `INSERT INTO actions (id, batch_id, position, mode, node_id, kind, name, action,
           status, requested_by, requested_at, deliverable_at, sent_at, finished_at)
         VALUES ('r1', 'b1', 0, 'rolling', ?, 'host', 'server', 'reboot', 'done', 'owner@example.test', ?, ?, ?, ?)`,
      )
      .run(
        NODE,
        new Date(BASE + 10_000).toISOString(),
        new Date(BASE + 10_000).toISOString(),
        new Date(BASE + 20_000).toISOString(),
        new Date(BASE + 30_000).toISOString(),
      );
    ws.close(1006, "rebooting");
    await t.hub.webSocketClose(ws as unknown as WebSocket);

    vi.setSystemTime(BASE + 200_000);
    await t.hub.alarm();
    expect(t.mail).toEqual([]);
    expect(t.storage.alarm).toBe(BASE + 260_000);

    vi.setSystemTime(BASE + 660_000);
    await t.hub.alarm();
    expect(t.mail.map((message) => message.subject)).toEqual([
      `[Krynodes] ${NODE}: offline`,
    ]);
  });

  it("follows a changed report interval before calling a server offline", async () => {
    const t = setup();
    const ws = await t.connect();
    t.sqlite
      .prepare("UPDATE nodes SET interval_seconds = 300 WHERE id = ?")
      .run(NODE);
    await t.send(ws, BASE + 5_000, heartbeat(10));
    expect(t.storage.alarm).toBe(BASE + 905_000);
    vi.setSystemTime(BASE + 400_000);
    await t.hub.alarm();
    expect(t.mail).toEqual([]);
  });

  it("never mails about a server that was deleted", async () => {
    const t = setup();
    const ws = await t.connect();
    await t.send(ws, BASE + 5_000, heartbeat(10));
    t.sqlite.prepare("DELETE FROM nodes WHERE id = ?").run(NODE);
    vi.setSystemTime(BASE + 300_000);
    await t.hub.alarm();
    expect(t.mail).toEqual([]);
    expect(t.storage.alarm).toBeNull();
  });

  it("opens no incident during planned work on the server, then one at the next failure", async () => {
    const t = setup();
    const planned = (status: string, finishedAt: string | null) =>
      t.sqlite
        .prepare(
          `INSERT OR REPLACE INTO actions (id, batch_id, position, mode, node_id, kind, name, action,
             status, requested_by, requested_at, deliverable_at, sent_at, finished_at)
           VALUES ('m1', 'b1', 0, 'rolling', ?, 'docker', 'nginx', 'restart', ?, 'budi@example.test', ?, ?, ?, ?)`,
        )
        .run(
          NODE,
          status,
          new Date(BASE).toISOString(),
          new Date(BASE).toISOString(),
          new Date(BASE).toISOString(),
          finishedAt,
        );
    const incidents = () =>
      (
        t.sqlite.prepare("SELECT COUNT(*) AS n FROM incidents").get() as {
          n: number;
        }
      ).n;
    planned("sent", null);
    const ws = await t.connect();
    await t.send(ws, BASE + 5_000, heartbeat(10, [result("DOWN")]));
    await t.send(ws, BASE + 65_000, heartbeat(10, [result("DOWN")]));
    expect(incidents()).toBe(0);
    planned("done", new Date(BASE + 70_000).toISOString());
    await t.send(ws, BASE + 125_000, heartbeat(10, [result("DOWN")]));
    expect(incidents()).toBe(0);
    await t.send(ws, BASE + 245_000, heartbeat(10, [result("DOWN")]));
    expect(incidents()).toBe(1);
  });

  it("answers at most 60 messages a minute from one server and drops the rest", async () => {
    const t = setup();
    const ws = await t.connect();
    for (let index = 0; index < 62; index++) {
      await t.send(ws, BASE + 5_000 + index * 100, heartbeat(10));
    }
    const answered = () =>
      ws.replies().filter((reply) => reply.type === "heartbeat").length;
    expect(answered()).toBe(60);
    expect(
      ws.replies().filter((reply) => reply.code === "TOO_MANY_MESSAGES"),
    ).toHaveLength(1);
    await t.send(ws, BASE + 66_000, heartbeat(10));
    expect(answered()).toBe(61);
  });

  it("still mails a confirmed failure when the server's socket closed before the answer", async () => {
    const t = setup();
    const ws = await t.connect();
    await t.send(ws, BASE + 5_000, heartbeat(10, [result("DOWN")]));
    ws.close(1006, "gone");
    await t.send(ws, BASE + 65_000, heartbeat(10, [result("DOWN")]));
    expect(t.mail.map((message) => message.subject)).toEqual([
      `[Krynodes] ${NODE}: 1 check down — ${CHECK}`,
    ]);
  });

  it("still mails a confirmed failure when handing out actions fails", async () => {
    const t = setup();
    const ws = await t.connect();
    await t.send(ws, BASE + 5_000, heartbeat(10, [result("DOWN")]));
    const prepare = t.db.prepare.bind(t.db);
    t.db.prepare = ((sql: string) => {
      if (sql.includes("SET status = 'expired'")) {
        throw new Error("D1 is unavailable");
      }
      return prepare(sql);
    }) as typeof t.db.prepare;
    await t.send(ws, BASE + 65_000, heartbeat(10, [result("DOWN")]));
    expect(t.mail.map((message) => message.subject)).toEqual([
      `[Krynodes] ${NODE}: 1 check down — ${CHECK}`,
    ]);
  });

  it("serves the live view and pokes connected servers", async () => {
    const t = setup();
    const ws = await t.connect();
    await t.send(ws, BASE + 5_000, heartbeat(10));
    const live = (await (
      await t.hub.fetch(new Request("https://fleet/live"))
    ).json()) as { nodes: Record<string, { lastSeen: number }> };
    expect(live.nodes[NODE]?.lastSeen).toBe(BASE + 5_000);
    const poke = await t.hub.fetch(
      new Request("https://fleet/poke", {
        method: "POST",
        body: JSON.stringify({ nodeIds: [NODE, "absent"] }),
      }),
    );
    expect(await poke.json()).toEqual({ poked: 1 });
    expect(ws.replies().at(-1)).toEqual({ type: "poke" });
  });

  it("answers every request by its id and refuses one without", async () => {
    const t = setup();
    const ws = await t.connect();
    await t.hub.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({ id: 1, type: "config" }),
    );
    expect(ws.replies()[0]).toMatchObject({
      id: 1,
      type: "config",
      config: {
        nodeId: NODE,
        intervalSeconds: 60,
        checks: [{ id: CHECK }],
      },
    });
    expect(
      (ws.replies()[0] as { config: { configVersion: string } }).config
        .configVersion,
    ).toMatch(/^[0-9a-f]{16}$/u);
    await t.hub.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({
        id: 2,
        type: "actions",
        report: {
          nodeId: NODE,
          inventory: {
            hash: "a".repeat(64),
            services: [
              {
                kind: "systemd",
                name: "nginx.service",
                state: "running",
                since: null,
                system: false,
              },
            ],
          },
        },
      }),
    );
    expect(ws.replies()[1]).toEqual({
      id: 2,
      type: "actions",
      response: { ok: true, inventoryHash: "a".repeat(64) },
    });
    expect(
      t.sqlite.prepare("SELECT name FROM services WHERE node_id = ?").all(NODE),
    ).toEqual([{ name: "nginx.service" }]);
    vi.setSystemTime(BASE + 5_000);
    await t.hub.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({ type: "heartbeat", heartbeat: heartbeat(10) }),
    );
    expect(ws.replies()[2]).toEqual({ type: "error", code: "INVALID_MESSAGE" });
    vi.setSystemTime(BASE + 6_000);
    await t.hub.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({ id: 3, type: "heartbeat", heartbeat: heartbeat(10) }),
    );
    expect(ws.replies()[3]).toMatchObject({ id: 3, type: "heartbeat" });
    await t.hub.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({ id: 4, type: "actions", report: { nodeId: "other" } }),
    );
    expect(ws.replies()[4]).toEqual({
      id: 4,
      type: "error",
      code: "INVALID_MESSAGE",
    });
  });

  it("tells an agent below the minimum to update at once, and no one else", async () => {
    const t = setup();
    t.sqlite
      .prepare(
        "INSERT INTO settings (key, value, updated_at) VALUES ('agent_release', '0.6.2', ?)",
      )
      .run(new Date(BASE).toISOString());
    const ws = await t.connect();
    await t.send(ws, BASE + 5_000, heartbeat(10));
    expect(ws.replies().at(-1)).not.toMatchObject({
      response: { update: expect.anything() },
    });
    await t.send(ws, BASE + 65_000, {
      ...heartbeat(10),
      agentVersion: "0.5.1",
    });
    expect(ws.replies().at(-1)).toMatchObject({
      response: { update: { version: "0.6.2" } },
    });
    expect(
      t.sqlite
        .prepare(
          "SELECT update_requested_version, update_attempts FROM nodes WHERE id = ?",
        )
        .get(NODE),
    ).toEqual({ update_requested_version: "0.6.2", update_attempts: 1 });
  });

  it("asks again for a stalled update and keeps the agent's reason, like the HTTP route", async () => {
    const t = setup();
    t.sqlite
      .prepare(
        "UPDATE nodes SET update_requested_version = '0.6.1', update_requested_at = ?, update_attempts = 1 WHERE id = ?",
      )
      .run(new Date(BASE - 16 * 60_000).toISOString(), NODE);
    const ws = await t.connect();
    await t.send(ws, BASE + 5_000, {
      ...heartbeat(10),
      update: { version: "0.6.1", message: "download stalled" },
    });
    const row = t.sqlite
      .prepare(
        "SELECT update_requested_at, update_attempts, update_error FROM nodes WHERE id = ?",
      )
      .get(NODE) as {
      update_requested_at: string;
      update_attempts: number;
      update_error: string;
    };
    expect(row).toMatchObject({
      update_requested_at: new Date(BASE + 5_000).toISOString(),
      update_attempts: 2,
      update_error: "download stalled",
    });
    expect(ws.replies().at(-1)).toMatchObject({
      response: {
        update: {
          version: "0.6.1",
          requestedAt: new Date(BASE + 5_000).toISOString(),
        },
      },
    });
  });

  it("remembers an alert mail that could not go out until one does", async () => {
    const t = setup();
    const ws = await t.connect();
    const mailState = async () =>
      (
        (await (
          await t.hub.fetch(new Request("https://fleet/live"))
        ).json()) as { mail: { failedAt: string; error: string } | null }
      ).mail;
    expect(await mailState()).toBeNull();
    t.failMail(true);
    await t.send(ws, BASE + 5_000, heartbeat(10, [result("DOWN")]));
    await t.send(ws, BASE + 65_000, heartbeat(10, [result("DOWN")]));
    expect(await mailState()).toEqual({
      failedAt: new Date(BASE + 65_000).toISOString(),
      error: "destination address not verified",
    });
    t.failMail(false);
    const disk = {
      ...heartbeat(10),
      metrics: {
        ...heartbeat(10).metrics,
        diskUsedBytes: 96,
        diskTotalBytes: 100,
      },
    };
    await t.send(ws, BASE + 125_000, disk);
    expect(t.mail.length).toBe(1);
    expect(await mailState()).toBeNull();
  });

  it("keeps the results of a report whose inventory it cannot read", async () => {
    const t = setup();
    const ws = await t.connect();
    const action = "77777777-7777-4777-8777-777777777777";
    t.sqlite
      .prepare(
        `INSERT INTO actions (id, batch_id, position, mode, node_id, kind, name, action,
           status, requested_by, requested_at, deliverable_at, sent_at)
         VALUES (?, ?, 0, 'rolling', ?, 'docker', 'adguard', 'restart', 'sent', 'owner', ?, ?, ?)`,
      )
      .run(
        action,
        action,
        NODE,
        new Date(BASE).toISOString(),
        new Date(BASE).toISOString(),
        new Date(BASE).toISOString(),
      );
    vi.setSystemTime(BASE + 5_000);
    await t.hub.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({
        id: 9,
        type: "actions",
        report: {
          nodeId: NODE,
          results: [
            {
              id: action,
              ok: true,
              exitCode: 0,
              output: "restarted",
              finishedAt: new Date(BASE + 4_000).toISOString(),
            },
          ],
          inventory: {
            hash: "b".repeat(64),
            services: [
              {
                kind: "docker",
                name: "bad name!",
                state: "running",
                since: null,
                system: false,
              },
            ],
          },
        },
      }),
    );
    expect(ws.replies().at(-1)).toMatchObject({
      id: 9,
      type: "actions",
      response: { ok: true },
    });
    expect(
      (ws.replies().at(-1) as { response: { inventoryHash: string | null } })
        .response.inventoryHash,
    ).not.toBe("b".repeat(64));
    expect(
      t.sqlite.prepare("SELECT status FROM actions WHERE id = ?").get(action),
    ).toEqual({ status: "done" });
  });

  it("tells the live view when each server connected", async () => {
    const t = setup();
    vi.setSystemTime(BASE + 1_000);
    const ws = await t.connect();
    await t.send(ws, BASE + 5_000, heartbeat(10));
    const live = (await (
      await t.hub.fetch(new Request("https://fleet/live"))
    ).json()) as { nodes: Record<string, { connectedAt: number }> };
    expect(live.nodes[NODE]?.connectedAt).toBe(BASE + 1_000);
  });

  describe("dashboards watching", () => {
    const changes = (ws: FakeSocket) =>
      ws
        .replies()
        .filter((reply) => reply.type === "changed")
        .map((reply) => reply.topics);

    it("hears when a server connects, reports a check change and leaves", async () => {
      const t = setup();
      const viewer = new FakeSocket();
      await t.hub.watch(viewer as unknown as WebSocket);
      const ws = await t.connect();
      await t.send(ws, BASE + 5_000, heartbeat(10, [result("UP")]));
      expect(changes(viewer)).toEqual([["nodes", "checks"]]);
      await t.send(ws, BASE + 65_000, heartbeat(20, [result("UP")]));
      expect(changes(viewer)).toHaveLength(1);
      await t.hub.webSocketClose(ws as unknown as WebSocket);
      expect(changes(viewer).at(-1)).toEqual(["nodes"]);
    });

    it("hears action results and inventories, and what the Worker announces", async () => {
      const t = setup();
      const viewer = new FakeSocket();
      await t.hub.watch(viewer as unknown as WebSocket);
      const ws = await t.connect();
      await t.hub.webSocketMessage(
        ws as unknown as WebSocket,
        JSON.stringify({
          id: 1,
          type: "actions",
          report: { nodeId: NODE, inventory: { hash: "a".repeat(64) } },
        }),
      );
      expect(changes(viewer)).toEqual([["actions", "services"]]);
      await t.hub.fetch(
        new Request("https://fleet/announce", {
          method: "POST",
          body: JSON.stringify({ topics: ["all"] }),
        }),
      );
      expect(changes(viewer).at(-1)).toEqual(["all"]);
    });

    it("keeps watchers out of the live view, the agents' sockets and window flushing", async () => {
      const t = setup();
      const viewer = new FakeSocket();
      await t.hub.watch(viewer as unknown as WebSocket);
      await t.hub.webSocketMessage(viewer as unknown as WebSocket, "hello");
      expect(viewer.replies()).toEqual([]);
      const live = await (
        await t.hub.fetch(new Request("https://fleet/live"))
      ).json();
      expect(live).toEqual({ nodes: {}, mail: null });
      await t.hub.webSocketClose(viewer as unknown as WebSocket);
      expect(t.windows()).toEqual([]);
    });
  });

  it("mails a new serious security finding once", async () => {
    const t = setup();
    const ws = await t.connect();
    let id = 1000;
    const inventory = (hash: string, ids: string[]) =>
      t.hub.webSocketMessage(
        ws as unknown as WebSocket,
        JSON.stringify({
          id: (id += 1),
          type: "actions",
          report: {
            nodeId: NODE,
            inventory: {
              hash: hash.repeat(64),
              services: [],
              security: {
                checkedAt: "2026-10-05T10:00:00.000Z",
                findings: ids.map((finding) => ({
                  id: finding,
                  severity: "serious",
                  detail: `${finding} detail`,
                })),
                recipes: [],
                lockdown: false,
                rebootHour: null,
              },
            },
          },
        }),
      );
    await inventory("a", ["ssh-password"]);
    await inventory("b", ["ssh-password"]);
    await inventory("c", ["ssh-password", "os-eol"]);
    expect(t.mail.map((message) => message.subject)).toEqual([
      `[Krynodes] ${NODE}: 1 serious security finding`,
      `[Krynodes] ${NODE}: 1 serious security finding`,
    ]);
    expect(t.mail[1]!.text).toContain("os-eol detail");
  });
});
