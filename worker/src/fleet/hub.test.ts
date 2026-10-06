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
  agentVersion: "0.5.0",
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
          (entry) => !entry.ws.closed && (!tag || entry.tags.includes(tag)),
        )
        .map((entry) => entry.ws);
    },
    setWebSocketAutoResponse() {},
    storage: new FakeStorage(),
  };
  const mail: { subject: string; text: string }[] = [];
  const hub = new FleetHub(
    ctx as unknown as DurableObjectState,
    {
      DB: db,
      ALERT_EMAIL: "owner@example.test",
      FROM_EMAIL: "kry@example.test",
      PUBLIC_ORIGIN: "https://kry.example.test",
      EMAIL: {
        send: async (message: { subject: string; text: string }) => {
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
    sqlite,
    hub,
    accepted,
    connect,
    send,
    node,
    windows,
    changes,
    mail,
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
      agentVersion: "0.5.0",
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
      agentVersion: "0.5.0",
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

  it("serves the live view and pokes connected servers", async () => {
    const t = setup();
    const ws = await t.connect();
    await t.send(ws, BASE + 5_000, heartbeat(10));
    const live = (await (
      await t.hub.fetch(new Request("https://fleet/live"))
    ).json()) as Record<string, { lastSeen: number }>;
    expect(live[NODE]?.lastSeen).toBe(BASE + 5_000);
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

  it("asks again for a stalled update and keeps the agent's reason, like the HTTP route", async () => {
    const t = setup();
    t.sqlite
      .prepare(
        "UPDATE nodes SET update_requested_version = '0.5.1', update_requested_at = ?, update_attempts = 1 WHERE id = ?",
      )
      .run(new Date(BASE - 16 * 60_000).toISOString(), NODE);
    const ws = await t.connect();
    await t.send(ws, BASE + 5_000, {
      ...heartbeat(10),
      update: { version: "0.5.1", message: "download stalled" },
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
          version: "0.5.1",
          requestedAt: new Date(BASE + 5_000).toISOString(),
        },
      },
    });
  });

  it("tells the live view when each server connected", async () => {
    const t = setup();
    vi.setSystemTime(BASE + 1_000);
    const ws = await t.connect();
    await t.send(ws, BASE + 5_000, heartbeat(10));
    const live = (await (
      await t.hub.fetch(new Request("https://fleet/live"))
    ).json()) as Record<string, { connectedAt: number }>;
    expect(live[NODE]?.connectedAt).toBe(BASE + 1_000);
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
      expect(live).toEqual({});
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
