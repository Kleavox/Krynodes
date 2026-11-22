import { afterEach, describe, expect, it, vi } from "vitest";

import { freshDb } from "../test/db";
import { hubHarness } from "../test/hub";

const SEAL =
  "BKjpRA_slHw4x3NdGJcyQ75R9_DQQtbaWv1M8JLZI1Y0jhyDrnX9kl3a9IjqweVG1-weFpLFHMr0nXfvK_uB2Iw";

const hello = {
  type: "hello",
  v: 1,
  version: "0.7.90",
  hostname: "server-1",
  os: "linux",
  arch: "amd64",
  kernel: "6.8.0-45-generic",
  sealKey: SEAL,
  trust: { version: 3, core: ["Y3JlZC1jb3Jl"], access: ["Y3JlZC1jb3Jl"] },
};

const command = {
  type: "command",
  id: "a1",
  kind: "host",
  name: "server-1",
  action: "reboot",
  signed: "c2lnbmVk",
};

async function setup() {
  const db = freshDb();
  await db
    .prepare(
      "INSERT INTO nodes (id, name, agent_token_hash, enrolled_at) VALUES ('n1', 'server-1', 'h1', '2026-11-22T00:00:00.000Z')",
    )
    .run();
  await db
    .prepare(
      "INSERT INTO actions (id, node_id, kind, name, action, title, status, created_at) VALUES ('a1', 'n1', 'host', 'server-1', 'reboot', 'Reboot server-1', 'sent', '2026-11-22T00:00:00.000Z')",
    )
    .run();
  const writes: string[] = [];
  const counted = {
    prepare: (sql: string) => {
      if (/^\s*(INSERT|UPDATE|DELETE)/iu.test(sql)) writes.push(sql);
      return db.prepare(sql);
    },
    batch: db.batch.bind(db),
  } as unknown as D1Database;
  return { db, writes, ...hubHarness(counted) };
}

const post = (path: string, body: unknown) =>
  new Request(`https://fleet${path}`, {
    method: "POST",
    body: JSON.stringify(body),
  });

afterEach(() => vi.useRealTimers());

describe("FleetHub", () => {
  it("answers pings without waking", async () => {
    const { autoResponses } = await setup();
    expect(autoResponses).toEqual([{ request: "ping", response: "pong" }]);
  });

  it("hello writes facts once and not again when nothing changed", async () => {
    const { db, writes, connect, say } = await setup();
    const ws = connect("n1");
    await say(ws, hello);
    expect(writes).toHaveLength(2);
    expect(
      await db
        .prepare(
          "SELECT hostname, os, arch, kernel, version, seal_key, last_seen_at IS NOT NULL AS seen FROM nodes WHERE id = 'n1'",
        )
        .first(),
    ).toEqual({
      hostname: "server-1",
      os: "linux",
      arch: "amd64",
      kernel: "6.8.0-45-generic",
      version: "0.7.90",
      seal_key: SEAL,
      seen: 1,
    });
    expect(
      await db
        .prepare(
          "SELECT version, core, access FROM node_trust WHERE node_id = 'n1'",
        )
        .first(),
    ).toEqual({
      version: 3,
      core: '["Y3JlZC1jb3Jl"]',
      access: '["Y3JlZC1jb3Jl"]',
    });

    await say(ws, hello);
    await say(connect("n1"), hello);
    expect(writes).toHaveLength(2);

    await say(connect("n1"), { ...hello, kernel: "6.8.0-46-generic" });
    expect(writes).toHaveLength(3);
  });

  it("writes last_seen_at again after ten minutes", async () => {
    vi.useFakeTimers({ now: Date.parse("2026-11-22T08:00:00.000Z") });
    const { writes, connect, say } = await setup();
    const ws = connect("n1");
    await say(ws, { ...hello, trust: null });
    vi.setSystemTime(Date.parse("2026-11-22T08:09:00.000Z"));
    await say(ws, { ...hello, trust: null });
    expect(writes).toHaveLength(1);
    vi.setSystemTime(Date.parse("2026-11-22T08:10:00.000Z"));
    await say(ws, { ...hello, trust: null });
    expect(writes).toHaveLength(2);
  });

  it("a command reaches the node's socket", async () => {
    const { connect, hub } = await setup();
    const ws = connect("n1");
    const other = connect("n2");
    const response = await hub.fetch(
      post("/command", { nodeId: "n1", command }),
    );
    expect(response.status).toBe(200);
    expect(ws.replies()).toEqual([command]);
    expect(other.sent).toEqual([]);
  });

  it("a command for a node with no socket is OFFLINE", async () => {
    const { connect, hub } = await setup();
    connect("n1").close(1001, "gone");
    const response = await hub.fetch(
      post("/command", { nodeId: "n1", command }),
    );
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({ code: "OFFLINE" });
  });

  it("refuses a command that is not one", async () => {
    const { connect, hub } = await setup();
    connect("n1");
    const response = await hub.fetch(
      post("/command", { nodeId: "n1", command: { type: "ack", id: "a1" } }),
    );
    expect(response.status).toBe(400);
  });

  it("drop closes the node's sockets and no other", async () => {
    const { connect, hub } = await setup();
    const first = connect("n1");
    const other = connect("n2");
    const response = await hub.fetch(post("/drop", { nodeId: "n1" }));
    expect(response.status).toBe(204);
    expect(first.closed).toEqual({ code: 4001, reason: "removed" });
    expect(other.closed).toBeNull();
  });

  it("a late result from a removed node is closed, not stored", async () => {
    const { db, connect, say } = await setup();
    const ws = connect("n1");
    await db.prepare("DELETE FROM nodes WHERE id = 'n1'").run();
    await say(ws, {
      type: "result",
      id: "a1",
      ok: true,
      message: "Done",
      trust: { version: 4, core: ["Y29yZQ"], access: [] },
    });
    expect(ws.closed?.code).toBe(4401);
    expect(ws.sent).toEqual([]);
    expect(
      await db.prepare("SELECT version FROM node_trust").first(),
    ).toBeNull();
  });

  it("a server stays online after the hub forgets its memory", async () => {
    const harness = await setup();
    harness.connect("n1");
    harness.forget();
    const response = await harness.hub.fetch(
      new Request("https://fleet/online"),
    );
    expect(await response.json()).toEqual(["n1"]);
  });

  it("a second socket replaces the first", async () => {
    const { connect, hub } = await setup();
    const first = connect("n1");
    const second = connect("n1");
    expect(first.closed).toEqual({ code: 4000, reason: "replaced" });
    expect(second.closed).toBeNull();
    await hub.fetch(post("/command", { nodeId: "n1", command }));
    expect(second.replies()).toEqual([command]);
  });

  it("resent result is stored once and acked twice", async () => {
    const { db, writes, connect, watch, say } = await setup();
    const ws = connect("n1");
    const dashboard = watch();
    const result = { type: "result", id: "a1", ok: true, message: "Rebooted" };
    await say(ws, result);
    const stored = await db
      .prepare(
        "SELECT status, message, finished_at FROM actions WHERE id = 'a1'",
      )
      .first<{ status: string; message: string; finished_at: string }>();
    expect(stored).toMatchObject({ status: "done", message: "Rebooted" });
    await say(ws, { ...result, ok: false, message: "Again" });
    expect(
      await db
        .prepare(
          "SELECT status, message, finished_at FROM actions WHERE id = 'a1'",
        )
        .first(),
    ).toEqual(stored);
    expect(ws.replies()).toEqual([
      { type: "ack", id: "a1" },
      { type: "ack", id: "a1" },
    ]);
    expect(writes.filter((sql) => sql.includes("actions"))).toHaveLength(2);
    expect(dashboard.replies()).toEqual([
      { type: "changed", topics: ["fleet"] },
    ]);
  });

  it("a failed result is failed and its trust is stored", async () => {
    const { db, connect, say } = await setup();
    await say(connect("n1"), {
      type: "result",
      id: "a1",
      ok: false,
      message: "No",
      trust: { version: 4, core: ["Y29yZQ"], access: [] },
    });
    expect(
      await db.prepare("SELECT status FROM actions WHERE id = 'a1'").first(),
    ).toEqual({ status: "failed" });
    expect(await db.prepare("SELECT version FROM node_trust").first()).toEqual({
      version: 4,
    });
  });

  it("another node cannot finish an action", async () => {
    const { db, connect, say } = await setup();
    await say(connect("n2"), {
      type: "result",
      id: "a1",
      ok: true,
      message: "Done",
    });
    expect(
      await db.prepare("SELECT status FROM actions WHERE id = 'a1'").first(),
    ).toEqual({ status: "sent" });
  });

  it("progress reaches dashboards only and is not stored", async () => {
    const { writes, connect, watch, say } = await setup();
    const ws = connect("n1");
    const other = connect("n2");
    const dashboard = watch();
    await say(ws, { type: "progress", id: "a1", line: "Pulling image" });
    expect(dashboard.replies()).toEqual([
      { type: "progress", id: "a1", line: "Pulling image" },
    ]);
    expect(ws.sent).toEqual([]);
    expect(other.sent).toEqual([]);
    expect(writes).toEqual([]);
  });

  it("an invalid message is answered and the socket kept", async () => {
    const { writes, connect, say } = await setup();
    const ws = connect("n1");
    await say(ws, "{not json");
    await say(ws, { type: "result", id: "a1" });
    expect(ws.replies()).toEqual([
      { type: "error", code: "INVALID_MESSAGE" },
      { type: "error", code: "INVALID_MESSAGE" },
    ]);
    expect(ws.closed).toBeNull();
    expect(writes).toEqual([]);
  });

  it("closing writes last_seen_at and tells dashboards", async () => {
    const { db, connect, watch, hub } = await setup();
    const ws = connect("n1");
    const dashboard = watch();
    await hub.webSocketClose(ws as unknown as WebSocket);
    expect(
      await db
        .prepare(
          "SELECT last_seen_at IS NOT NULL AS seen FROM nodes WHERE id = 'n1'",
        )
        .first(),
    ).toEqual({ seen: 1 });
    expect(dashboard.replies()).toEqual([
      { type: "changed", topics: ["fleet"] },
    ]);
  });

  it("announces topics to dashboards", async () => {
    const { connect, watch, hub } = await setup();
    const ws = connect("n1");
    const dashboard = watch();
    await hub.fetch(post("/announce", { topics: ["fleet", 3] }));
    expect(dashboard.replies()).toEqual([
      { type: "changed", topics: ["fleet"] },
    ]);
    expect(ws.sent).toEqual([]);
  });

  it("an agent below MIN_AGENT is closed with 4426", async () => {
    const { connect, hub } = await setup();
    for (const version of ["0.7.25", null]) {
      const ws = connect("n1", version);
      expect(ws.closed?.code).toBe(4426);
    }
    const response = await hub.fetch(new Request("https://fleet/online"));
    expect(await response.json()).toEqual([]);
  });

  describe("silent sockets", () => {
    const START = Date.parse("2026-11-22T08:00:00.000Z");
    const at = (seconds: number) => vi.setSystemTime(START + seconds * 1000);

    it("closes a socket silent for more than 75 seconds and the node reads offline", async () => {
      vi.useFakeTimers({ now: START });
      const { db, connect, watch, hub, settled, fire } = await setup();
      const ws = connect("n1");
      await settled();
      const dashboard = watch();
      at(75);
      await fire();
      expect(ws.closed).toBeNull();
      expect(dashboard.replies()).toEqual([]);
      at(76);
      await fire();
      expect(ws.closed).toEqual({ code: 4408, reason: "silent" });
      const online = await hub.fetch(new Request("https://fleet/online"));
      expect(await online.json()).toEqual([]);
      expect(
        await db
          .prepare(
            "SELECT last_seen_at IS NOT NULL AS seen FROM nodes WHERE id = 'n1'",
          )
          .first(),
      ).toEqual({ seen: 1 });
      expect(dashboard.replies()).toEqual([
        { type: "changed", topics: ["fleet"] },
      ]);
      const refused = await hub.fetch(
        post("/command", { nodeId: "n1", command }),
      );
      expect(refused.status).toBe(409);
    });

    it("keeps a socket that pinged or spoke recently and closes only the silent one", async () => {
      vi.useFakeTimers({ now: START });
      const { connect, hub, settled, ping, say, fire } = await setup();
      const pinged = connect("n1");
      const spoke = connect("n2");
      const silent = connect("n3");
      await settled();
      at(90);
      ping(pinged);
      await say(spoke, { type: "progress", id: "a1", line: "Pulling" });
      at(120);
      await fire();
      expect(pinged.closed).toBeNull();
      expect(spoke.closed).toBeNull();
      expect(silent.closed).toEqual({ code: 4408, reason: "silent" });
      const online = await hub.fetch(new Request("https://fleet/online"));
      expect(await online.json()).toEqual(["n1", "n2"]);
    });

    it("counts a silence from the last ping when it is newer than the last message", async () => {
      vi.useFakeTimers({ now: START });
      const { connect, settled, ping, fire } = await setup();
      const ws = connect("n1");
      await settled();
      at(100);
      ping(ws);
      at(170);
      await fire();
      expect(ws.closed).toBeNull();
      at(176);
      await fire();
      expect(ws.closed?.code).toBe(4408);
    });

    it("reads a silent socket as offline and refuses a command before the alarm comes", async () => {
      vi.useFakeTimers({ now: START });
      const { connect, hub, settled, ping } = await setup();
      const silent = connect("n1");
      const pinged = connect("n2");
      await settled();
      const online = async () =>
        (await hub.fetch(new Request("https://fleet/online"))).json();
      at(75);
      expect(await online()).toEqual(["n1", "n2"]);
      at(100);
      ping(pinged);
      at(150);
      expect(await online()).toEqual(["n2"]);
      const refused = await hub.fetch(
        post("/command", { nodeId: "n1", command }),
      );
      expect(refused.status).toBe(409);
      expect(await refused.json()).toEqual({ code: "OFFLINE" });
      expect(silent.sent).toEqual([]);
      expect(silent.closed).toBeNull();
      const sent = await hub.fetch(post("/command", { nodeId: "n2", command }));
      expect(sent.status).toBe(200);
    });

    it("sets no alarm while no agent is connected", async () => {
      vi.useFakeTimers({ now: START });
      const harness = await setup();
      expect(harness.alarmAt()).toBeNull();
      harness.watch();
      harness.connect("n1", "0.7.25");
      await harness.settled();
      expect(harness.alarmAt()).toBeNull();
    });

    it("arms one alarm 60 seconds out for the first agent and leaves it for the next", async () => {
      vi.useFakeTimers({ now: START });
      const { connect, settled, alarmAt } = await setup();
      connect("n1");
      await settled();
      expect(alarmAt()).toBe(START + 60_000);
    });

    it("does not push the alarm out when another agent joins", async () => {
      vi.useFakeTimers({ now: START });
      const harness = await setup();
      harness.connect("n1");
      await harness.settled();
      at(30);
      harness.connect("n2");
      await harness.settled();
      expect(harness.alarmAt()).toBe(START + 60_000);
    });

    it("sets the next alarm 60 seconds on while an agent remains", async () => {
      vi.useFakeTimers({ now: START });
      const harness = await setup();
      const ws = harness.connect("n1");
      await harness.settled();
      at(60);
      harness.ping(ws);
      await harness.fire();
      expect(ws.closed).toBeNull();
      expect(harness.alarmAt()).toBe(START + 120_000);
    });

    it("does not set another alarm when the last agent was closed", async () => {
      vi.useFakeTimers({ now: START });
      const harness = await setup();
      const ws = harness.connect("n1");
      await harness.settled();
      at(200);
      await harness.fire();
      expect(ws.closed?.code).toBe(4408);
      expect(harness.alarmAt()).toBeNull();
    });

    it("does not set another alarm when the agent had already closed", async () => {
      vi.useFakeTimers({ now: START });
      const harness = await setup();
      harness.connect("n1").close(1001, "gone");
      await harness.settled();
      at(60);
      await harness.fire();
      expect(harness.alarmAt()).toBeNull();
    });
  });
});
