import { describe, expect, it } from "vitest";

import { addNode, testEnv } from "../test/env";

async function fleet() {
  const harness = testEnv();
  const { db } = harness;
  await addNode(db, "n1", "server-1", "0.7.90");
  await addNode(db, "n2", "server-2", "0.7.91");
  await db
    .prepare(
      "UPDATE nodes SET hostname = 'vps-1', os = 'linux', arch = 'amd64', last_seen_at = '2026-11-22T08:00:00.000Z' WHERE id = 'n1'",
    )
    .run();
  await db
    .prepare(
      "INSERT INTO node_trust (node_id, version, core, access, reported_at) VALUES ('n1', 3, '[\"d1\"]', '[\"d1\",\"d2\"]', '2026-11-22T08:00:00.000Z')",
    )
    .run();
  await db
    .prepare(
      "INSERT INTO agent_release (id, version, checked_at) VALUES (1, '0.7.91', '2026-11-22T00:00:00.000Z')",
    )
    .run();
  harness.hub.online.push("n1");
  return harness;
}

const stale = (db: D1Database, match: string, row: unknown) =>
  ({
    prepare: (sql: string) =>
      sql.includes(match)
        ? { bind: () => ({ first: async () => row }) }
        : db.prepare(sql),
    batch: db.batch.bind(db),
  }) as unknown as D1Database;

describe("GET /api/nodes", () => {
  it("lists every server with its state, trust and pending update", async () => {
    const { call } = await fleet();
    const response = await call("/api/nodes");
    expect(await response.json()).toEqual([
      {
        id: "n1",
        name: "server-1",
        hostname: "vps-1",
        os: "linux",
        arch: "amd64",
        version: "0.7.90",
        online: true,
        lastSeenAt: "2026-11-22T08:00:00.000Z",
        trust: { version: 3, core: ["d1"], access: ["d1", "d2"] },
        update: "0.7.91",
        kind: "server",
        address: null,
        via: null,
        ms: null,
        request: null,
      },
      {
        id: "n2",
        name: "server-2",
        hostname: null,
        os: null,
        arch: null,
        version: "0.7.91",
        online: false,
        lastSeenAt: null,
        trust: null,
        update: null,
        kind: "server",
        address: null,
        via: null,
        ms: null,
        request: null,
      },
    ]);
  });

  it("shows each machine's place in the private network", async () => {
    const { db, call } = await fleet();
    await addNode(db, "l1", "laptop-1", "0.7.92");
    await addNode(db, "n3", "server-3", "0.7.92");
    await db.prepare("UPDATE nodes SET kind = 'laptop' WHERE id = 'l1'").run();
    for (const [id, state, address] of [
      ["n1", "in", "10.88.37.10"],
      ["n2", "in", "10.88.37.20"],
      ["l1", "requested", null],
      ["n3", "rejected", null],
    ] as const) {
      await db
        .prepare(
          "INSERT INTO network_members (node_id, state, address, since) VALUES (?1, ?2, ?3, '2026-11-22T00:00:00.000Z')",
        )
        .bind(id, state, address)
        .run();
    }
    await db
      .prepare(
        "INSERT INTO network_links (a, b, answering, ms, since) VALUES ('n1', 'n2', 1, 4.25, '2026-11-22T00:00:00.000Z'), ('n2', 'n3', 0, NULL, '2026-11-22T00:00:00.000Z')",
      )
      .run();
    const list = (await (await call("/api/nodes")).json()) as Record<
      string,
      unknown
    >[];
    expect(
      list.map(({ name, kind, address, ms, request }) => ({
        name,
        kind,
        address,
        ms,
        request,
      })),
    ).toEqual([
      {
        name: "laptop-1",
        kind: "laptop",
        address: null,
        ms: null,
        request: "requested",
      },
      {
        name: "server-1",
        kind: "server",
        address: "10.88.37.10",
        ms: 4.25,
        request: null,
      },
      {
        name: "server-2",
        kind: "server",
        address: "10.88.37.20",
        ms: 4.25,
        request: null,
      },
      {
        name: "server-3",
        kind: "server",
        address: null,
        ms: null,
        request: "rejected",
      },
    ]);
  });

  it("names the member a laptop is relayed through, in one hub read", async () => {
    const { db, call, hub } = await fleet();
    await addNode(db, "l1", "laptop-1", "0.7.92");
    await db.prepare("UPDATE nodes SET kind = 'laptop' WHERE id = 'l1'").run();
    hub.via = { l1: "n1" };
    const list = (await (await call("/api/nodes")).json()) as {
      id: string;
      via: string | null;
    }[];
    expect(list.map(({ id, via }) => [id, via])).toEqual([
      ["l1", "n1"],
      ["n1", null],
      ["n2", null],
    ]);
    expect(hub.calls.map((one) => one.path).sort()).toEqual([
      "/online",
      "/via",
    ]);
  });

  it("a failed via read leaves every via null, and no laptop asks no via", async () => {
    const { db, call, hub } = await fleet();
    expect((await call("/api/nodes")).status).toBe(200);
    expect(hub.calls.map((one) => one.path)).toEqual(["/online"]);
    await addNode(db, "l1", "laptop-1", "0.7.92");
    await db.prepare("UPDATE nodes SET kind = 'laptop' WHERE id = 'l1'").run();
    hub.via = null;
    const response = await call("/api/nodes");
    expect(response.status).toBe(200);
    const list = (await response.json()) as { via: string | null }[];
    expect(list.map((one) => one.via)).toEqual([null, null, null]);
  });

  it("offers no update before a release is known or to a node of unknown version", async () => {
    const { db, call } = await fleet();
    await db.prepare("UPDATE nodes SET version = NULL WHERE id = 'n1'").run();
    await db.prepare("DELETE FROM agent_release").run();
    const list = (await (await call("/api/nodes")).json()) as {
      update: string | null;
    }[];
    expect(list.map((node) => node.update)).toEqual([null, null]);
  });
});

describe("PATCH /api/nodes/:id", () => {
  it("renames and tells dashboards", async () => {
    const { db, send, hub } = await fleet();
    const response = await send("PATCH", "/api/nodes/n1", { name: " web " });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ name: "web" });
    expect(
      await db.prepare("SELECT name FROM nodes WHERE id = 'n1'").first(),
    ).toEqual({ name: "web" });
    expect(hub.calls.map((call) => call.path)).toEqual(["/announce"]);
  });

  it("refuses a name whose network name another machine has, but not its own", async () => {
    const { db, send } = await fleet();
    const clash = await send("PATCH", "/api/nodes/n1", { name: "Server_2" });
    expect(clash.status).toBe(409);
    expect(await clash.json()).toEqual({
      code: "NAME_TAKEN",
      message:
        "Server_2 would have the same network name as server-2 (server-2.kry). Choose another name.",
    });
    expect(
      await db.prepare("SELECT name FROM nodes WHERE id = 'n1'").first(),
    ).toEqual({ name: "server-1" });
    expect(
      (await send("PATCH", "/api/nodes/n1", { name: "Server 1" })).status,
    ).toBe(200);
  });

  it("refuses a name with control characters", async () => {
    const { db, send } = await fleet();
    for (const name of [
      "web\r\nBcc: x@example.test",
      "web\u0007",
      "a\u0085b",
    ]) {
      expect((await send("PATCH", "/api/nodes/n1", { name })).status).toBe(400);
    }
    expect(
      await db.prepare("SELECT name FROM nodes WHERE id = 'n1'").first(),
    ).toEqual({ name: "server-1" });
  });

  it("refuses a taken name, an empty name and an unknown server", async () => {
    const { send } = await fleet();
    expect(
      (await send("PATCH", "/api/nodes/n1", { name: "server-2" })).status,
    ).toBe(409);
    expect((await send("PATCH", "/api/nodes/n1", { name: " " })).status).toBe(
      400,
    );
    expect(
      (await send("PATCH", "/api/nodes/ghost", { name: "x" })).status,
    ).toBe(404);
  });
});

describe("DELETE /api/nodes/:id", () => {
  it("removes an offline server with its trust and actions, after closing its socket", async () => {
    const { db, send, hub } = await fleet();
    await db
      .prepare(
        "INSERT INTO actions (id, node_id, kind, name, action, title, status, created_at) VALUES ('a1', 'n2', 'host', 'x', 'restart', 'Restart', 'sent', '2026-11-22T00:00:00.000Z')",
      )
      .run();
    const response = await send("DELETE", "/api/nodes/n2");
    expect(response.status).toBe(200);
    expect(
      await db.prepare("SELECT id FROM nodes WHERE id = 'n2'").first(),
    ).toBeNull();
    expect(await db.prepare("SELECT id FROM actions").first()).toBeNull();
    expect(hub.calls.map((call) => [call.path, call.body])).toEqual([
      ["/online", null],
      ["/drop", { nodeId: "n2" }],
      ["/announce", { topics: ["fleet"] }],
    ]);
  });

  it("refuses an online server that still has the agent", async () => {
    const { db, send, hub } = await fleet();
    const response = await send("DELETE", "/api/nodes/n1");
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({
      code: "STILL_INSTALLED",
      message: "Remove server-1 from its ⋯ menu first.",
    });
    expect(
      await db.prepare("SELECT id FROM nodes WHERE id = 'n1'").first(),
    ).toEqual({ id: "n1" });
    expect(hub.calls.some((call) => call.path === "/drop")).toBe(false);
  });

  it("removes an online server once its agent/remove is done, and only then", async () => {
    const { db, send } = await fleet();
    const remove = (status: string) =>
      db
        .prepare(
          "INSERT OR REPLACE INTO actions (id, node_id, kind, name, action, title, status, created_at) VALUES ('r1', 'n1', 'agent', 'server-1', 'remove', 'Remove', ?, '2026-11-22T00:00:00.000Z')",
        )
        .bind(status)
        .run();
    for (const status of ["sent", "failed"]) {
      await remove(status);
      expect((await send("DELETE", "/api/nodes/n1")).status).toBe(409);
    }
    await remove("done");
    expect((await send("DELETE", "/api/nodes/n1")).status).toBe(200);
    expect(
      await db.prepare("SELECT id FROM nodes WHERE id = 'n1'").first(),
    ).toBeNull();
  });

  it("a member cannot be deleted or removed", async () => {
    const { db, send, hub } = await fleet();
    await db
      .prepare(
        "INSERT INTO network_members (node_id, state, since) VALUES ('n1', 'in', '2026-11-22T00:00:00.000Z'), ('n2', 'in', '2026-11-22T00:00:00.000Z')",
      )
      .run();
    const deleted = await send("DELETE", "/api/nodes/n2");
    expect(deleted.status).toBe(409);
    expect(await deleted.json()).toEqual({
      code: "NETWORK_MEMBER",
      message: "Remove server-2 from the private network first.",
    });
    const removed = await send("POST", "/api/actions", {
      nodeId: "n1",
      id: "r1",
      kind: "agent",
      name: "server-1",
      action: "remove",
      title: "Remove server-1",
      signed: "c2lnbmVk",
    });
    expect(removed.status).toBe(409);
    expect(await removed.json()).toEqual({
      code: "NETWORK_MEMBER",
      message: "Remove server-1 from the private network first.",
    });
    expect(
      (await db.prepare("SELECT COUNT(*) AS n FROM nodes").first())?.n,
    ).toBe(2);
    expect(await db.prepare("SELECT id FROM actions").first()).toBeNull();
    expect(hub.calls.map((call) => call.path)).toEqual([]);
  });

  it("a server that became a member meanwhile is not deleted or dropped", async () => {
    const harness = await fleet();
    await harness.db
      .prepare(
        "INSERT INTO network_members (node_id, state, since) VALUES ('n2', 'in', '2026-11-22T00:00:00.000Z')",
      )
      .run();
    harness.env.DB = stale(
      harness.db,
      "SELECT 1 FROM network_members WHERE node_id = ? AND state = 'in'",
      null,
    );
    const response = await harness.send("DELETE", "/api/nodes/n2");
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({ code: "NETWORK_MEMBER" });
    expect(
      await harness.db.prepare("SELECT id FROM nodes WHERE id = 'n2'").first(),
    ).toEqual({ id: "n2" });
    expect(harness.hub.calls.some((call) => call.path === "/drop")).toBe(false);
  });

  it("answers 404 for an unknown server", async () => {
    const { send } = await fleet();
    expect((await send("DELETE", "/api/nodes/ghost")).status).toBe(404);
  });
});
