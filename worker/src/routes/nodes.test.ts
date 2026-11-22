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
      },
    ]);
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

  it("answers 404 for an unknown server", async () => {
    const { send } = await fleet();
    expect((await send("DELETE", "/api/nodes/ghost")).status).toBe(404);
  });
});
