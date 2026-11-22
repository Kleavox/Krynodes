import { describe, expect, it } from "vitest";

import { addNode, testEnv } from "../test/env";

const action = {
  nodeId: "n1",
  id: "a1",
  kind: "host",
  name: "server-1",
  action: "restart",
  title: "Restart server-1",
  signed: "c2lnbmVk",
};

async function fleet() {
  const harness = testEnv();
  await addNode(harness.db, "n1", "server-1");
  harness.hub.online.push("n1");
  return harness;
}

describe("POST /api/actions", () => {
  it("records the action as sent and hands the signed command to the hub", async () => {
    const { db, send, hub } = await fleet();
    const response = await send("POST", "/api/actions", action);
    expect(response.status).toBe(201);
    expect(await response.json()).toEqual({
      id: "a1",
      nodeId: "n1",
      kind: "host",
      name: "server-1",
      action: "restart",
      title: "Restart server-1",
      status: "sent",
      message: null,
      output: null,
      createdAt: expect.any(String),
      finishedAt: null,
    });
    expect(
      await db.prepare("SELECT status, node_id FROM actions").first(),
    ).toEqual({ status: "sent", node_id: "n1" });
    expect(hub.calls.map((call) => call.path)).toEqual([
      "/command",
      "/announce",
    ]);
    expect(hub.calls[0]!.body).toEqual({
      nodeId: "n1",
      command: {
        type: "command",
        id: "a1",
        kind: "host",
        name: "server-1",
        action: "restart",
        signed: "c2lnbmVk",
      },
    });
  });

  it("an action for an offline node leaves no row", async () => {
    const { db, send, hub } = await fleet();
    hub.online.length = 0;
    const response = await send("POST", "/api/actions", action);
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({
      code: "OFFLINE",
      message: "server-1 is offline.",
    });
    expect(await db.prepare("SELECT id FROM actions").first()).toBeNull();
    expect(hub.calls.map((call) => call.path)).toEqual(["/command"]);
  });

  it("accepts the four actions a node can run and nothing else", async () => {
    const { send } = await fleet();
    const status = async (
      kind: string,
      name: string,
      act: string,
      id: string,
    ) =>
      (
        await send("POST", "/api/actions", {
          ...action,
          id,
          kind,
          name,
          action: act,
        })
      ).status;
    expect(await status("trust", "devices", "apply", "t1")).toBe(201);
    expect(await status("agent", "server-1", "update", "t2")).toBe(201);
    expect(await status("agent", "server-1", "remove", "t3")).toBe(201);
    expect(await status("host", "server-1", "restart", "t4")).toBe(201);
    expect(await status("host", "server-1", "reboot", "t5")).toBe(400);
    expect(await status("trust", "devices", "update", "t6")).toBe(400);
    expect(await status("agent", "server-1", "restart", "t7")).toBe(400);
    expect(await status("stack", "x", "apply", "t8")).toBe(400);
  });

  it("refuses a malformed action before it touches anything", async () => {
    const { db, send, hub } = await fleet();
    for (const bad of [
      { ...action, name: "" },
      { ...action, id: "" },
      { ...action, id: "x".repeat(65) },
      { ...action, title: "" },
      { ...action, signed: "" },
      { ...action, extra: 1 },
      { ...action, nodeId: undefined },
    ]) {
      expect((await send("POST", "/api/actions", bad)).status).toBe(400);
    }
    expect(await db.prepare("SELECT id FROM actions").first()).toBeNull();
    expect(hub.calls).toEqual([]);
  });

  it("answers 404 for an unknown server and 409 for a reused id", async () => {
    const { send, hub } = await fleet();
    expect(
      (await send("POST", "/api/actions", { ...action, nodeId: "ghost" }))
        .status,
    ).toBe(404);
    expect((await send("POST", "/api/actions", action)).status).toBe(201);
    const again = await send("POST", "/api/actions", action);
    expect(again.status).toBe(409);
    expect(await again.json()).toMatchObject({ code: "ACTION_EXISTS" });
    expect(hub.calls.filter((call) => call.path === "/command")).toHaveLength(
      1,
    );
  });
});

describe("GET /api/actions", () => {
  const insert = (
    db: D1Database,
    id: string,
    node: string,
    status: string,
    createdAt: string,
  ) =>
    db
      .prepare(
        "INSERT INTO actions (id, node_id, kind, name, action, title, status, created_at) VALUES (?1, ?2, 'host', 'x', 'restart', 'Restart', ?3, ?4)",
      )
      .bind(id, node, status, createdAt)
      .run();

  it("lists newest first, for one server when asked", async () => {
    const { db, call } = await fleet();
    await addNode(db, "n2", "server-2");
    const now = Date.now();
    await insert(db, "old", "n1", "done", new Date(now - 3000).toISOString());
    await insert(db, "other", "n2", "done", new Date(now - 2000).toISOString());
    await insert(db, "new", "n1", "done", new Date(now - 1000).toISOString());
    const ids = async (query: string) =>
      (
        (await (await call(`/api/actions${query}`)).json()) as { id: string }[]
      ).map((row) => row.id);
    expect(await ids("")).toEqual(["new", "other", "old"]);
    expect(await ids("?node=n1")).toEqual(["new", "old"]);
    expect(await ids("?limit=1")).toEqual(["new"]);
  });

  it("returns 50 at most, and 50 when the limit is not a number", async () => {
    const { db, call } = await fleet();
    const now = Date.now();
    for (let index = 0; index < 60; index += 1) {
      await insert(
        db,
        `a${index}`,
        "n1",
        "done",
        new Date(now - index).toISOString(),
      );
    }
    const count = async (query: string) =>
      ((await (await call(`/api/actions${query}`)).json()) as unknown[]).length;
    expect(await count("")).toBe(50);
    expect(await count("?limit=500")).toBe(50);
    expect(await count("?limit=abc")).toBe(50);
    expect(await count("?limit=0")).toBe(50);
    expect(await count("?limit=3")).toBe(3);
  });

  it("an old sent action reads as no answer, without writing", async () => {
    const { db, call } = await fleet();
    const now = Date.now();
    await insert(
      db,
      "stale",
      "n1",
      "sent",
      new Date(now - 31 * 60_000).toISOString(),
    );
    await insert(
      db,
      "stale-running",
      "n1",
      "running",
      new Date(now - 45 * 60_000).toISOString(),
    );
    await insert(
      db,
      "fresh",
      "n1",
      "sent",
      new Date(now - 10 * 60_000).toISOString(),
    );
    await insert(
      db,
      "finished",
      "n1",
      "done",
      new Date(now - 90 * 60_000).toISOString(),
    );
    const rows = (await (await call("/api/actions")).json()) as {
      id: string;
      status: string;
      message: string | null;
    }[];
    expect(rows.map((row) => [row.id, row.status, row.message])).toEqual([
      ["fresh", "sent", null],
      ["stale", "failed", "No answer from server-1."],
      ["stale-running", "failed", "No answer from server-1."],
      ["finished", "done", null],
    ]);
    expect(
      await db.prepare("SELECT status FROM actions WHERE id = 'stale'").first(),
    ).toEqual({ status: "sent" });
  });
});
