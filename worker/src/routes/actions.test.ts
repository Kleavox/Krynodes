import { describe, expect, it } from "vitest";

import { toB64url } from "../lib/b64url";
import { addNode, testEnv } from "../test/env";

const signedCommand = (command: Record<string, unknown>) =>
  JSON.stringify({
    grant: {
      grant: "e30",
      credentialId: "cGsx",
      authenticatorData: "AAAA",
      clientDataJSON: "e30",
      signature: "c2ln",
    },
    command: toB64url(new TextEncoder().encode(JSON.stringify(command))),
    signature: "c2ln",
  });

const network = (
  verb: string,
  args?: Record<string, string>,
  extra: Record<string, unknown> = {},
) => ({
  nodeId: "n1",
  id: `net-${verb}`,
  kind: "network",
  name: "server-1",
  action: verb,
  title: `Network ${verb}`,
  signed: signedCommand({
    v: 1,
    id: `net-${verb}`,
    nodeId: "n1",
    kind: "network",
    name: "server-1",
    action: verb,
    issuedAt: "2026-11-22T00:00:00.000Z",
    expiresAt: "2026-11-22T01:00:00.000Z",
    ...(args ? { args } : {}),
    ...extra,
  }),
});

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

describe("network commands", () => {
  const request = (db: D1Database, ready: number, reason: string | null) =>
    db
      .prepare(
        "INSERT INTO network_members (node_id, state, ready, reason, since) VALUES ('n1', 'requested', ?1, ?2, '2026-11-22T00:00:00.000Z')",
      )
      .bind(ready, reason)
      .run();

  it("sends a signed network command whose arguments hold", async () => {
    const { db, send } = await fleet();
    await request(db, 1, null);
    for (const command of [
      network("inspect"),
      network("prepare", { range: "10.88.37.0/24", port: "51820" }),
      network("rekey", {}),
    ]) {
      expect((await send("POST", "/api/actions", command)).status).toBe(201);
    }
  });

  it("refuses arguments that do not hold or a command that is not the one named", async () => {
    const { db, send, hub } = await fleet();
    await request(db, 1, null);
    for (const command of [
      network("prepare", { range: "10.89.37.0/24", port: "51820" }),
      network("inspect", { extra: "1" }),
      network("tighten"),
      { ...network("inspect"), action: "rekey" },
      { ...network("inspect"), id: "other" },
      network("inspect", undefined, { kind: "host" }),
      { ...network("inspect"), signed: "c2lnbmVk" },
    ]) {
      expect((await send("POST", "/api/actions", command)).status).toBe(400);
    }
    expect(hub.calls).toEqual([]);
  });

  it("refuses to prepare a machine that is not ready, with its reason", async () => {
    const { db, send } = await fleet();
    await request(db, 0, "iptables is missing.");
    const prepare = network("prepare", {
      range: "10.88.37.0/24",
      port: "51820",
    });
    const response = await send("POST", "/api/actions", prepare);
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({
      code: "NOT_READY",
      message: "server-1 cannot join: iptables is missing.",
    });
    for (const verb of ["inspect", "rekey"]) {
      expect((await send("POST", "/api/actions", network(verb))).status).toBe(
        201,
      );
    }
    await db.prepare("DELETE FROM network_members").run();
    expect((await send("POST", "/api/actions", prepare)).status).toBe(409);
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
