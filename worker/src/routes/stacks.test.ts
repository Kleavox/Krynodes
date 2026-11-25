import { describe, expect, it, vi } from "vitest";

import fixture from "../../../packages/protocol/src/fixtures/stack-args.json";
import worker from "../index";
import { toB64url } from "../lib/b64url";
import { freshDb } from "../test/db";
import { addNode, testEnv } from "../test/env";
import { hubHarness } from "../test/hub";
import { clearOldOutput } from "./actions";

const inventory = (hash: string, stacks: string[] = ["web"]) => ({
  type: "inventory",
  hash: hash.repeat(64),
  docker: "ready",
  compose: "2.29.1",
  stacks: stacks.map((project) => ({
    project,
    title: null,
    directory: `/var/lib/krynodes/stacks/${project}`,
    own: true,
    access: "contained",
    running: 1,
    total: 1,
    rollback: false,
    network: [],
    services: [{ service: "app", container: `${project}-app-1` }],
  })),
  containers: stacks.map((project) => ({
    name: `${project}-app-1`,
    project,
    service: "app",
    image: "nginx:1.27",
    state: "running",
    health: null,
    ports: ["127.0.0.1:8080->80/tcp"],
  })),
  units: [{ name: "nginx.service", state: "running", protected: false }],
  removed: [{ project: "old", removedAt: "2026-11-20T00:00:00.000Z" }],
});

const stored = (hash: string, stacks?: string[]) => {
  const { type: _type, hash: digest, ...body } = inventory(hash, stacks);
  return { digest, body: JSON.stringify(body) };
};

async function report(db: D1Database, nodeId: string, stacks?: string[]) {
  const { digest, body } = stored("a", stacks);
  await db
    .prepare(
      "INSERT INTO node_inventory (node_id, hash, body, updated_at) VALUES (?1, ?2, ?3, '2026-11-22T00:00:00.000Z')",
    )
    .bind(nodeId, digest, body)
    .run();
}

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

let next = 0;
const action = (
  kind: string,
  name: string,
  verb: string,
  args?: unknown,
  extra: Record<string, unknown> = {},
) => {
  next += 1;
  const id = `s${next}`;
  return {
    nodeId: "n1",
    id,
    kind,
    name,
    action: verb,
    title: `${verb} ${name}`,
    signed: signedCommand({
      v: 1,
      id,
      nodeId: "n1",
      kind,
      name,
      action: verb,
      issuedAt: "2026-11-22T00:00:00.000Z",
      expiresAt: "2026-11-22T01:00:00.000Z",
      ...(args === undefined ? {} : { args }),
      ...extra,
    }),
  };
};

async function fleet() {
  const harness = testEnv();
  await addNode(harness.db, "n1", "server-1");
  harness.hub.online.push("n1");
  return harness;
}

describe("inventory", () => {
  it("writes the inventory only when its hash changes", async () => {
    const db = freshDb();
    await addNode(db, "n1", "server-1");
    const reads: string[] = [];
    const writes: string[] = [];
    const counted = {
      prepare: (sql: string) => {
        (/^\s*(INSERT|UPDATE|DELETE)/iu.test(sql) ? writes : reads).push(sql);
        return db.prepare(sql);
      },
      batch: db.batch.bind(db),
    } as unknown as D1Database;
    const harness = hubHarness(counted);
    const ws = harness.connect("n1");
    await harness.settled();
    const watcher = harness.watch();
    await harness.say(ws, inventory("a"));
    await harness.say(ws, inventory("a"));
    expect(writes).toHaveLength(1);
    expect(reads).toEqual([]);
    expect(watcher.replies()).toEqual([
      { type: "changed", topics: ["stacks"] },
    ]);
    await harness.say(ws, inventory("b", ["web", "db"]));
    expect(writes).toHaveLength(2);
    const row = await db
      .prepare("SELECT hash, body FROM node_inventory WHERE node_id = 'n1'")
      .first<{ hash: string; body: string }>();
    expect(row?.hash).toBe("b".repeat(64));
    expect(JSON.parse(row!.body)).toEqual(
      JSON.parse(stored("b", ["web", "db"]).body),
    );
    harness.forget();
    await harness.say(ws, inventory("b", ["web", "db"]));
    expect(writes).toHaveLength(3);
    expect(watcher.replies()).toHaveLength(2);
  });

  it("stores a result's output on its action", async () => {
    const db = freshDb();
    await addNode(db, "n1", "server-1");
    await db
      .prepare(
        "INSERT INTO actions (id, node_id, kind, name, action, title, status, created_at) VALUES ('l1', 'n1', 'stack', 'web', 'logs', 'Logs', 'sent', ?)",
      )
      .bind(new Date().toISOString())
      .run();
    const harness = hubHarness(db);
    const ws = harness.connect("n1");
    await harness.settled();
    await harness.say(ws, {
      type: "result",
      id: "l1",
      ok: true,
      message: "server-1 sent 2 lines.",
      output: "one\ntwo\n",
    });
    expect(
      await db.prepare("SELECT output FROM actions WHERE id = 'l1'").first(),
    ).toEqual({ output: "one\ntwo\n" });
  });
});

describe("hub inventory boundaries", () => {
  async function counted() {
    const db = freshDb();
    await addNode(db, "n1", "server-1");
    await addNode(db, "n2", "server-2");
    const writes: string[] = [];
    const wrapped = {
      prepare: (sql: string) => {
        if (/^\s*(INSERT|UPDATE|DELETE)/iu.test(sql)) writes.push(sql);
        return db.prepare(sql);
      },
      batch: db.batch.bind(db),
    } as unknown as D1Database;
    return { db, writes, ...hubHarness(wrapped) };
  }

  const rows = (db: D1Database) =>
    db
      .prepare("SELECT node_id, hash FROM node_inventory ORDER BY node_id")
      .all<{ node_id: string; hash: string }>()
      .then((result) => result.results);

  it("refuses an inventory that carries another server's id and writes nothing", async () => {
    const { db, writes, connect, settled, say } = await counted();
    const ws = connect("n1");
    await settled();
    await say(ws, { ...inventory("a"), nodeId: "n2" });
    expect(ws.replies()).toEqual([{ type: "error", code: "INVALID_MESSAGE" }]);
    expect(writes).toEqual([]);
    expect(await rows(db)).toEqual([]);
  });

  it("two servers with different hashes write only their own rows", async () => {
    const { db, writes, connect, settled, say } = await counted();
    const one = connect("n1");
    const two = connect("n2");
    await settled();
    await say(one, inventory("a"));
    await say(two, inventory("b", ["db"]));
    await say(one, inventory("a"));
    expect(writes).toHaveLength(2);
    expect(await rows(db)).toEqual([
      { node_id: "n1", hash: "a".repeat(64) },
      { node_id: "n2", hash: "b".repeat(64) },
    ]);
  });

  it("skips an inventory over 1 MiB and logs it", async () => {
    const { db, writes, connect, settled, say } = await counted();
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const ws = connect("n1");
    await settled();
    const big = {
      ...inventory("c"),
      containers: Array.from({ length: 256 }, (_, index) => ({
        name: `big-${index}`,
        project: null,
        service: null,
        image: "x".repeat(512),
        state: "running",
        health: null,
        ports: Array.from({ length: 32 }, () => "p".repeat(128)),
      })),
    };
    await say(ws, big);
    await say(ws, big);
    expect(ws.replies()).toEqual([]);
    expect(writes).toEqual([]);
    expect(await rows(db)).toEqual([]);
    expect(warn).toHaveBeenCalledTimes(1);
    warn.mockRestore();
  });
});

describe("action output", () => {
  const insert = (db: D1Database, id: string, createdAt: string) =>
    db
      .prepare(
        "INSERT INTO actions (id, node_id, kind, name, action, title, status, message, output, created_at, finished_at) VALUES (?1, 'n1', 'stack', 'web', 'logs', 'Logs', 'done', 'ok', 'TOKEN=secret', ?2, ?2)",
      )
      .bind(id, createdAt)
      .run();

  it("the list leaves output out and the action itself carries it", async () => {
    const { db, call } = await fleet();
    await insert(db, "l1", new Date().toISOString());
    const listed = (await (await call("/api/actions")).json()) as Record<
      string,
      unknown
    >[];
    expect(listed).toHaveLength(1);
    expect(listed[0]).not.toHaveProperty("output");
    const one = await call("/api/actions/l1");
    expect(one.status).toBe(200);
    expect(await one.json()).toMatchObject({
      id: "l1",
      status: "done",
      output: "TOKEN=secret",
    });
    expect((await call("/api/actions/ghost")).status).toBe(404);
  });

  it("output older than a day is never shown and is cleared", async () => {
    const { db, call } = await fleet();
    const now = Date.now();
    await insert(db, "old", new Date(now - 25 * 60 * 60_000).toISOString());
    await insert(db, "new", new Date(now - 60_000).toISOString());
    expect(
      ((await (await call("/api/actions/old")).json()) as { output: unknown })
        .output,
    ).toBeNull();
    await clearOldOutput(db, now);
    expect(
      (
        await db
          .prepare("SELECT id, output FROM actions ORDER BY id")
          .all<{ id: string; output: string | null }>()
      ).results,
    ).toEqual([
      { id: "new", output: "TOKEN=secret" },
      { id: "old", output: null },
    ]);
  });

  it("the daily schedule clears old output", async () => {
    const { db, env } = await fleet();
    await insert(
      db,
      "old",
      new Date(Date.now() - 25 * 60 * 60_000).toISOString(),
    );
    const waits: Promise<unknown>[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("{}", { status: 500 })),
    );
    worker.scheduled({} as ScheduledController, env, {
      waitUntil: (promise: Promise<unknown>) => waits.push(promise),
    } as unknown as ExecutionContext);
    await Promise.allSettled(waits);
    vi.unstubAllGlobals();
    expect(
      await db.prepare("SELECT output FROM actions WHERE id = 'old'").first(),
    ).toEqual({ output: null });
  });
});

describe("GET /api/stacks", () => {
  it("lists every server with its stacks", async () => {
    const { db, call } = await fleet();
    await addNode(db, "n2", "server-2");
    await db
      .prepare(
        "INSERT INTO nodes (id, name, agent_token_hash, enrolled_at, kind) VALUES ('l1', 'laptop-1', 'hash-l1', '2026-11-22T00:00:00.000Z', 'laptop')",
      )
      .run();
    await report(db, "n1");
    const response = await call("/api/stacks");
    expect(response.status).toBe(200);
    const { body } = stored("a");
    expect(await response.json()).toEqual({
      nodes: [
        {
          nodeId: "n1",
          name: "server-1",
          online: true,
          ...JSON.parse(body),
          updatedAt: "2026-11-22T00:00:00.000Z",
        },
        {
          nodeId: "n2",
          name: "server-2",
          online: false,
          docker: null,
          compose: null,
          stacks: [],
          containers: [],
          units: [],
          removed: [],
          updatedAt: null,
        },
      ],
    });
  });

  it("deleting a server deletes its inventory", async () => {
    const { db, send, hub } = await fleet();
    hub.online.length = 0;
    await report(db, "n1");
    expect((await send("DELETE", "/api/nodes/n1")).status).toBe(200);
    expect(await db.prepare("SELECT * FROM node_inventory").first()).toBeNull();
  });
});

describe("stack actions", () => {
  const status = async (
    send: ReturnType<typeof testEnv>["send"],
    body: Record<string, unknown>,
  ) => {
    const response = await send("POST", "/api/actions", body);
    return { status: response.status, body: await response.json() };
  };

  it("refuses a protected unit before it reaches the server", async () => {
    const { db, send, hub } = await fleet();
    await report(db, "n1");
    for (const [kind, name] of [
      ["unit", "ssh.service"],
      ["unit", "systemd-resolved.service"],
      ["container", "krynodes-tunnel"],
    ] as const) {
      expect(await status(send, action(kind, name, "stop"))).toEqual({
        status: 400,
        body: {
          code: "REFUSED",
          message: `${name} is protected on server-1.`,
        },
      });
    }
    expect(hub.calls).toEqual([]);
    expect(await db.prepare("SELECT id FROM actions").first()).toBeNull();
    expect(
      (await status(send, action("unit", "nginx.service", "stop"))).status,
    ).toBe(201);
  });

  it("refuses stack args the agent would refuse", async () => {
    const { db, send, hub } = await fleet();
    await report(db, "n1");
    const nameOf = (kind: string, verb: string) => {
      if (kind === "container") return "web-app-1";
      if (kind === "unit") return "nginx.service";
      if (kind === "docker") return "docker";
      if (verb === "create") return "fresh";
      if (verb === "restore" || verb === "purge") return "old";
      return "web";
    };
    for (const entry of fixture.valid) {
      const result = await status(
        send,
        action(
          entry.kind,
          nameOf(entry.kind, entry.action),
          entry.action,
          entry.args,
        ),
      );
      expect(result.status, `${entry.kind}/${entry.action}`).toBe(201);
    }
    const sent = hub.calls.length;
    for (const entry of fixture.invalid) {
      const result = await status(
        send,
        action(
          entry.kind,
          nameOf(entry.kind, entry.action),
          entry.action,
          entry.args,
        ),
      );
      expect(result.status, entry.why).toBe(400);
    }
    expect(hub.calls).toHaveLength(sent);
  });

  it("refuses a command that is not the one named, naming the server", async () => {
    const { db, send, hub } = await fleet();
    await report(db, "n1");
    const mismatch =
      "The signed command does not match this request for server-1.";
    for (const [body, message] of [
      [{ ...action("stack", "web", "start"), name: "other" }, mismatch],
      [{ ...action("stack", "web", "start"), action: "stop" }, mismatch],
      [{ ...action("stack", "web", "start"), id: "other" }, mismatch],
      [
        action("stack", "web", "start", undefined, { kind: "container" }),
        mismatch,
      ],
      [{ ...action("stack", "web", "start"), signed: "c2lnbmVk" }, mismatch],
      [
        action("stack", "Web", "start"),
        "server-1 has no stack that could be named Web.",
      ],
      [
        action("unit", "nginx", "start"),
        "server-1 has no unit that could be named nginx.",
      ],
      [
        action("docker", "podman", "install"),
        "server-1 has no docker that could be named podman.",
      ],
      [
        action("stack", "web", "logs", { lines: "0" }),
        "server-1 would refuse the settings sent with this stack logs.",
      ],
      [
        action("container", "web-app-1", "start", { lines: "1" }),
        "server-1 would refuse the settings sent with this container start.",
      ],
    ] as const) {
      expect(await status(send, body)).toEqual({
        status: 400,
        body: { code: "REFUSED", message },
      });
    }
    expect(hub.calls).toEqual([]);
  });

  it("answers 404 before judging a stack command for an unknown server", async () => {
    const { send } = await fleet();
    const response = await status(send, {
      ...action("stack", "web", "start"),
      nodeId: "ghost",
    });
    expect(response.status).toBe(404);
  });

  it("refuses a stack name the inventory contradicts, naming the server", async () => {
    const { db, send } = await fleet();
    const save = {
      compose: "services:\n  app:\n    image: nginx:1.27\n",
      access: "contained",
      network: "",
    };
    expect(await status(send, action("stack", "web", "start"))).toEqual({
      status: 400,
      body: {
        code: "REFUSED",
        message: "server-1 has not reported its Docker inventory yet.",
      },
    });
    expect(
      (await status(send, action("stack", "web", "create", save))).body,
    ).toMatchObject({
      message: "server-1 has not reported its Docker inventory yet.",
    });
    await report(db, "n1");
    expect(await status(send, action("stack", "web", "create", save))).toEqual({
      status: 400,
      body: {
        code: "REFUSED",
        message: "A stack named web already runs on server-1.",
      },
    });
    expect(
      (await status(send, action("stack", "old", "create", save))).body,
    ).toEqual({
      code: "REFUSED",
      message: "A stack named old waits in Removed on server-1.",
    });
    expect(
      (await status(send, action("stack", "ghost", "deploy"))).body,
    ).toEqual({
      code: "REFUSED",
      message: "server-1 has no stack named ghost.",
    });
    expect(
      (await status(send, action("stack", "ghost", "restore"))).status,
    ).toBe(201);
    expect(
      (await status(send, action("stack", "fresh", "create", save))).status,
    ).toBe(201);
    expect((await status(send, action("stack", "web", "deploy"))).status).toBe(
      201,
    );
  });
});
