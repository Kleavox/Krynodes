import { describe, expect, it } from "vitest";

import { app } from "../app";
import type { Env } from "../env";
import { runRetention } from "../index";
import { seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";

const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const C = "33333333-3333-4333-8333-333333333333";
const FOREIGN = "44444444-4444-4444-8444-444444444444";

const b64 = (value: unknown) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

const authData = (flags: number) =>
  Buffer.from(
    Uint8Array.from({ length: 37 }, (_, index) => (index === 32 ? flags : 0)),
  ).toString("base64url");
const VERIFIED = authData(0x05);

const signedFor = (target: {
  id: string;
  nodeId: string;
  kind: string;
  name: string;
  action: string;
}) => ({
  grant: {
    grant: "Z3JhbnQ",
    credentialId: "ZGV2aWNlLTE",
    authenticatorData: VERIFIED,
    clientDataJSON: "Y2xpZW50",
    signature: "c2ln",
  },
  command: b64({ v: 1, ...target }),
  signature: "c2lnbmF0dXJl",
});

interface Reply {
  code?: string;
  batchId?: string;
  cancelled?: number;
  refreshed?: number;
  actions?: Record<string, unknown>[];
  nodes?: { id: string; services: Record<string, unknown>[] }[];
}

const reply = async (response: Response | Promise<Response>) =>
  (await (await response).json()) as Reply;

function setup() {
  const { db, sqlite } = createTestDb();
  for (const [id, version, owner] of [
    [A, "0.5.0", undefined],
    [B, "0.5.0", undefined],
    [C, "0.5.0", undefined],
    [FOREIGN, "0.5.0", "someone-else"],
  ] as const) {
    seedNode(sqlite, { id, owner });
    sqlite
      .prepare(
        "UPDATE nodes SET agent_version = ?, last_seen_at = datetime('now') WHERE id = ?",
      )
      .run(version, id);
    sqlite
      .prepare(
        "INSERT INTO services (node_id, kind, name, state) VALUES (?, 'docker', 'adguard', 'running')",
      )
      .run(id);
  }
  sqlite
    .prepare(
      "INSERT INTO services (node_id, kind, name, state, system) VALUES (?, 'systemd', 'cron.service', 'running', 1)",
    )
    .run(A);
  const env = {
    DB: db,
    PUBLIC_ORIGIN: "https://kry.example.test",
  } as unknown as Env;
  const call = (method: string, path: string, body?: unknown) =>
    app.request(
      `https://kry.example.test${path}`,
      {
        method,
        headers: { "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      },
      env,
    );
  const restart = (
    targets: { nodeId: string; kind?: string; name?: string }[],
    mode?: string,
  ) =>
    call("POST", "/api/actions", {
      action: "restart",
      ...(mode ? { mode } : {}),
      targets: targets.map((target) => {
        const full = {
          id: crypto.randomUUID(),
          kind: "docker",
          name: "adguard",
          ...target,
        };
        return { ...full, signed: signedFor({ ...full, action: "restart" }) };
      }),
    });
  return { db, sqlite, env, call, restart };
}

describe("GET /api/services", () => {
  it("lists the owner's inventories and recent actions", async () => {
    const { call, restart } = setup();
    await restart([{ nodeId: A }]);
    const body = await reply(call("GET", "/api/services"));
    expect(body.nodes!.map((node) => node.id).sort()).toEqual([A, B, C].sort());
    const a = body.nodes!.find((node) => node.id === A);
    expect(a!.services).toEqual([
      {
        kind: "docker",
        name: "adguard",
        state: "running",
        since: null,
        system: false,
      },
      {
        kind: "systemd",
        name: "cron.service",
        state: "running",
        since: null,
        system: true,
      },
    ]);
    expect(body.actions).toEqual([
      expect.objectContaining({
        nodeId: A,
        kind: "docker",
        name: "adguard",
        action: "restart",
        status: "queued",
        mode: "rolling",
        position: 0,
        requestedBy: "standalone@localhost",
      }),
    ]);
  });

  it("reads the day's actions through the node index", () => {
    const { sqlite } = setup();
    const plan = sqlite
      .prepare(
        `EXPLAIN QUERY PLAN SELECT * FROM actions
         WHERE node_id IN (SELECT id FROM nodes WHERE owner_user_id = ?)
           AND requested_at >= ?`,
      )
      .all()
      .map((row) => String((row as { detail: unknown }).detail))
      .join(" | ");
    expect(plan).toMatch(/USING INDEX idx_actions_node_requested/u);
    expect(plan).not.toMatch(/SCAN actions\b/u);
  });
});

describe("POST /api/actions", () => {
  it("queues a rolling batch with only the first server's turn open", async () => {
    const { sqlite, restart } = setup();
    const response = await restart([{ nodeId: A }, { nodeId: B }]);
    expect(response.status).toBe(201);
    const body = await reply(response);
    expect(body.actions).toHaveLength(2);
    const rows = sqlite
      .prepare(
        "SELECT node_id, position, deliverable_at IS NOT NULL AS open, requested_by FROM actions ORDER BY position",
      )
      .all();
    expect(rows).toEqual([
      {
        node_id: A,
        position: 0,
        open: 1,
        requested_by: "standalone@localhost",
      },
      {
        node_id: B,
        position: 1,
        open: 0,
        requested_by: "standalone@localhost",
      },
    ]);
  });

  it("opens every turn at once in parallel mode", async () => {
    const { sqlite, restart } = setup();
    await restart([{ nodeId: A }, { nodeId: B }], "parallel");
    expect(
      sqlite
        .prepare(
          "SELECT COUNT(*) AS open FROM actions WHERE deliverable_at IS NOT NULL",
        )
        .get(),
    ).toEqual({ open: 2 });
  });

  it("refuses what it cannot or must not do", async () => {
    const { call, restart } = setup();
    expect(
      (await call("POST", "/api/actions", { action: "exec", targets: [] }))
        .status,
    ).toBe(400);
    expect((await restart([{ nodeId: A }, { nodeId: A }])).status).toBe(400);
    expect(
      (await restart([{ nodeId: A, kind: "systemd", name: "a;b.service" }]))
        .status,
    ).toBe(400);

    const protectedTarget = await restart([
      { nodeId: A, kind: "systemd", name: "ssh.service" },
    ]);
    expect(protectedTarget.status).toBe(422);
    expect((await reply(protectedTarget)).code).toBe("PROTECTED_TARGET");

    const unknown = await restart([{ nodeId: A, name: "ghost" }]);
    expect(unknown.status).toBe(422);
    expect((await reply(unknown)).code).toBe("UNKNOWN_TARGET");

    expect((await restart([{ nodeId: C }])).status).toBe(201);

    expect((await restart([{ nodeId: FOREIGN }])).status).toBe(404);

    expect((await restart([{ nodeId: A }])).status).toBe(201);
    const pending = await restart([{ nodeId: A }]);
    expect(pending.status).toBe(409);
    expect((await reply(pending)).code).toBe("ACTION_PENDING");
  });

  it("refuses an action whose session was opened with a touch", async () => {
    const { call } = setup();
    const target = {
      id: crypto.randomUUID(),
      nodeId: A,
      kind: "docker",
      name: "adguard",
    };
    const signed = signedFor({ ...target, action: "restart" });
    signed.grant.authenticatorData = authData(0x01);
    const response = await call("POST", "/api/actions", {
      action: "restart",
      targets: [{ ...target, signed }],
    });
    expect(response.status).toBe(400);
    expect((await reply(response)).code).toBe("FINGERPRINT_NEEDED");
  });

  it("refuses an unsigned restart and one signed for another service", async () => {
    const { call } = setup();
    const id = crypto.randomUUID();
    const target = { id, nodeId: A, kind: "docker", name: "adguard" };
    expect(
      (
        await call("POST", "/api/actions", {
          action: "restart",
          targets: [target],
        })
      ).status,
    ).toBe(400);
    const other = await call("POST", "/api/actions", {
      action: "restart",
      targets: [
        {
          ...target,
          signed: signedFor({ ...target, name: "nginx", action: "restart" }),
        },
      ],
    });
    expect(other.status).toBe(400);
    expect((await reply(other)).code).toBe("SIGNATURE_MISMATCH");
    const stop = await call("POST", "/api/actions", {
      action: "restart",
      targets: [
        { ...target, signed: signedFor({ ...target, action: "stop" }) },
      ],
    });
    expect((await reply(stop)).code).toBe("SIGNATURE_MISMATCH");
  });

  it("queues a signed restart of a server and refuses a mismatched one", async () => {
    const { call, sqlite } = setup();
    const target = {
      id: crypto.randomUUID(),
      nodeId: A,
      kind: "host",
      name: "server",
    };
    const ok = await call("POST", "/api/actions", {
      action: "reboot",
      targets: [
        { ...target, signed: signedFor({ ...target, action: "reboot" }) },
      ],
    });
    expect(ok.status).toBe(201);
    expect(
      sqlite.prepare("SELECT kind, name, action FROM actions").all(),
    ).toEqual([{ kind: "host", name: "server", action: "reboot" }]);
    const restart = await call("POST", "/api/actions", {
      action: "restart",
      targets: [
        {
          ...target,
          id: crypto.randomUUID(),
          signed: signedFor({ ...target, action: "restart" }),
        },
      ],
    });
    expect(restart.status).toBe(400);
    const other = await call("POST", "/api/actions", {
      action: "reboot",
      targets: [
        {
          ...target,
          id: crypto.randomUUID(),
          name: "other",
          signed: signedFor({ ...target, name: "other", action: "reboot" }),
        },
      ],
    });
    expect(other.status).toBe(400);
  });

  it("records which device signed each action", async () => {
    const { call, restart } = setup();
    await restart([{ nodeId: A }]);
    const body = await reply(call("GET", "/api/services"));
    expect(body.actions).toEqual([
      expect.objectContaining({ nodeId: A, deviceId: "ZGV2aWNlLTE" }),
    ]);
  });

  it("answers ACTION_PENDING when two requests race for one service", async () => {
    const { restart } = setup();
    const statuses = (
      await Promise.all([restart([{ nodeId: A }]), restart([{ nodeId: A }])])
    )
      .map((response) => response.status)
      .sort();
    expect(statuses).toEqual([201, 409]);
  });

  it("finds pending actions through the status index", () => {
    const { sqlite } = setup();
    const plan = sqlite
      .prepare(
        `EXPLAIN QUERY PLAN SELECT node_id, kind, name FROM actions
         WHERE status IN ('queued', 'sent')
           AND node_id IN (SELECT value FROM json_each(?))`,
      )
      .all()
      .map((row) => String((row as { detail: unknown }).detail))
      .join(" | ");
    expect(plan).toMatch(/USING INDEX idx_actions_status_node/u);
  });
});

describe("logs", () => {
  const logs = (
    call: ReturnType<typeof setup>["call"],
    nodeId: string,
    kind: string,
    name: string,
  ) => {
    const full = { id: crypto.randomUUID(), nodeId, kind, name };
    return call("POST", "/api/actions", {
      action: "logs",
      targets: [{ ...full, signed: signedFor({ ...full, action: "logs" }) }],
    });
  };

  it("reads logs, for protected units too, without blocking a restart", async () => {
    const { call, sqlite, restart } = setup();
    sqlite
      .prepare(
        "INSERT INTO services (node_id, kind, name, state, system) VALUES (?, 'systemd', 'ssh.service', 'running', 1)",
      )
      .run(A);
    sqlite
      .prepare(
        "INSERT INTO stacks (node_id, project, directory, running, total, compose, rollback, updated_at) VALUES (?, 'listmonk', '/opt/listmonk', 1, 1, 1, 0, datetime('now'))",
      )
      .run(A);
    expect((await logs(call, A, "docker", "adguard")).status).toBe(201);
    expect((await logs(call, A, "docker", "adguard")).status).toBe(201);
    expect((await logs(call, A, "systemd", "ssh.service")).status).toBe(201);
    expect((await logs(call, A, "compose", "listmonk")).status).toBe(201);
    expect((await restart([{ nodeId: A }])).status).toBe(201);
    expect((await logs(call, A, "docker", "adguard")).status).toBe(201);
  });

  it("keeps log text out of lists and serves it by id", async () => {
    const { call, sqlite, restart } = setup();
    await restart([{ nodeId: A }]);
    const created = await reply(logs(call, A, "docker", "adguard"));
    const id = created.actions![0]!.id as string;
    sqlite
      .prepare(
        "UPDATE actions SET status = 'done', output = 'line one', finished_at = datetime('now') WHERE id = ?",
      )
      .run(id);
    const listed = await reply(call("GET", "/api/services"));
    const entry = listed.actions!.find((action) => action.id === id);
    expect(entry).toMatchObject({ action: "logs", output: null });
    const history = await reply(call("GET", `/api/nodes/${A}/actions`));
    expect(history.actions!.map((action) => action.action)).toEqual([
      "restart",
    ]);
    const single = (await (await call("GET", `/api/actions/${id}`)).json()) as {
      action: Record<string, unknown>;
    };
    expect(single.action).toMatchObject({ id, output: "line one" });
    expect(
      (await call("GET", `/api/actions/${crypto.randomUUID()}`)).status,
    ).toBe(404);
  });

  it("refuses logs from older agents and for the server itself", async () => {
    const { call, sqlite } = setup();
    sqlite
      .prepare("UPDATE nodes SET agent_version = '0.4.1' WHERE id = ?")
      .run(B);
    const old = await logs(call, B, "docker", "adguard");
    expect(old.status).toBe(422);
    expect((await reply(old)).code).toBe("AGENT_TOO_OLD");
    expect((await logs(call, A, "host", "server")).status).toBe(400);
  });
});

describe("agents before 0.5.0", () => {
  it("are refused every action, a plain restart too", async () => {
    const { restart, sqlite } = setup();
    sqlite
      .prepare("UPDATE nodes SET agent_version = '0.4.1' WHERE id = ?")
      .run(B);
    const old = await restart([{ nodeId: A }, { nodeId: B }]);
    expect(old.status).toBe(422);
    expect(await reply(old)).toMatchObject({
      code: "AGENT_TOO_OLD",
      message: expect.stringContaining("0.5.0"),
    });
    expect(sqlite.prepare("SELECT COUNT(*) AS n FROM actions").get()).toEqual({
      n: 0,
    });
  });
});

describe("cancel, refresh, history and retention", () => {
  it("cancels the queued part of a batch", async () => {
    const { call, restart, sqlite } = setup();
    const { batchId } = await reply(restart([{ nodeId: A }, { nodeId: B }]));
    const body = await reply(call("POST", `/api/actions/${batchId}/cancel`));
    expect(body).toEqual({ cancelled: 2 });
    expect(sqlite.prepare("SELECT DISTINCT status FROM actions").all()).toEqual(
      [{ status: "cancelled" }],
    );
  });

  it("asks every reporting agent for a fresh inventory", async () => {
    const { call } = setup();
    const response = await call("POST", "/api/services/refresh", {});
    expect(response.status).toBe(202);
    expect(await reply(response)).toEqual({ refreshed: 3 });
    expect(
      await reply(call("POST", "/api/services/refresh", { nodeIds: [C] })),
    ).toEqual({ refreshed: 1 });
  });

  it("returns a node's ten newest actions", async () => {
    const { call, sqlite } = setup();
    for (let index = 0; index < 12; index += 1) {
      sqlite
        .prepare(
          `INSERT INTO actions (id, batch_id, position, mode, node_id, kind, name, action, status, requested_by, requested_at)
           VALUES (?, ?, 0, 'rolling', ?, 'docker', 'adguard', 'restart', 'done', 'o', ?)`,
        )
        .run(
          crypto.randomUUID(),
          crypto.randomUUID(),
          A,
          new Date(Date.UTC(2026, 8, 29, 10, index)).toISOString(),
        );
    }
    const body = await reply(call("GET", `/api/nodes/${A}/actions`));
    expect(body.actions).toHaveLength(10);
    expect(body.actions![0]!.requestedAt).toBe("2026-09-29T10:11:00.000Z");
    expect((await call("GET", `/api/nodes/${FOREIGN}/actions`)).status).toBe(
      404,
    );
  });

  it("deleting a node removes its actions and services", async () => {
    const { call, restart, sqlite } = setup();
    await restart([{ nodeId: A }]);
    sqlite.prepare("DELETE FROM nodes WHERE id = ?").run(A);
    expect(sqlite.prepare("SELECT COUNT(*) AS n FROM actions").get()).toEqual({
      n: 0,
    });
    expect(
      sqlite
        .prepare("SELECT COUNT(*) AS n FROM services WHERE node_id = ?")
        .get(A),
    ).toEqual({ n: 0 });
    expect((await call("GET", "/api/services")).status).toBe(200);
  });

  it("pages the history newest first without losing a batch at the edge", async () => {
    const { call, sqlite } = setup();
    const insert = sqlite.prepare(
      `INSERT INTO actions (id, batch_id, position, mode, node_id, kind, name, action, status, requested_by, requested_at)
       VALUES (?, ?, ?, 'rolling', ?, 'docker', 'adguard', 'restart', 'done', 'o', ?)`,
    );
    const at = (minute: number) =>
      new Date(Date.UTC(2026, 8, 29, 10, minute)).toISOString();
    const ids: string[] = [];
    for (let minute = 0; minute < 5; minute += 1) {
      const id = `old-${minute}`;
      insert.run(id, id, 0, A, at(minute));
      ids.push(id);
    }
    for (let position = 0; position < 3; position += 1) {
      const id = `batch-${position}`;
      insert.run(id, "batch", position, [A, B, C][position]!, at(10));
      ids.push(id);
    }
    for (let minute = 20; minute < 68; minute += 1) {
      const id = `new-${minute}`;
      insert.run(id, id, 0, B, at(minute));
      ids.push(id);
    }
    const first = (await (await call("GET", "/api/history")).json()) as {
      actions: { id: string; requestedAt: string }[];
      next: string | null;
    };
    expect(first.actions).toHaveLength(50);
    expect(first.actions[0]!.id).toBe("new-67");
    expect(first.next).not.toBeNull();
    const second = (await (
      await call(
        "GET",
        `/api/history?before=${encodeURIComponent(first.next!)}`,
      )
    ).json()) as { actions: { id: string }[]; next: string | null };
    expect(second.next).toBeNull();
    const seen = [...first.actions, ...second.actions].map(
      (action) => action.id,
    );
    expect(new Set(seen).size).toBe(seen.length);
    expect([...seen].sort()).toEqual([...ids].sort());
  });

  it("filters the history by server, leaves out other owners, trust updates and log text", async () => {
    const { call, sqlite } = setup();
    const insert = sqlite.prepare(
      `INSERT INTO actions (id, batch_id, position, mode, node_id, kind, name, action, status, requested_by, requested_at, output)
       VALUES (?, ?, 0, 'parallel', ?, 'docker', 'adguard', ?, 'done', 'o', ?, ?)`,
    );
    const now = new Date().toISOString();
    insert.run("on-a", "b1", A, "restart", now, "restarted");
    insert.run("logs-a", "b2", A, "logs", now, "secret lines");
    insert.run("on-b", "b3", B, "restart", now, null);
    insert.run("foreign", "b4", FOREIGN, "restart", now, null);
    sqlite
      .prepare(
        `INSERT INTO actions (id, batch_id, position, mode, node_id, kind, name, action, status, requested_by, requested_at)
         VALUES ('trust-a', 'b5', 0, 'parallel', ?, 'trust', 'devices', 'trust', 'done', 'o', ?)`,
      )
      .run(A, now);
    const all = (await (await call("GET", "/api/history")).json()) as {
      actions: { id: string; output: string | null }[];
    };
    expect(all.actions.map((action) => action.id).sort()).toEqual([
      "logs-a",
      "on-a",
      "on-b",
    ]);
    expect(
      all.actions.find((action) => action.id === "logs-a")!.output,
    ).toBeNull();
    expect(all.actions.find((action) => action.id === "on-a")!.output).toBe(
      "restarted",
    );
    const onB = (await (
      await call("GET", `/api/history?node=${B}`)
    ).json()) as {
      actions: { id: string }[];
    };
    expect(onB.actions.map((action) => action.id)).toEqual(["on-b"]);
  });

  it("forgets actions after 90 days", async () => {
    const { env, sqlite } = setup();
    for (const [id, days] of [
      ["old", 91],
      ["new", 89],
    ] as const) {
      sqlite
        .prepare(
          `INSERT INTO actions (id, batch_id, position, mode, node_id, kind, name, action, status, requested_by, requested_at)
           VALUES (?, ?, 0, 'rolling', ?, 'docker', 'adguard', 'restart', 'done', 'o', ?)`,
        )
        .run(id, id, A, new Date(Date.now() - days * 86_400_000).toISOString());
    }
    await runRetention(env);
    expect(sqlite.prepare("SELECT id FROM actions").all()).toEqual([
      { id: "new" },
    ]);
  });
});

describe("stack, container and auto-restart commands", () => {
  function newer() {
    const t = setup();
    t.sqlite
      .prepare(
        "UPDATE nodes SET agent_version = '0.5.0', docker = 'ready' WHERE id IN (?, ?)",
      )
      .run(A, B);
    t.sqlite.prepare("UPDATE nodes SET docker = 'missing' WHERE id = ?").run(B);
    t.sqlite
      .prepare(
        "INSERT INTO stacks (node_id, project, directory, running, total, compose, rollback, updated_at) VALUES (?, 'kuma', '/var/lib/kry-exec/compose/kuma', 1, 1, 1, 0, datetime('now'))",
      )
      .run(A);
    t.sqlite
      .prepare(
        "INSERT INTO services (node_id, kind, name, state) VALUES (?, 'systemd', 'nginx.service', 'running')",
      )
      .run(A);
    const send = (
      action: string,
      target: { nodeId: string; kind: string; name: string },
      signed = true,
    ) => {
      const id = crypto.randomUUID();
      return t.call("POST", "/api/actions", {
        action,
        targets: [
          {
            ...target,
            id,
            ...(signed ? { signed: signedFor({ ...target, id, action }) } : {}),
          },
        ],
      });
    };
    return { ...t, send };
  }

  it("starts, stops, restarts and removes a stack, only on a current agent", async () => {
    const t = newer();
    for (const verb of ["start", "stop", "restart", "remove"]) {
      const response = await t.send(verb, {
        nodeId: A,
        kind: "compose",
        name: "kuma",
      });
      expect(response.status, verb).toBe(201);
      t.sqlite.prepare("UPDATE actions SET status = 'done'").run();
    }
    t.sqlite
      .prepare("UPDATE nodes SET agent_version = '0.4.1' WHERE id = ?")
      .run(A);
    const old = await t.send("restart", {
      nodeId: A,
      kind: "compose",
      name: "kuma",
    });
    expect(old.status).toBe(422);
    expect((await reply(old)).code).toBe("AGENT_TOO_OLD");
  });

  it("removes a container but never a unit", async () => {
    const t = newer();
    expect(
      (await t.send("remove", { nodeId: A, kind: "docker", name: "adguard" }))
        .status,
    ).toBe(201);
    expect(
      (
        await t.send("remove", {
          nodeId: A,
          kind: "systemd",
          name: "nginx.service",
        })
      ).status,
    ).toBe(400);
  });

  it("creates a stack only under a free name on a server with Docker", async () => {
    const t = newer();
    expect(
      (await t.send("create", { nodeId: A, kind: "compose", name: "uptime" }))
        .status,
    ).toBe(201);
    const taken = await t.send("create", {
      nodeId: A,
      kind: "compose",
      name: "kuma",
    });
    expect(taken.status).toBe(409);
    expect((await reply(taken)).code).toBe("STACK_EXISTS");
    const missing = await t.send("create", {
      nodeId: B,
      kind: "compose",
      name: "uptime",
    });
    expect(missing.status).toBe(422);
    expect((await reply(missing)).code).toBe("NO_DOCKER");
    expect(
      (
        await t.send(
          "create",
          { nodeId: A, kind: "compose", name: "other" },
          false,
        )
      ).status,
    ).toBe(400);
  });

  it("turns auto-restart on with a signature for a unit a SERVICE check watches, and off without one", async () => {
    const t = newer();
    const unit = { nodeId: A, kind: "systemd", name: "nginx.service" };
    const unwatched = await t.send("autorestart", unit);
    expect(unwatched.status).toBe(422);
    expect((await reply(unwatched)).code).toBe("NO_CHECK");
    t.sqlite
      .prepare(
        "INSERT INTO checks (id, node_id, name, kind, target, enabled) VALUES ('c1', ?, 'nginx', 'SERVICE', 'nginx', 1)",
      )
      .run(A);
    expect((await t.send("autorestart", unit, false)).status).toBe(400);
    expect((await t.send("autorestart", unit)).status).toBe(201);
    t.sqlite.prepare("UPDATE actions SET status = 'done'").run();
    expect((await t.send("manual", unit, false)).status).toBe(201);
    expect(
      t.sqlite
        .prepare(
          "SELECT action, signed IS NULL AS bare FROM actions ORDER BY requested_at, action",
        )
        .all(),
    ).toEqual([
      { action: "autorestart", bare: 0 },
      { action: "manual", bare: 1 },
    ]);
  });
});

describe("removed stacks", () => {
  function withRemoved() {
    const t = setup();
    t.sqlite
      .prepare(
        "UPDATE nodes SET agent_version = '0.5.0', docker = 'ready' WHERE id = ?",
      )
      .run(A);
    t.sqlite
      .prepare(
        "INSERT INTO stacks (node_id, project, directory, running, total, compose, rollback, updated_at) VALUES (?, 'kuma', '/var/lib/kry-exec/compose/kuma', 1, 1, 1, 0, datetime('now'))",
      )
      .run(A);
    t.sqlite
      .prepare(
        "INSERT INTO removed_stacks (node_id, project, directory, removed_at) VALUES (?, 'old', '/home/alice/old', '2026-10-04T10:00:00.000Z')",
      )
      .run(A);
    const send = (action: string, name: string) => {
      const id = crypto.randomUUID();
      const target = { nodeId: A, kind: "compose", name };
      return t.call("POST", "/api/actions", {
        action,
        targets: [
          { ...target, id, signed: signedFor({ ...target, id, action }) },
        ],
      });
    };
    return { ...t, send };
  }

  it("lists removed stacks with each server", async () => {
    const t = withRemoved();
    const body = (await (await t.call("GET", "/api/services")).json()) as {
      nodes: { id: string; removed: unknown[] }[];
    };
    expect(body.nodes.find((node) => node.id === A)!.removed).toEqual([
      {
        project: "old",
        directory: "/home/alice/old",
        removedAt: "2026-10-04T10:00:00.000Z",
      },
    ]);
  });

  it("restores and deletes a removed stack, never restores a running one", async () => {
    const t = withRemoved();
    expect((await t.send("restore", "old")).status).toBe(201);
    t.sqlite.prepare("UPDATE actions SET status = 'done'").run();
    expect((await t.send("purge", "old")).status).toBe(201);
    t.sqlite.prepare("UPDATE actions SET status = 'done'").run();
    const running = await t.send("restore", "kuma");
    expect(running.status).toBe(422);
    expect((await reply(running)).code).toBe("UNKNOWN_TARGET");
  });

  it("keeps New stack away from a name waiting in Removed", async () => {
    const t = withRemoved();
    const taken = await t.send("create", "old");
    expect(taken.status).toBe(409);
    expect((await reply(taken)).code).toBe("STACK_EXISTS");
  });
});
