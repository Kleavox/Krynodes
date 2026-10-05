import type { AgentHeartbeat } from "@krynodes/protocol";
import { describe, expect, it } from "vitest";

import { createBatch } from "../actions/store";
import { hubHarness, type FakeSocket } from "../test/hub";
import { seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";

const A = "11111111-1111-4111-8111-111111111111";

interface Reply {
  actions?: { id: string; kind: string; name: string; action: string }[];
  refresh?: boolean;
  ok?: boolean;
  inventoryHash?: string | null;
}
const B = "22222222-2222-4222-8222-222222222222";

async function setup() {
  const { db, sqlite } = createTestDb();
  for (const id of [A, B]) {
    seedNode(sqlite, { id });
    sqlite
      .prepare("UPDATE nodes SET agent_version = '0.6.0' WHERE id = ?")
      .run(id);
    sqlite
      .prepare(
        "INSERT INTO services (node_id, kind, name, state) VALUES (?, 'docker', 'adguard', 'running')",
      )
      .run(id);
  }
  const hub = hubHarness({ DB: db });
  const sockets = new Map<string, FakeSocket>();
  const send = async (
    nodeId: string,
    type: string,
    fields: Record<string, unknown>,
  ) => {
    let socket = sockets.get(nodeId);
    if (!socket) {
      socket = await hub.connect(nodeId);
      sockets.set(nodeId, socket);
    }
    return (await hub.request(socket, type, fields)) ?? {};
  };
  const heartbeat = (
    nodeId: string,
    results: AgentHeartbeat["results"] = undefined,
    version = "0.6.0",
  ): AgentHeartbeat => ({
    nodeId,
    hostname: "web-01",
    operatingSystem: "Debian 12.10",
    architecture: "amd64",
    agentVersion: version,
    metrics: {
      cpuPercent: 10,
      memoryUsedBytes: 1,
      memoryTotalBytes: 2,
      diskUsedBytes: 1,
      diskTotalBytes: 2,
      load1: 0.1,
      load5: 0.1,
      load15: 0.1,
      uptimeSeconds: 60,
    },
    ...(results ? { results } : {}),
  });
  const queue = async (nodes: string[]) => {
    const batch = createBatch(db, {
      action: "restart",
      mode: "rolling",
      targets: nodes.map((nodeId) => ({
        nodeId,
        kind: "docker" as const,
        name: "adguard",
      })),
      requestedBy: "owner@example.test",
      now: Date.now(),
    });
    await db.batch(batch.statements);
    return batch.actions;
  };
  const status = (id: string) =>
    (
      sqlite.prepare("SELECT status FROM actions WHERE id = ?").get(id) as {
        status: string;
      }
    ).status;
  const beat = async (
    nodeId: string,
    results: AgentHeartbeat["results"] = undefined,
    version?: string,
  ) =>
    ((
      await send(nodeId, "heartbeat", {
        heartbeat: heartbeat(nodeId, results, version),
      })
    ).response ?? {}) as Reply;
  const report = (nodeId: string, report: Record<string, unknown>) =>
    send(nodeId, "actions", { report });
  return { sqlite, db, beat, report, queue, status };
}

describe("agent service actions", () => {
  it("hands queued actions to the heartbeat once", async () => {
    const { beat, queue, status } = await setup();
    const [action] = await queue([A]);
    expect((await beat(A)).actions).toEqual([
      expect.objectContaining({
        id: action!.id,
        kind: "docker",
        name: "adguard",
        action: "restart",
      }),
    ]);
    expect(status(action!.id)).toBe("sent");
    expect((await beat(A)).actions).toBeUndefined();
  });

  it("asks for a fresh inventory while a refresh is pending", async () => {
    const { sqlite, beat } = await setup();
    sqlite
      .prepare("UPDATE nodes SET refresh_requested_at = ? WHERE id = ?")
      .run(new Date().toISOString(), A);
    expect((await beat(A)).refresh).toBe(true);
  });

  it("records a result and gives the next server its turn", async () => {
    const { beat, report, queue, status } = await setup();
    const [first, second] = await queue([A, B]);
    await beat(A);
    const answer = await report(A, {
      nodeId: A,
      results: [
        {
          id: first!.id,
          ok: true,
          exitCode: 0,
          output: "",
          finishedAt: new Date().toISOString(),
        },
      ],
    });
    expect(answer).toMatchObject({
      type: "actions",
      response: { ok: true, inventoryHash: null },
    });
    expect(status(first!.id)).toBe("done");
    expect((await beat(B)).actions?.[0]?.id).toBe(second!.id);
  });

  it("ignores a result sent by another server", async () => {
    const { beat, report, queue, status } = await setup();
    const [action] = await queue([A]);
    await beat(A);
    await report(B, {
      nodeId: B,
      results: [
        {
          id: action!.id,
          ok: true,
          exitCode: 0,
          output: "",
          finishedAt: new Date().toISOString(),
        },
      ],
    });
    expect(status(action!.id)).toBe("sent");
    expect(
      await report(B, { nodeId: A, inventory: { hash: "a".repeat(64) } }),
    ).toMatchObject({ type: "error", code: "INVALID_MESSAGE" });
  });

  it("acknowledges an inventory with its hash", async () => {
    const { report } = await setup();
    expect(
      await report(A, {
        nodeId: A,
        inventory: {
          hash: "c".repeat(64),
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
      }),
    ).toMatchObject({
      type: "actions",
      response: { ok: true, inventoryHash: "c".repeat(64) },
    });
  });
});

describe("docker state and auto-restart", () => {
  const CHECK = "c0c0c0c0-0000-4000-8000-000000000001";
  const down = [
    {
      checkId: CHECK,
      status: "DOWN" as const,
      latencyMs: null,
      message: "failed",
    },
  ];

  async function watched(autoRestart: boolean) {
    const t = await setup();
    t.sqlite
      .prepare(
        "INSERT INTO checks (id, node_id, name, kind, target, enabled, auto_restart) VALUES (?, ?, 'nginx', 'SERVICE', 'nginx.service', 1, ?)",
      )
      .run(CHECK, A, autoRestart ? 1 : 0);
    const heals = () =>
      t.sqlite
        .prepare(
          "SELECT name, status, requested_by FROM actions WHERE action = 'heal'",
        )
        .all();
    return { ...t, heals };
  }

  it("keeps the Docker state the server reports", async () => {
    const { sqlite, report } = await setup();
    await report(A, {
      nodeId: A,
      inventory: { hash: "d".repeat(64), docker: "ready", services: [] },
    });
    expect(
      sqlite.prepare("SELECT docker FROM nodes WHERE id = ?").get(A),
    ).toEqual({ docker: "ready" });
  });

  it("restarts an auto-restart unit once when its check turns red, never while yellow", async () => {
    const t = await watched(true);
    await t.beat(A, down);
    expect(t.heals()).toEqual([]);
    const red = await t.beat(A, down);
    expect(red.actions?.map((action) => action.action)).toEqual(["heal"]);
    expect(t.heals()).toEqual([
      { name: "nginx.service", status: "sent", requested_by: "Krynodes" },
    ]);
    await t.beat(A, down);
    expect(t.heals()).toHaveLength(1);
  });

  it("heals the full unit name when the check names it without .service", async () => {
    const t = await watched(true);
    t.sqlite
      .prepare("UPDATE checks SET target = 'nginx' WHERE id = ?")
      .run(CHECK);
    await t.beat(A, down);
    await t.beat(A, down);
    expect(t.heals()).toEqual([
      { name: "nginx.service", status: "sent", requested_by: "Krynodes" },
    ]);
  });

  it("leaves a red check alone when auto-restart is off or the agent is older", async () => {
    const off = await watched(false);
    await off.beat(A, down);
    await off.beat(A, down);
    expect(off.heals()).toEqual([]);
    const old = await watched(true);
    await old.beat(A, down, "0.3.5");
    await old.beat(A, down, "0.3.5");
    expect(old.heals()).toEqual([]);
  });

  it("turns a check's auto-restart on and off as the server confirms it", async () => {
    const t = await watched(false);
    const flag = () =>
      (
        t.sqlite
          .prepare("SELECT auto_restart FROM checks WHERE id = ?")
          .get(CHECK) as {
          auto_restart: number;
        }
      ).auto_restart;
    const run = async (action: "autorestart" | "manual", ok: boolean) => {
      const batch = createBatch(t.db, {
        action,
        mode: "parallel",
        targets: [{ nodeId: A, kind: "systemd", name: "nginx.service" }],
        requestedBy: "owner@example.test",
        now: Date.now(),
      });
      await t.db.batch(batch.statements);
      await t.beat(A);
      await t.report(A, {
        nodeId: A,
        results: [
          {
            id: batch.actions[0]!.id,
            ok,
            exitCode: ok ? 0 : 1,
            output: "",
            finishedAt: new Date().toISOString(),
          },
        ],
      });
    };
    t.sqlite
      .prepare("UPDATE checks SET target = 'nginx' WHERE id = ?")
      .run(CHECK);
    await run("autorestart", false);
    expect(flag()).toBe(0);
    await run("autorestart", true);
    expect(flag()).toBe(1);
    await run("manual", true);
    expect(flag()).toBe(0);
  });
});

describe("removals from the dashboard", () => {
  it("drop the stack or container as soon as the server confirms, and keep it when it fails", async () => {
    const t = await setup();
    t.sqlite
      .prepare(
        "INSERT INTO stacks (node_id, project, directory, running, total, compose, rollback, updated_at) VALUES (?, ?, '/var/lib/kry-exec/compose/' || ?, 1, 1, 1, 0, datetime('now'))",
      )
      .run(A, "kuma", "kuma");
    t.sqlite
      .prepare(
        "INSERT INTO stacks (node_id, project, directory, running, total, compose, rollback, updated_at) VALUES (?, ?, '/opt/' || ?, 1, 1, 1, 0, datetime('now'))",
      )
      .run(A, "shop", "shop");
    const finish = async (
      action: "purge" | "remove",
      kind: "compose" | "docker",
      name: string,
      ok: boolean,
    ) => {
      const batch = createBatch(t.db, {
        action,
        mode: "parallel",
        targets: [{ nodeId: A, kind, name }],
        requestedBy: "owner@example.test",
        now: Date.now(),
      });
      await t.db.batch(batch.statements);
      await t.beat(A);
      await t.report(A, {
        nodeId: A,
        results: [
          {
            id: batch.actions[0]!.id,
            ok,
            exitCode: ok ? 0 : 1,
            output: ok ? "" : "down failed",
            finishedAt: new Date().toISOString(),
          },
        ],
      });
    };
    const stacks = () =>
      t.sqlite.prepare("SELECT project FROM stacks ORDER BY project").all();
    const containers = () =>
      t.sqlite
        .prepare(
          "SELECT name FROM services WHERE kind = 'docker' AND node_id = ?",
        )
        .all(A);
    await finish("purge", "compose", "shop", false);
    expect(stacks()).toEqual([{ project: "kuma" }, { project: "shop" }]);
    await finish("purge", "compose", "kuma", true);
    expect(stacks()).toEqual([{ project: "shop" }]);
    await finish("remove", "docker", "adguard", true);
    expect(containers()).toEqual([]);
  });
});

describe("the Removed list", () => {
  it("mirrors what the server reports", async () => {
    const { sqlite, report } = await setup();
    await report(A, {
      nodeId: A,
      inventory: {
        hash: "e".repeat(64),
        services: [],
        removed: [
          {
            project: "kuma",
            directory: "/var/lib/kry-exec/compose/kuma",
            removedAt: "2026-10-05T10:00:00.000Z",
          },
        ],
      },
    });
    expect(
      sqlite
        .prepare("SELECT project, directory, removed_at FROM removed_stacks")
        .all(),
    ).toEqual([
      {
        project: "kuma",
        directory: "/var/lib/kry-exec/compose/kuma",
        removed_at: "2026-10-05T10:00:00.000Z",
      },
    ]);
  });

  it("moves a stack in at once on Remove and out on Restore or Delete permanently", async () => {
    const t = await setup();
    t.sqlite
      .prepare(
        "INSERT INTO stacks (node_id, project, directory, running, total, compose, rollback, updated_at) VALUES (?, 'kuma', '/var/lib/kry-exec/compose/kuma', 1, 1, 1, 0, datetime('now'))",
      )
      .run(A);
    const finish = async (action: "remove" | "restore" | "purge") => {
      const batch = createBatch(t.db, {
        action,
        mode: "parallel",
        targets: [{ nodeId: A, kind: "compose", name: "kuma" }],
        requestedBy: "owner@example.test",
        now: Date.now(),
      });
      await t.db.batch(batch.statements);
      await t.beat(A);
      await t.report(A, {
        nodeId: A,
        results: [
          {
            id: batch.actions[0]!.id,
            ok: true,
            exitCode: 0,
            output: "",
            finishedAt: new Date().toISOString(),
          },
        ],
      });
    };
    const removed = () =>
      t.sqlite.prepare("SELECT project, directory FROM removed_stacks").all();
    await finish("remove");
    expect(removed()).toEqual([
      { project: "kuma", directory: "/var/lib/kry-exec/compose/kuma" },
    ]);
    expect(t.sqlite.prepare("SELECT project FROM stacks").all()).toEqual([]);
    await finish("restore");
    expect(removed()).toEqual([]);
    t.sqlite
      .prepare(
        "INSERT INTO removed_stacks (node_id, project, directory, removed_at) VALUES (?, 'kuma', '/x', '2026-10-05T10:00:00.000Z')",
      )
      .run(A);
    await finish("purge");
    expect(removed()).toEqual([]);
  });
});
