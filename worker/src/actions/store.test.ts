import type { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";

import { OWNER, seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";
import {
  actionResultStatements,
  cancelStatement,
  createBatch,
  DELIVER_SQL,
  deliverActions,
  EXPIRE_SQL,
  sweepStatements,
  type BatchMode,
} from "./store";

function recordStatements(sqlite: DatabaseSync): string[] {
  const statements: string[] = [];
  const prepare = sqlite.prepare.bind(sqlite);
  sqlite.prepare = ((sql: string) => {
    statements.push(sql);
    return prepare(sql);
  }) as typeof sqlite.prepare;
  return statements;
}

const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const C = "33333333-3333-4333-8333-333333333333";
const NOW = Date.parse("2026-09-29T10:00:00.000Z");
const MINUTE = 60_000;
const iso = (ms: number) => new Date(ms).toISOString();

function setup() {
  const { db, sqlite } = createTestDb();
  for (const id of [A, B, C]) seedNode(sqlite, { id });
  const queue = async (mode: BatchMode, nodes: string[], now = NOW) => {
    const batch = createBatch(db, {
      action: "restart",
      mode,
      targets: nodes.map((nodeId) => ({
        nodeId,
        kind: "docker" as const,
        name: "adguard",
      })),
      requestedBy: "owner@example.test",
      now,
    });
    await db.batch(batch.statements);
    return batch;
  };
  const sweep = (now: number) => db.batch(sweepStatements(db, now));
  const status = (id: string) =>
    (
      sqlite.prepare("SELECT status FROM actions WHERE id = ?").get(id) as {
        status: string;
      }
    ).status;
  const finish = async (nodeId: string, id: string, ok: boolean, now: number) =>
    db.batch([
      ...(await actionResultStatements(
        db,
        nodeId,
        [
          {
            id,
            ok,
            exitCode: ok ? 0 : 1,
            output: ok ? "" : "Job failed",
            finishedAt: iso(now),
          },
        ],
        now,
      )),
      ...sweepStatements(db, now),
    ]);
  return { db, sqlite, queue, sweep, status, finish };
}

describe("action batches", () => {
  it("delivers only the first action of a rolling batch and marks it sent", async () => {
    const { db, queue, status } = setup();
    const { actions } = await queue("rolling", [A, B]);
    const [first, second] = actions;
    expect(await deliverActions(db, B, NOW)).toEqual([]);
    expect(await deliverActions(db, A, NOW)).toEqual([
      {
        id: first!.id,
        kind: "docker",
        name: "adguard",
        action: "restart",
        expiresAt: iso(NOW + 10 * MINUTE),
      },
    ]);
    expect(status(first!.id)).toBe("sent");
    expect(await deliverActions(db, A, NOW)).toEqual([]);
    expect(status(second!.id)).toBe("queued");
  });

  it("gives the next server its turn once the previous one is done", async () => {
    const { db, queue, finish } = setup();
    const { actions } = await queue("rolling", [A, B]);
    const [first, second] = actions;
    await deliverActions(db, A, NOW);
    await finish(A, first!.id, true, NOW + MINUTE);
    const delivered = await deliverActions(db, B, NOW + MINUTE);
    expect(delivered.map((action) => action.id)).toEqual([second!.id]);
    expect(delivered[0]!.expiresAt).toBe(iso(NOW + 11 * MINUTE));
  });

  it("skips the rest of a rolling batch after a failure", async () => {
    const { db, queue, finish, status } = setup();
    const { actions } = await queue("rolling", [A, B, C]);
    const [first, second, third] = actions;
    await deliverActions(db, A, NOW);
    await finish(A, first!.id, false, NOW + MINUTE);
    expect(status(first!.id)).toBe("failed");
    expect(status(second!.id)).toBe("skipped");
    expect(status(third!.id)).toBe("skipped");
    expect(await deliverActions(db, B, NOW + MINUTE)).toEqual([]);
  });

  it("delivers every action of a parallel batch at once", async () => {
    const { db, queue } = setup();
    await queue("parallel", [A, B]);
    expect(await deliverActions(db, A, NOW)).toHaveLength(1);
    expect(await deliverActions(db, B, NOW)).toHaveLength(1);
  });

  it("expires an action nobody picked up within 10 minutes and skips what follows", async () => {
    const { queue, sweep, status } = setup();
    const { actions } = await queue("rolling", [A, B]);
    const [first, second] = actions;
    await sweep(NOW + 10 * MINUTE - 1);
    expect(status(first!.id)).toBe("queued");
    await sweep(NOW + 10 * MINUTE + 1);
    expect(status(first!.id)).toBe("expired");
    expect(status(second!.id)).toBe("skipped");
  });

  it("counts the ten minutes from the action's turn, not from the batch", async () => {
    const { db, queue, finish, sweep, status } = setup();
    const { actions } = await queue("rolling", [A, B]);
    const [first, second] = actions;
    await deliverActions(db, A, NOW + 9 * MINUTE);
    await finish(A, first!.id, true, NOW + 9.5 * MINUTE);
    await sweep(NOW + 15 * MINUTE);
    expect(status(second!.id)).toBe("queued");
    expect(await deliverActions(db, B, NOW + 15 * MINUTE)).toHaveLength(1);
  });

  it("fails an action that was sent but never answered", async () => {
    const { db, sqlite, queue, sweep, status } = setup();
    const { actions } = await queue("rolling", [A]);
    await deliverActions(db, A, NOW);
    await sweep(NOW + 10 * MINUTE + 1);
    expect(status(actions[0]!.id)).toBe("sent");
    await sweep(NOW + 15 * MINUTE - 1);
    expect(status(actions[0]!.id)).toBe("sent");
    await sweep(NOW + 15 * MINUTE + 1);
    expect(status(actions[0]!.id)).toBe("failed");
    expect(
      sqlite
        .prepare("SELECT output FROM actions WHERE id = ?")
        .get(actions[0]!.id),
    ).toEqual({ output: "No result from the server" });
  });

  it("accepts a result once, and only from the server it was sent to", async () => {
    const { db, queue, finish, status } = setup();
    const { actions } = await queue("rolling", [A]);
    const id = actions[0]!.id;
    await deliverActions(db, A, NOW);
    await finish(B, id, true, NOW + MINUTE);
    expect(status(id)).toBe("sent");
    await finish(A, id, true, NOW + MINUTE);
    expect(status(id)).toBe("done");
    await finish(A, id, false, NOW + 2 * MINUTE);
    expect(status(id)).toBe("done");
  });

  it("cancels only the queued actions, and only for their owner", async () => {
    const { db, queue, status } = setup();
    const { batchId, actions } = await queue("rolling", [A, B]);
    const [first, second] = actions;
    await deliverActions(db, A, NOW);
    const [stranger] = await db.batch([
      cancelStatement(db, batchId, "someone-else", NOW),
    ]);
    expect(stranger?.meta.changes).toBe(0);
    await db.batch([cancelStatement(db, batchId, OWNER, NOW)]);
    expect(status(first!.id)).toBe("sent");
    expect(status(second!.id)).toBe("cancelled");
  });

  it("keeps one pending action per service", async () => {
    const { queue } = setup();
    await queue("rolling", [A]);
    await expect(queue("rolling", [A])).rejects.toThrow(/UNIQUE/u);
  });

  it("stores the finish time the Worker can vouch for", async () => {
    const { db, sqlite, queue } = setup();
    const { actions } = await queue("parallel", [A, B, C]);
    await deliverActions(db, A, NOW);
    await deliverActions(db, B, NOW);
    await deliverActions(db, C, NOW);
    const [a, b, c] = actions;
    const report = async (nodeId: string, id: string, finishedAt: string) =>
      db.batch(
        await actionResultStatements(
          db,
          nodeId,
          [{ id, ok: true, exitCode: 0, output: "", finishedAt }],
          NOW + MINUTE,
        ),
      );
    await report(A, a!.id, "2026-09-29T10:00:05.123456789Z");
    await report(B, b!.id, "2030-01-01T00:00:00Z");
    await report(C, c!.id, "2026-09-29T09:00:00Z");
    const finished = (id: string) =>
      (
        sqlite
          .prepare("SELECT finished_at FROM actions WHERE id = ?")
          .get(id) as {
          finished_at: string;
        }
      ).finished_at;
    expect(finished(a!.id)).toBe("2026-09-29T10:00:05.123Z");
    expect(finished(b!.id)).toBe(iso(NOW + MINUTE));
    expect(finished(c!.id)).toBe(iso(NOW));
  });

  it("queues a whole batch in one statement", () => {
    const { db } = setup();
    const batch = createBatch(db, {
      action: "restart",
      mode: "rolling",
      targets: Array.from({ length: 50 }, (_, index) => ({
        nodeId: A,
        kind: "docker" as const,
        name: `c${index}`,
      })),
      requestedBy: "owner@example.test",
      now: NOW,
    });
    expect(batch.statements).toHaveLength(1);
    expect(batch.actions).toHaveLength(50);
  });

  it("delivers at most ten actions in a single statement", async () => {
    const { db, sqlite } = setup();
    const batch = createBatch(db, {
      action: "restart",
      mode: "parallel",
      targets: Array.from({ length: 12 }, (_, index) => ({
        nodeId: A,
        kind: "docker" as const,
        name: `c${index}`,
      })),
      requestedBy: "owner@example.test",
      now: NOW,
    });
    await db.batch(batch.statements);
    const statements = recordStatements(sqlite);
    const delivered = await deliverActions(db, A, NOW);
    expect(delivered).toHaveLength(10);
    expect(statements.filter((sql) => /\bactions\b/u.test(sql))).toHaveLength(
      1,
    );
    expect(
      sqlite
        .prepare("SELECT COUNT(*) AS sent FROM actions WHERE status = 'sent'")
        .get(),
    ).toEqual({ sent: 10 });
  });

  it("never hands out an action that was cancelled", async () => {
    const { db, queue } = setup();
    const { batchId } = await queue("parallel", [A]);
    await db.batch([cancelStatement(db, batchId, OWNER, NOW)]);
    expect(await deliverActions(db, A, NOW)).toEqual([]);
  });

  it("reads pending actions through indexes", () => {
    const { sqlite } = setup();
    const plan = (sql: string) =>
      sqlite
        .prepare(`EXPLAIN QUERY PLAN ${sql}`)
        .all()
        .map((row) => String((row as { detail: unknown }).detail))
        .join(" | ");
    expect(plan(DELIVER_SQL)).toMatch(
      /SEARCH actions USING (COVERING )?INDEX idx_actions_status_node \(status=\? AND node_id=\?\)/u,
    );
    expect(plan(DELIVER_SQL)).not.toMatch(/SCAN actions\b/u);
    expect(plan(EXPIRE_SQL)).toMatch(
      /SEARCH actions USING INDEX idx_actions_status_node \(status=\?\)/u,
    );
  });

  it("stores a signed compose action under the browser's id and delivers it", async () => {
    const { db, sqlite } = setup();
    const id = "55555555-5555-4555-8555-555555555555";
    const signed = {
      grant: {
        grant: "Z3JhbnQ",
        credentialId: "Y3JlZA",
        authenticatorData: "YXV0aA",
        clientDataJSON: "Y2xpZW50",
        signature: "c2ln",
      },
      command: "Y29tbWFuZA",
      signature: "c2lnbmF0dXJl",
    };
    const batch = createBatch(db, {
      action: "deploy",
      mode: "rolling",
      targets: [{ id, nodeId: A, kind: "compose", name: "listmonk", signed }],
      requestedBy: "owner@example.test",
      now: NOW,
    });
    expect(batch.actions[0]!.id).toBe(id);
    await db.batch(batch.statements);
    expect(
      sqlite.prepare("SELECT signed FROM actions WHERE id = ?").get(id),
    ).toEqual({ signed: JSON.stringify(signed) });
    expect(await deliverActions(db, A, NOW)).toEqual([
      {
        id,
        kind: "compose",
        name: "listmonk",
        action: "deploy",
        expiresAt: iso(NOW + 10 * MINUTE),
        signed,
      },
    ]);
  });

  it("delivers a restart without a signed payload", async () => {
    const { db, queue } = setup();
    await queue("rolling", [A]);
    const [delivered] = await deliverActions(db, A, NOW);
    expect(delivered).not.toHaveProperty("signed");
  });

  it("abandons a compose action after 30 minutes and a restart after 15", async () => {
    const { db, sqlite, queue, sweep, status } = setup();
    const { actions } = await queue("parallel", [A]);
    const deploy = createBatch(db, {
      action: "deploy",
      mode: "parallel",
      targets: [
        {
          id: "66666666-6666-4666-8666-666666666666",
          nodeId: B,
          kind: "compose",
          name: "listmonk",
          signed: { grant: { grant: "Zw" }, command: "Yw", signature: "cw" },
        },
      ],
      requestedBy: "owner@example.test",
      now: NOW,
    });
    await db.batch(deploy.statements);
    await deliverActions(db, A, NOW);
    await deliverActions(db, B, NOW);
    await sweep(NOW + 16 * MINUTE);
    expect(status(actions[0]!.id)).toBe("failed");
    expect(status("66666666-6666-4666-8666-666666666666")).toBe("sent");
    await sweep(NOW + 31 * MINUTE);
    expect(status("66666666-6666-4666-8666-666666666666")).toBe("failed");
    expect(
      sqlite.prepare("SELECT output FROM actions WHERE kind = 'compose'").get(),
    ).toEqual({ output: "No result from the server" });
  });
});
