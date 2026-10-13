import { describe, expect, it } from "vitest";

import { seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";
import { receiveReport } from "./report";
import { createBatch, deliverActions } from "./store";

const LEAVING = "11111111-1111-4111-8111-111111111111";
const HOLDER = "22222222-2222-4222-8222-222222222222";
const NOW = Date.parse("2026-10-13T10:00:00.000Z");
const SIGNED = { grant: { grant: "Zw" }, command: "Yw", signature: "cw" };

async function setup() {
  const { db, sqlite } = createTestDb();
  seedNode(sqlite, { id: LEAVING });
  seedNode(sqlite, { id: HOLDER });
  const batch = createBatch(db, {
    action: "store",
    mode: "rolling",
    targets: [
      {
        nodeId: HOLDER,
        kind: "vault",
        name: "cloudflare",
        action: "store",
        signed: SIGNED,
      },
      {
        nodeId: LEAVING,
        kind: "host",
        name: "server",
        action: "uninstall",
        signed: SIGNED,
      },
    ],
    requestedBy: "owner@example.test",
    now: NOW,
  });
  await db.batch(batch.statements);
  sqlite
    .prepare("UPDATE nodes SET deleting_batch = ? WHERE id = ?")
    .run(batch.batchId, LEAVING);
  const [store, uninstall] = batch.actions;
  const report = async (nodeId: string, id: string, ok: boolean) => {
    await deliverActions(db, nodeId, NOW);
    return receiveReport(
      db,
      { id: nodeId } as Parameters<typeof receiveReport>[1],
      {
        nodeId,
        results: [
          {
            id,
            ok,
            exitCode: ok ? 0 : 1,
            output: ok ? "" : "refused",
            finishedAt: new Date(NOW).toISOString(),
          },
        ],
      },
      NOW + 1_000,
    );
  };
  const ids = () =>
    (
      sqlite.prepare("SELECT id FROM nodes ORDER BY id").all() as {
        id: string;
      }[]
    ).map((row) => row.id);
  return { store: store!, uninstall: uninstall!, report, ids };
}

describe("a node deleted in the background", () => {
  it("goes once every step of its batch is done, and only then", async () => {
    const t = await setup();
    const first = await t.report(HOLDER, t.store.id, true);
    expect(first.deleted).toBe(false);
    expect(first.next).toEqual([LEAVING]);
    expect(t.ids()).toEqual([LEAVING, HOLDER]);
    const last = await t.report(LEAVING, t.uninstall.id, true);
    expect(last).toMatchObject({ deleted: true, inventoryHash: null });
    expect(t.ids()).toEqual([HOLDER]);
  });

  it("stays when a step fails", async () => {
    const t = await setup();
    const failed = await t.report(HOLDER, t.store.id, false);
    expect(failed.deleted).toBe(false);
    expect(failed.next).toEqual([]);
    expect(t.ids()).toEqual([LEAVING, HOLDER]);
  });
});
