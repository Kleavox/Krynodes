import type { AgentActionsRequest } from "@krynodes/protocol";

import type { AgentNode } from "../agent/ingest";
import { applyInventory } from "./inventory";
import { actionResultStatements, sweepStatements } from "./store";

export async function receiveReport(
  db: D1Database,
  node: AgentNode,
  report: AgentActionsRequest,
  now: number,
): Promise<{ ok: true; inventoryHash: string | null }> {
  if (report.results && report.results.length > 0) {
    await db.batch([
      ...(await actionResultStatements(db, node.id, report.results, now)),
      ...sweepStatements(db, now),
    ]);
  }
  const inventoryHash = report.inventory
    ? await applyInventory(
        db,
        {
          id: node.id,
          inventory_hash: node.inventory_hash ?? null,
          refresh_requested_at: node.refresh_requested_at ?? null,
        },
        report.inventory,
        now,
      )
    : (node.inventory_hash ?? null);
  return { ok: true, inventoryHash };
}
