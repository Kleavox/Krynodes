import type { AgentActionsRequest } from "@krynodes/protocol";

import type { AgentNode } from "../agent/ingest";
import { applyInventory } from "./inventory";
import { actionResultStatements, sweepStatements } from "./store";

export interface Finding {
  id: string;
  severity: string;
  detail: string;
}

function newSerious(
  before: string | null | undefined,
  after: { findings: Finding[] } | undefined,
): Finding[] {
  if (!after) return [];
  let known: string[] = [];
  try {
    const parsed = JSON.parse(before ?? "null") as {
      findings?: Finding[];
    } | null;
    known = (parsed?.findings ?? [])
      .filter((finding) => finding.severity === "serious")
      .map((finding) => finding.id);
  } catch {
    known = [];
  }
  return after.findings.filter(
    (finding) => finding.severity === "serious" && !known.includes(finding.id),
  );
}

export async function receiveReport(
  db: D1Database,
  node: AgentNode,
  report: AgentActionsRequest,
  now: number,
): Promise<{
  ok: true;
  inventoryHash: string | null;
  alerts: Finding[];
  next: string[];
  deleted: boolean;
}> {
  let next: string[] = [];
  let deleted = false;
  if (report.results && report.results.length > 0) {
    const ids = JSON.stringify(report.results.map((result) => result.id));
    const done = await db.batch([
      ...(await actionResultStatements(db, node.id, report.results, now)),
      ...sweepStatements(db, now),
      db
        .prepare(
          `DELETE FROM nodes
           WHERE deleting_batch IN (SELECT batch_id FROM actions
             WHERE id IN (SELECT value FROM json_each(?)))
             AND NOT EXISTS (SELECT 1 FROM actions
               WHERE batch_id = nodes.deleting_batch AND status <> 'done')`,
        )
        .bind(ids),
    ]);
    if ((done.at(-1)?.meta.changes ?? 0) > 0) {
      deleted = true;
      const gone = !(await db
        .prepare("SELECT id FROM nodes WHERE id = ?")
        .bind(node.id)
        .first());
      if (gone) {
        return { ok: true, inventoryHash: null, alerts: [], next, deleted };
      }
    }
    const waiting = await db
      .prepare(
        `SELECT DISTINCT node_id FROM actions
         WHERE status = 'queued' AND deliverable_at IS NOT NULL
           AND batch_id IN (SELECT batch_id FROM actions
             WHERE id IN (SELECT value FROM json_each(?)))`,
      )
      .bind(ids)
      .all<{ node_id: string }>();
    next = waiting.results.map((row) => row.node_id);
  }
  if (report.progress && report.progress.length > 0) {
    await db.batch(
      report.progress.map((step) => {
        const reported = Date.parse(step.at);
        const at = new Date(Math.min(reported, now)).toISOString();
        return db
          .prepare(
            `UPDATE actions SET progress = ?1
             WHERE id = ?2 AND node_id = ?3 AND status = 'sent' AND progress IS NOT ?1`,
          )
          .bind(
            JSON.stringify({
              at,
              done: step.done,
              total: step.total,
              line: step.line,
            }),
            step.id,
            node.id,
          );
      }),
    );
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
  const alerts =
    inventoryHash !== (node.inventory_hash ?? null)
      ? newSerious(node.security, report.inventory?.security)
      : [];
  return { ok: true, inventoryHash, alerts, next, deleted };
}
