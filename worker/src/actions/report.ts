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
): Promise<{ ok: true; inventoryHash: string | null; alerts: Finding[] }> {
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
  const alerts =
    inventoryHash !== (node.inventory_hash ?? null)
      ? newSerious(node.security, report.inventory?.security)
      : [];
  return { ok: true, inventoryHash, alerts };
}
