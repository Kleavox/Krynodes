import { TAILSCALE } from "@krynodes/protocol";
import type { MiddlewareHandler } from "hono";

import {
  agentOrigin,
  type KrynodesApp,
  type KrynodesEnv,
} from "../routes/shared";

interface TailnetRow {
  tailnet: string;
  client_id: string;
  set_id: string | null;
  rules: string;
  block: string | null;
  lines: string;
  members: string;
  saved_at: string | null;
  saved_by: string | null;
  connected_at: string;
}

interface AlarmRow {
  id: string;
  kind: "device" | "policy";
  detail: string;
  at: string;
}

function parsed<T>(text: string | null, fallback: T): T {
  try {
    return (JSON.parse(text ?? "null") as T | null) ?? fallback;
  } catch {
    return fallback;
  }
}

export function registerTailscaleRoutes(
  app: KrynodesApp,
  requireOperator: MiddlewareHandler<KrynodesEnv>,
): void {
  app.get("/api/tailscale", requireOperator, async (context) => {
    const db = context.env.DB;
    const owner = context.get("identity").id;
    const [row, nodes, alarms] = await Promise.all([
      db
        .prepare(
          `SELECT tailnet, client_id, set_id, rules, block, lines, members, saved_at, saved_by,
                  connected_at
           FROM tailscale WHERE owner_user_id = ?`,
        )
        .bind(owner)
        .first<TailnetRow>(),
      db
        .prepare(
          `SELECT n.id, n.name, n.tailscale, n.tailscale_vault, n.security, t.node_id IS NOT NULL AS signed
           FROM nodes n LEFT JOIN tailscale_nodes t ON t.node_id = n.id
           WHERE n.owner_user_id = ? AND n.enrolled_at IS NOT NULL AND n.disabled_at IS NULL
           ORDER BY n.name`,
        )
        .bind(owner)
        .all<{
          id: string;
          name: string;
          tailscale: string | null;
          tailscale_vault: string | null;
          security: string | null;
          signed: number;
        }>(),
      db
        .prepare(
          `SELECT id, kind, detail, at FROM tailscale_alarms
           WHERE owner_user_id = ? AND raised_at IS NOT NULL AND cleared_at IS NULL
           ORDER BY at`,
        )
        .bind(owner)
        .all<AlarmRow>(),
    ]);
    return context.json({
      hook: `${agentOrigin(context.env)}${TAILSCALE.hook}`,
      connected: row
        ? {
            tailnet: row.tailnet,
            clientId: row.client_id,
            setId: row.set_id,
            rules: parsed<unknown[]>(row.rules, []),
            block: row.block,
            lines: parsed<string[]>(row.lines, []),
            members: parsed<string[]>(row.members, []),
            savedAt: row.saved_at,
            savedBy: row.saved_by,
            connectedAt: row.connected_at,
          }
        : null,
      servers: nodes.results.map((node) => ({
        nodeId: node.id,
        name: node.name,
        report: parsed<unknown>(node.tailscale, null),
        vault: parsed<unknown>(node.tailscale_vault, null),
        signedIn: node.signed === 1,
        listeners:
          parsed<{ listeners?: unknown[] } | null>(node.security, null)
            ?.listeners ?? [],
      })),
      alarms: alarms.results.map((alarm) => {
        const detail = parsed<Record<string, unknown>>(alarm.detail, {});
        return {
          id: alarm.id,
          kind: alarm.kind,
          at: alarm.at,
          ...(alarm.kind === "device"
            ? { device: detail }
            : { change: detail }),
        };
      }),
    });
  });
}
