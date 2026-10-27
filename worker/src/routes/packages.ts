import type { MiddlewareHandler } from "hono";

import type { KrynodesApp, KrynodesEnv } from "./shared";

export function registerPackageRoutes(
  app: KrynodesApp,
  requireOperator: MiddlewareHandler<KrynodesEnv>,
): void {
  app.get("/api/nodes/:id/packages", requireOperator, async (context) => {
    const row = await context.env.DB.prepare(
      `SELECT n.inventory_at, p.report FROM nodes n
       LEFT JOIN packages p ON p.node_id = n.id
       WHERE n.id = ? AND n.owner_user_id = ?`,
    )
      .bind(context.req.param("id"), context.get("identity").id)
      .first<{ inventory_at: string | null; report: string | null }>();
    if (!row) return context.json({ code: "NOT_FOUND" }, 404);
    return context.json({
      report: row.report === null ? null : (JSON.parse(row.report) as unknown),
      readAt: row.inventory_at,
    });
  });

  app.get("/api/packages", requireOperator, async (context) => {
    const rows = await context.env.DB.prepare(
      `SELECT p.node_id, json_extract(item.value, '$.name') AS name
       FROM packages p
       JOIN nodes n ON n.id = p.node_id,
         json_each(p.report, '$.packages') AS item
       WHERE n.owner_user_id = ? AND n.disabled_at IS NULL
       ORDER BY p.node_id, name`,
    )
      .bind(context.get("identity").id)
      .all<{ node_id: string; name: string }>();
    const servers = new Map<string, string[]>();
    for (const row of rows.results) {
      servers.set(row.node_id, [...(servers.get(row.node_id) ?? []), row.name]);
    }
    return context.json({
      servers: [...servers].map(([nodeId, names]) => ({ nodeId, names })),
    });
  });
}
