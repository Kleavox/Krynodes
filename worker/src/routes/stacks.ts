import type { KrynodesApp } from "../env";
import { onlineNodes } from "../fleet/client";

interface Row {
  id: string;
  name: string;
  body: string | null;
  updated_at: string | null;
}

const EMPTY = {
  docker: null,
  compose: null,
  stacks: [],
  containers: [],
  units: [],
  removed: [],
};

export function registerStackRoutes(app: KrynodesApp): void {
  app.get("/api/stacks", async (context) => {
    const [rows, online] = await Promise.all([
      context.env.DB.prepare(
        `SELECT n.id, n.name, i.body, i.updated_at
         FROM nodes n LEFT JOIN node_inventory i ON i.node_id = n.id
         WHERE n.kind = 'server'
         ORDER BY n.name`,
      ).all<Row>(),
      onlineNodes(context.env),
    ]);
    return context.json({
      nodes: rows.results.map((row) => ({
        nodeId: row.id,
        name: row.name,
        online: online.has(row.id),
        ...(row.body ? (JSON.parse(row.body) as typeof EMPTY) : EMPTY),
        updatedAt: row.updated_at,
      })),
    });
  });
}
