import { compareVersions, type TrustReport } from "@krynodes/protocol";
import { z } from "zod";

import { readAgentRelease } from "../agent/releases";
import type { KrynodesApp } from "../env";
import { announce, dropNode, onlineNodes } from "../fleet/client";
import { invalidRequest, isUnique, readJson } from "./shared";

const renameSchema = z.strictObject({ name: z.string().trim().min(1).max(64) });

interface NodeRow {
  id: string;
  name: string;
  hostname: string | null;
  os: string | null;
  arch: string | null;
  version: string | null;
  last_seen_at: string | null;
  trust_version: number | null;
  core: string | null;
  access: string | null;
}

export function registerNodeRoutes(app: KrynodesApp): void {
  app.get("/api/nodes", async (context) => {
    const db = context.env.DB;
    const [rows, online, release] = await Promise.all([
      db
        .prepare(
          `SELECT n.id, n.name, n.hostname, n.os, n.arch, n.version, n.last_seen_at,
                  t.version AS trust_version, t.core, t.access
           FROM nodes n LEFT JOIN node_trust t ON t.node_id = n.id
           ORDER BY n.name`,
        )
        .all<NodeRow>(),
      onlineNodes(context.env),
      readAgentRelease(db),
    ]);
    return context.json(
      rows.results.map((row) => ({
        id: row.id,
        name: row.name,
        hostname: row.hostname,
        os: row.os,
        arch: row.arch,
        version: row.version,
        online: online.has(row.id),
        lastSeenAt: row.last_seen_at,
        trust:
          row.trust_version === null
            ? null
            : ({
                version: row.trust_version,
                core: JSON.parse(row.core!) as string[],
                access: JSON.parse(row.access!) as string[],
              } satisfies TrustReport),
        update:
          release.version &&
          row.version &&
          compareVersions(release.version, row.version) > 0
            ? release.version
            : null,
      })),
    );
  });

  app.patch("/api/nodes/:id", async (context) => {
    const body = renameSchema.safeParse(await readJson(context));
    if (!body.success) return invalidRequest(context);
    let renamed: D1Result;
    try {
      renamed = await context.env.DB.prepare(
        "UPDATE nodes SET name = ? WHERE id = ?",
      )
        .bind(body.data.name, context.req.param("id"))
        .run();
    } catch (error) {
      if (!isUnique(error)) throw error;
      return context.json(
        {
          code: "NAME_TAKEN",
          message: `${body.data.name} is already a server. Choose another name.`,
        },
        409,
      );
    }
    if (!renamed.meta.changes) return context.json({ code: "NOT_FOUND" }, 404);
    await announce(context.env, ["fleet"]);
    return context.json({ name: body.data.name });
  });

  app.delete("/api/nodes/:id", async (context) => {
    const db = context.env.DB;
    const id = context.req.param("id");
    const node = await db
      .prepare("SELECT name FROM nodes WHERE id = ?")
      .bind(id)
      .first<{ name: string }>();
    if (!node) return context.json({ code: "NOT_FOUND" }, 404);
    if ((await onlineNodes(context.env)).has(id)) {
      const removed = await db
        .prepare(
          "SELECT 1 FROM actions WHERE node_id = ? AND kind = 'agent' AND action = 'remove' AND status = 'done'",
        )
        .bind(id)
        .first();
      if (!removed) {
        return context.json(
          {
            code: "STILL_INSTALLED",
            message: `Remove ${node.name} from its ⋯ menu first.`,
          },
          409,
        );
      }
    }
    await dropNode(context.env, id);
    await db.prepare("DELETE FROM nodes WHERE id = ?").bind(id).run();
    await announce(context.env, ["fleet"]);
    return context.json({ removed: true });
  });
}
