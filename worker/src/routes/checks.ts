import { CONTAINER_NAME, stackTitleValid } from "@krynodes/protocol";
import { z } from "zod";

import type { KrynodesApp, KrynodesContext } from "../env";
import { onlineNodes, pushChecks } from "../fleet/client";
import { invalidRequest, isUnique, readJson } from "./shared";

const MAX_CHECKS = 64;

const title = z.string().refine(stackTitleValid);

const createSchema = z.strictObject({
  nodeId: z.string().min(1).max(64),
  container: z.string().regex(CONTAINER_NAME),
  name: title,
});

const changeSchema = z.strictObject({
  name: title.optional(),
  public: z.boolean().optional(),
  note: z.string().max(280).nullable().optional(),
});

interface Row {
  id: string;
  node_id: string;
  node_name: string;
  container: string;
  name: string;
  public: number;
  note: string | null;
  state: string;
  cause: string | null;
  since: string | null;
  created_at: string;
}

const SELECT =
  "SELECT c.id, c.node_id, n.name AS node_name, c.container, c.name, c.public, c.note, c.state, c.cause, c.since, c.created_at FROM checks c JOIN nodes n ON n.id = c.node_id";

const present = (row: Row, online: Set<string>) => ({
  id: row.id,
  nodeId: row.node_id,
  nodeName: row.node_name,
  online: online.has(row.node_id),
  container: row.container,
  name: row.name,
  public: row.public === 1,
  note: row.note,
  state: online.has(row.node_id) ? row.state : "unknown",
  lastState: row.state,
  cause: row.cause,
  since: row.since,
  createdAt: row.created_at,
});

const notFound = (context: KrynodesContext, what: string) =>
  context.json(
    { code: "NOT_FOUND", message: `The ${what} was not found.` },
    404,
  );

async function answer(context: KrynodesContext, id: string, status: 200 | 201) {
  const [row, online] = await Promise.all([
    context.env.DB.prepare(`${SELECT} WHERE c.id = ?`).bind(id).first<Row>(),
    onlineNodes(context.env),
  ]);
  return context.json(present(row!, online), status);
}

export function registerCheckRoutes(app: KrynodesApp): void {
  app.get("/api/checks", async (context) => {
    const [rows, online] = await Promise.all([
      context.env.DB.prepare(`${SELECT} ORDER BY n.name, c.name`).all<Row>(),
      onlineNodes(context.env),
    ]);
    return context.json({
      checks: rows.results.map((row) => present(row, online)),
      statusPage: context.env.STATUS_PAGE_URL || null,
    });
  });

  app.post("/api/checks", async (context) => {
    const body = createSchema.safeParse(await readJson(context));
    if (!body.success) return invalidRequest(context);
    const { nodeId, container, name } = body.data;
    const db = context.env.DB;
    const node = await db
      .prepare("SELECT name FROM nodes WHERE id = ? AND kind = 'server'")
      .bind(nodeId)
      .first<{ name: string }>();
    if (!node) return notFound(context, "server");
    const id = crypto.randomUUID();
    try {
      const added = await db
        .prepare(
          "INSERT INTO checks (id, node_id, container, name, created_at) SELECT ?1, ?2, ?3, ?4, ?5 WHERE (SELECT COUNT(*) FROM checks WHERE node_id = ?2) < ?6",
        )
        .bind(id, nodeId, container, name, new Date().toISOString(), MAX_CHECKS)
        .run();
      if (added.meta.changes === 0) {
        return context.json(
          {
            code: "TOO_MANY",
            message: `${node.name} already has ${MAX_CHECKS} checks.`,
          },
          409,
        );
      }
    } catch (error) {
      if (!isUnique(error)) throw error;
      return context.json(
        {
          code: "CHECK_EXISTS",
          message: `${node.name} already has a check for ${container}.`,
        },
        409,
      );
    }
    await pushChecks(context.env, nodeId);
    return answer(context, id, 201);
  });

  app.patch("/api/checks/:id", async (context) => {
    const body = changeSchema.safeParse(await readJson(context));
    if (!body.success) return invalidRequest(context);
    const { name, public: shown, note } = body.data;
    const id = context.req.param("id");
    const changed = await context.env.DB.prepare(
      "UPDATE checks SET name = COALESCE(?1, name), public = COALESCE(?2, public), note = CASE WHEN ?3 THEN ?4 ELSE note END WHERE id = ?5 RETURNING node_id",
    )
      .bind(
        name ?? null,
        shown === undefined ? null : Number(shown),
        Number(note !== undefined),
        note ?? null,
        id,
      )
      .first<{ node_id: string }>();
    if (!changed) return notFound(context, "check");
    await pushChecks(context.env, changed.node_id);
    return answer(context, id, 200);
  });

  app.delete("/api/checks/:id", async (context) => {
    const removed = await context.env.DB.prepare(
      "DELETE FROM checks WHERE id = ? RETURNING node_id",
    )
      .bind(context.req.param("id"))
      .first<{ node_id: string }>();
    if (!removed) return notFound(context, "check");
    await pushChecks(context.env, removed.node_id);
    return context.body(null, 204);
  });
}
