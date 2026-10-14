import type { MiddlewareHandler } from "hono";
import { z } from "zod";

import { expandResults, windowSize, type WindowRow } from "../agent/windows";
import {
  invalidRequest,
  readJson,
  type KrynodesApp,
  type KrynodesContext,
  type KrynodesEnv,
} from "./shared";

const SPAN_MS = 4 * 3_600_000;
const WINDOW_MS = 300_000;
const INCIDENT_PAD_MS = 10 * 60_000;

const epoch = (value: string) =>
  Date.parse(
    /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/u.test(value)
      ? `${value.replace(" ", "T")}Z`
      : value,
  );

interface IncidentRow {
  id: string;
  check_id: string;
  status: "OPEN" | "RESOLVED";
  started_at: string;
  resolved_at: string | null;
  summary: string | null;
  check_name: string;
  check_kind: string;
  check_target: string;
  node_id: string;
  node_name: string;
}

export const CHECK_RESULTS_SQL = `
  SELECT w.window_start, w.checks
  FROM nodes n
  JOIN node_windows w ON w.node_id = n.id AND w.window_start >= ?2
  WHERE n.owner_user_id = ?1`;

const OWNED_CHECKS_SQL = `
  SELECT c.id FROM checks c
  JOIN nodes n ON n.id = c.node_id
  WHERE n.owner_user_id = ?1`;

interface CheckHistory {
  results: {
    t: string;
    status: "UP" | "DOWN";
    latencyMs: number | null;
    message: string | null;
  }[];
  up4h: number | null;
}

export function registerCheckResultRoutes(
  app: KrynodesApp,
  requireAdmin: MiddlewareHandler<KrynodesEnv>,
): void {
  app.get("/api/checks/results", requireAdmin, async (context) => {
    const ownerId = context.get("identity").id;
    const from = new Date(
      (Math.floor((Date.now() - SPAN_MS) / WINDOW_MS) - 2) * WINDOW_MS,
    ).toISOString();
    const [rows, owned] = await Promise.all([
      context.env.DB.prepare(CHECK_RESULTS_SQL)
        .bind(ownerId, from)
        .all<WindowRow>(),
      context.env.DB.prepare(OWNED_CHECKS_SQL)
        .bind(ownerId)
        .all<{ id: string }>(),
    ]);
    const expanded = expandResults(
      rows.results,
      new Set(owned.results.map((row) => row.id)),
    );
    const checks: Record<string, CheckHistory> = {};
    for (const [checkId, results] of expanded) {
      const up = results.filter((result) => result.status === "UP").length;
      checks[checkId] = {
        results,
        up4h: results.length > 0 ? (up / results.length) * 100 : null,
      };
    }
    return context.json({ windowSeconds: 300, from, checks });
  });

  app.get("/api/incidents/:id", requireAdmin, async (context) => {
    const db = context.env.DB;
    const incident = await db
      .prepare(
        `SELECT i.id, i.check_id, i.status, i.started_at, i.resolved_at,
              i.summary, c.name AS check_name, c.kind AS check_kind,
              c.target AS check_target, c.node_id AS node_id,
              n.name AS node_name
       FROM incidents i
       JOIN checks c ON c.id = i.check_id
       JOIN nodes n ON n.id = c.node_id
       WHERE i.id = ? AND n.owner_user_id = ?`,
      )
      .bind(context.req.param("id"), context.get("identity").id)
      .first<IncidentRow>();
    if (!incident) return context.json({ code: "NOT_FOUND" }, 404);
    const start = epoch(incident.started_at) - INCIDENT_PAD_MS;
    const end =
      (incident.resolved_at ? epoch(incident.resolved_at) : Date.now()) +
      INCIDENT_PAD_MS;
    const node = await db
      .prepare("SELECT interval_seconds FROM nodes WHERE id = ?")
      .bind(incident.node_id)
      .first<{ interval_seconds: number }>();
    const rows = await db
      .prepare(
        `SELECT window_start, checks FROM node_windows
         WHERE node_id = ? AND window_start >= ? AND window_start <= ?
         ORDER BY window_start DESC LIMIT 100`,
      )
      .bind(
        incident.node_id,
        new Date(
          start - windowSize(node?.interval_seconds ?? 60) + 1,
        ).toISOString(),
        new Date(end).toISOString(),
      )
      .all<WindowRow>();
    const results = (
      expandResults(rows.results, new Set([incident.check_id])).get(
        incident.check_id,
      ) ?? []
    ).reverse();
    const [updates, check] = await Promise.all([
      db
        .prepare(
          `SELECT id, status, message, author, created_at AS createdAt
           FROM incident_updates WHERE incident_id = ? ORDER BY created_at, id`,
        )
        .bind(incident.id)
        .all<{
          id: string;
          status: string;
          message: string;
          author: string;
          createdAt: string;
        }>(),
      db
        .prepare("SELECT public FROM checks WHERE id = ?")
        .bind(incident.check_id)
        .first<{ public: number }>(),
    ]);
    return context.json({
      incident,
      results,
      updates: updates.results,
      public: check?.public === 1,
    });
  });

  const ownedIncident = (context: KrynodesContext) =>
    context.env.DB.prepare(
      `SELECT i.id, i.status FROM incidents i
       JOIN checks c ON c.id = i.check_id
       JOIN nodes n ON n.id = c.node_id
       WHERE i.id = ? AND n.owner_user_id = ?`,
    )
      .bind(context.req.param("id"), context.get("identity").id)
      .first<{ id: string; status: "OPEN" | "RESOLVED" }>();

  app.post("/api/incidents/:id/updates", requireAdmin, async (context) => {
    const body = updateSchema.safeParse(await readJson(context));
    if (!body.success) return invalidRequest(context);
    const incident = await ownedIncident(context);
    if (!incident) return context.json({ code: "NOT_FOUND" }, 404);
    if (incident.status !== "OPEN") {
      return context.json(
        {
          code: "INCIDENT_RESOLVED",
          message: "This incident has resolved; updates go to open ones.",
        },
        409,
      );
    }
    const update = {
      id: crypto.randomUUID(),
      status: body.data.status,
      message: body.data.message,
      author: context.get("identity").email,
      createdAt: new Date().toISOString(),
    };
    await context.env.DB.prepare(
      `INSERT INTO incident_updates (id, incident_id, status, message, author, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        update.id,
        incident.id,
        update.status,
        update.message,
        update.author,
        update.createdAt,
      )
      .run();
    return context.json(update, 201);
  });

  app.delete(
    "/api/incidents/:id/updates/:updateId",
    requireAdmin,
    async (context) => {
      const incident = await ownedIncident(context);
      if (!incident) return context.json({ code: "NOT_FOUND" }, 404);
      const row = await context.env.DB.prepare(
        "SELECT author FROM incident_updates WHERE id = ? AND incident_id = ?",
      )
        .bind(context.req.param("updateId"), incident.id)
        .first<{ author: string }>();
      if (!row) return context.json({ code: "NOT_FOUND" }, 404);
      if (row.author !== context.get("identity").email) {
        return context.json(
          {
            code: "NOT_YOUR_UPDATE",
            message: "Only the person who posted an update can delete it.",
          },
          403,
        );
      }
      await context.env.DB.prepare("DELETE FROM incident_updates WHERE id = ?")
        .bind(context.req.param("updateId"))
        .run();
      return context.body(null, 204);
    },
  );
}

const updateSchema = z.object({
  status: z.enum(["investigating", "identified", "monitoring", "update"]),
  message: z.string().trim().min(1).max(1000),
});
