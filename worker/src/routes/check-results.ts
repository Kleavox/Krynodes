import { ownerOf, touches, type OwnerServer } from "@krynodes/protocol";
import type { MiddlewareHandler } from "hono";
import { z } from "zod";

import { loadEstate } from "../actions/attention";
import type { ActionRow } from "../actions/store";
import { quietByNode } from "../agent/quiet";
import { expandResults, windowSize, type WindowRow } from "../agent/windows";
import { fleetLive, mergeLive } from "../fleet/client";
import { READ_ONLY, toActionRecord } from "./services";
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
const BEFORE_MS = 3_600_000;
const RECENT_SPAN_MS = 30 * 86_400_000;

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
  SELECT w.node_id, w.window_start, w.checks, w.uptime_seconds
  FROM nodes n
  JOIN node_windows w ON w.node_id = n.id AND w.window_start >= ?2
  WHERE n.owner_user_id = ?1`;

const QUIET_NODES_SQL = `
  SELECT id, interval_seconds, last_seen_at, security FROM nodes
  WHERE owner_user_id = ? AND enrolled_at IS NOT NULL AND disabled_at IS NULL`;

type QuietWindow = WindowRow & {
  node_id: string;
  uptime_seconds: number | null;
};

interface QuietNode {
  id: string;
  interval_seconds: number;
  last_seen_at: string | null;
  security: string | null;
}

const OWNED_CHECKS_SQL = `
  SELECT c.id FROM checks c
  JOIN nodes n ON n.id = c.node_id
  WHERE n.owner_user_id = ?1`;

type Watched = Pick<
  IncidentRow,
  "node_id" | "check_kind" | "check_target" | "started_at" | "resolved_at"
>;

function onIncident(
  incident: Watched,
  actions: ActionRow[],
  server: OwnerServer,
  now: number,
): ActionRow[] {
  const from = epoch(incident.started_at) - BEFORE_MS;
  const to = incident.resolved_at ? epoch(incident.resolved_at) : now;
  const watched = ownerOf(
    { kind: incident.check_kind, target: incident.check_target },
    server,
  );
  return actions.filter((action) => {
    const at = epoch(action.requested_at);
    return (
      action.node_id === incident.node_id &&
      at >= from &&
      at <= to &&
      !READ_ONLY.has(action.action) &&
      ((action.kind === "host" && action.action === "reboot") ||
        (watched !== null && touches(watched, action, server)))
    );
  });
}

interface CheckHistory {
  results: {
    t: string;
    status: "UP" | "DOWN";
    latencyMs: number | null;
    message: string | null;
  }[];
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
    const [rows, owned, nodes, live] = await Promise.all([
      context.env.DB.prepare(CHECK_RESULTS_SQL)
        .bind(ownerId, from)
        .all<QuietWindow>(),
      context.env.DB.prepare(OWNED_CHECKS_SQL)
        .bind(ownerId)
        .all<{ id: string }>(),
      context.env.DB.prepare(QUIET_NODES_SQL).bind(ownerId).all<QuietNode>(),
      fleetLive(context.env, ownerId),
    ]);
    const expanded = expandResults(
      rows.results,
      new Set(owned.results.map((row) => row.id)),
    );
    const checks: Record<string, CheckHistory> = {};
    for (const [checkId, results] of expanded) checks[checkId] = { results };
    return context.json({
      windowSeconds: 300,
      from,
      checks,
      nodes: quietByNode(
        rows.results,
        mergeLive(nodes.results, live?.nodes ?? null),
        Date.parse(from),
        Date.now(),
      ),
    });
  });

  app.get("/api/checks/dismissals", requireAdmin, async (context) => {
    const rows = await context.env.DB.prepare(
      `SELECT d.node_id AS nodeId, d.project, d.reaches FROM check_dismissals d
       JOIN nodes n ON n.id = d.node_id WHERE n.owner_user_id = ?
       ORDER BY d.node_id, d.project`,
    )
      .bind(context.get("identity").id)
      .all<{ nodeId: string; project: string; reaches: string }>();
    return context.json({
      dismissals: rows.results.map((row) => ({
        ...row,
        reaches: JSON.parse(row.reaches) as string[],
      })),
    });
  });

  app.put("/api/checks/dismissals", requireAdmin, async (context) => {
    const body = dismissalSchema.safeParse(await readJson(context));
    if (!body.success) return invalidRequest(context);
    const { nodeId, project, reaches } = body.data;
    const stored = await context.env.DB.prepare(
      `INSERT INTO check_dismissals (node_id, project, reaches, at)
       SELECT id, ?2, ?3, ?4 FROM nodes WHERE id = ?1 AND owner_user_id = ?5
       ON CONFLICT (node_id, project) DO UPDATE SET
         reaches = excluded.reaches, at = excluded.at`,
    )
      .bind(
        nodeId,
        project,
        JSON.stringify(reaches),
        new Date().toISOString(),
        context.get("identity").id,
      )
      .run();
    if (stored.meta.changes === 0) {
      return context.json({ code: "NOT_FOUND" }, 404);
    }
    return context.body(null, 204);
  });

  app.get("/api/incidents/board", requireAdmin, async (context) => {
    const db = context.env.DB;
    const owner = context.get("identity").id;
    const now = Date.now();
    const owned = `JOIN checks c ON c.id = i.check_id
       JOIN nodes n ON n.id = c.node_id WHERE n.owner_user_id = ?1`;
    const [open, updates, recent, estate] = await Promise.all([
      db
        .prepare(
          `SELECT i.id, i.started_at, i.resolved_at, c.node_id,
                  c.kind AS check_kind, c.target AS check_target
           FROM incidents i ${owned} AND i.status = 'OPEN'`,
        )
        .bind(owner)
        .all<Watched & { id: string }>(),
      db
        .prepare(
          `SELECT u.incident_id, u.status, u.message, u.created_at
           FROM incident_updates u JOIN incidents i ON i.id = u.incident_id
           ${owned} AND i.status = 'OPEN'
           ORDER BY u.created_at, u.id`,
        )
        .bind(owner)
        .all<{
          incident_id: string;
          status: string;
          message: string;
          created_at: string;
        }>(),
      db
        .prepare(
          `SELECT i.started_at, i.resolved_at FROM incidents i ${owned}
           AND i.started_at >= ?2`,
        )
        .bind(owner, new Date(now - RECENT_SPAN_MS).toISOString())
        .all<{ started_at: string; resolved_at: string | null }>(),
      loadEstate(db, owner),
    ]);
    const earliest = Math.min(
      ...open.results.map((incident) => epoch(incident.started_at)),
    );
    const actions =
      open.results.length > 0
        ? await db
            .prepare(
              `SELECT * FROM actions
               WHERE node_id IN (SELECT id FROM nodes WHERE owner_user_id = ?)
                 AND requested_at >= ?
               ORDER BY requested_at, position`,
            )
            .bind(owner, new Date(earliest - BEFORE_MS).toISOString())
            .all<ActionRow>()
        : { results: [] };
    const latest: Record<
      string,
      {
        at: string;
        updates: number;
        update: { status: string; message: string } | null;
        action: ReturnType<typeof toActionRecord> | null;
      }
    > = {};
    for (const incident of open.results) {
      const posted = updates.results.filter(
        (update) => update.incident_id === incident.id,
      );
      const update = posted.at(-1);
      const action = onIncident(
        incident,
        actions.results,
        estate.server(incident.node_id),
        now,
      ).at(-1);
      if (!update && !action) continue;
      const actionWins =
        action !== undefined &&
        (!update || epoch(action.requested_at) > epoch(update.created_at));
      latest[incident.id] = {
        at: actionWins ? action.requested_at : update!.created_at,
        updates: posted.length,
        update:
          !actionWins && update
            ? { status: update.status, message: update.message }
            : null,
        action: actionWins ? toActionRecord(action) : null,
      };
    }
    return context.json({
      latest,
      last30: {
        count: recent.results.length,
        downMs: recent.results.reduce(
          (total, incident) =>
            total +
            (incident.resolved_at ? epoch(incident.resolved_at) : now) -
            epoch(incident.started_at),
          0,
        ),
      },
    });
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
    const start = epoch(incident.started_at) - BEFORE_MS;
    const end =
      (incident.resolved_at ? epoch(incident.resolved_at) : Date.now()) +
      INCIDENT_PAD_MS;
    const owner = context.get("identity").id;
    const [node, live] = await Promise.all([
      db
        .prepare(
          "SELECT id, interval_seconds, last_seen_at, security FROM nodes WHERE id = ?",
        )
        .bind(incident.node_id)
        .first<QuietNode>(),
      fleetLive(context.env, owner),
    ]);
    const rows = await db
      .prepare(
        `SELECT node_id, window_start, checks, uptime_seconds FROM node_windows
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
      .all<QuietWindow>();
    const results = (
      expandResults(rows.results, new Set([incident.check_id])).get(
        incident.check_id,
      ) ?? []
    ).reverse();
    const now = Date.now();
    const [updates, check, actions, estate] = await Promise.all([
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
      db
        .prepare(
          `SELECT * FROM actions WHERE node_id = ? AND requested_at >= ?
           ORDER BY requested_at, position`,
        )
        .bind(incident.node_id, new Date(start).toISOString())
        .all<ActionRow>(),
      loadEstate(db, owner),
    ]);
    const lastGood = results.find(
      (result) =>
        result.status === "UP" && epoch(result.t) < epoch(incident.started_at),
    );
    return context.json({
      incident,
      results,
      updates: updates.results,
      public: check?.public === 1,
      actions: onIncident(
        incident,
        actions.results,
        estate.server(incident.node_id),
        now,
      ).map(toActionRecord),
      lastGood: lastGood
        ? { t: lastGood.t, latencyMs: lastGood.latencyMs }
        : null,
      quiet: node
        ? (quietByNode(
            rows.results,
            mergeLive([node], live?.nodes ?? null),
            start,
            now,
          )[node.id]?.quiet ?? [])
        : [],
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

const dismissalSchema = z.object({
  nodeId: z.string().uuid(),
  project: z.string().min(1).max(128),
  reaches: z.array(z.string().min(1).max(64)).max(64),
});

const updateSchema = z.object({
  status: z.enum(["investigating", "identified", "monitoring", "update"]),
  message: z.string().trim().min(1).max(1000),
});
