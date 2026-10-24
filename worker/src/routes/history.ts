import { ownerOf, touches } from "@krynodes/protocol";
import type { MiddlewareHandler } from "hono";

import { loadEstate, notFixed } from "../actions/attention";
import { SEALED_VERBS, type ActionRow } from "../actions/store";
import { READ_ONLY, toActionRecord } from "./services";
import type { KrynodesApp, KrynodesEnv } from "./shared";

const HISTORY_PAGE = 50;
const SHOWS = ["everything", "actions", "incidents", "failed"] as const;
const UNSEARCHED = JSON.stringify([...READ_ONLY, ...SEALED_VERBS]);

const like = (text: string) =>
  `%${text.replace(/[\\%_]/gu, (character) => `\\${character}`)}%`;

const record = (row: ActionRow) =>
  toActionRecord(READ_ONLY.has(row.action) ? { ...row, output: null } : row);

interface EntryKey {
  type: "action" | "incident";
  at: string;
  key: string;
  ref: string;
}

type HistoryEntry =
  | { type: "action"; at: string; action: ReturnType<typeof toActionRecord> }
  | {
      type: "incident";
      at: string;
      event: "opened" | "resolved";
      incident: {
        id: string;
        checkId: string;
        checkName: string;
        nodeId: string;
        nodeName: string;
        summary: string | null;
        startedAt: string;
        resolvedAt: string | null;
      };
    };

interface IncidentRow {
  id: string;
  check_id: string;
  check_name: string;
  node_id: string;
  node_name: string;
  summary: string | null;
  started_at: string;
  resolved_at: string | null;
}

export function registerHistoryRoutes(
  app: KrynodesApp,
  requireOperator: MiddlewareHandler<KrynodesEnv>,
): void {
  app.get("/api/history", requireOperator, async (context) => {
    const db = context.env.DB;
    const show =
      SHOWS.find((value) => value === context.req.query("show")) ??
      "everything";
    const q = context.req.query("q")?.trim();
    const [at, key] = (context.req.query("before") ?? "").split("|");
    const keys = await db
      .prepare(
        `WITH owned AS (SELECT id, name FROM nodes WHERE owner_user_id = ?1),
         incident_rows AS (
           SELECT i.id, i.started_at, i.resolved_at FROM incidents i
           JOIN checks c ON c.id = i.check_id
           JOIN owned n ON n.id = c.node_id
           WHERE ?3 IN ('everything', 'incidents')
             AND (?2 IS NULL OR c.node_id = ?2)
             AND (?4 IS NULL OR c.name LIKE ?4 ESCAPE '\\'
                  OR i.summary LIKE ?4 ESCAPE '\\' OR n.name LIKE ?4 ESCAPE '\\')
         ),
         entries AS (
           SELECT 'action' AS type, a.requested_at AS at, a.id AS key, a.id AS ref
           FROM actions a JOIN owned n ON n.id = a.node_id
           WHERE ?3 <> 'incidents' AND a.kind <> 'trust'
             AND (?2 IS NULL OR a.node_id = ?2)
             AND (?3 <> 'everything' OR a.action NOT IN ('logs', 'read'))
             AND (?3 <> 'failed' OR a.status IN ('failed', 'expired'))
             AND (?4 IS NULL OR a.action LIKE ?4 ESCAPE '\\'
                  OR a.name LIKE ?4 ESCAPE '\\' OR n.name LIKE ?4 ESCAPE '\\'
                  OR (a.action NOT IN (SELECT value FROM json_each(?5))
                      AND a.output LIKE ?4 ESCAPE '\\'))
           UNION ALL
           SELECT 'incident', started_at, id || ':opened', id FROM incident_rows
           UNION ALL
           SELECT 'incident', resolved_at, id || ':resolved', id FROM incident_rows
           WHERE resolved_at IS NOT NULL
         )
         SELECT type, at, key, ref FROM entries
         WHERE ?6 IS NULL OR at < ?6 OR (at = ?6 AND key < ?7)
         ORDER BY at DESC, key DESC LIMIT ?8`,
      )
      .bind(
        context.get("identity").id,
        context.req.query("node") ?? null,
        show,
        q ? like(q) : null,
        UNSEARCHED,
        at || null,
        key ?? "",
        HISTORY_PAGE + 1,
      )
      .all<EntryKey>();
    const page = keys.results.slice(0, HISTORY_PAGE);
    const refs = (type: EntryKey["type"]) =>
      JSON.stringify(
        page.filter((entry) => entry.type === type).map((entry) => entry.ref),
      );
    const [actions, incidents] = await Promise.all([
      db
        .prepare(
          "SELECT * FROM actions WHERE id IN (SELECT value FROM json_each(?))",
        )
        .bind(refs("action"))
        .all<ActionRow>(),
      db
        .prepare(
          `SELECT i.id, i.check_id, c.name AS check_name, c.node_id, n.name AS node_name,
                  i.summary, i.started_at, i.resolved_at
           FROM incidents i JOIN checks c ON c.id = i.check_id JOIN nodes n ON n.id = c.node_id
           WHERE i.id IN (SELECT value FROM json_each(?))`,
        )
        .bind(refs("incident"))
        .all<IncidentRow>(),
    ]);
    const actionById = new Map(actions.results.map((row) => [row.id, row]));
    const incidentById = new Map(incidents.results.map((row) => [row.id, row]));
    const last = page.at(-1);
    return context.json({
      entries: page.flatMap((entry): HistoryEntry[] => {
        if (entry.type === "action") {
          const row = actionById.get(entry.ref);
          return row
            ? [{ type: "action", at: entry.at, action: record(row) }]
            : [];
        }
        const row = incidentById.get(entry.ref);
        return row
          ? [
              {
                type: "incident",
                at: entry.at,
                event: entry.key.endsWith(":opened") ? "opened" : "resolved",
                incident: {
                  id: row.id,
                  checkId: row.check_id,
                  checkName: row.check_name,
                  nodeId: row.node_id,
                  nodeName: row.node_name,
                  summary: row.summary,
                  startedAt: row.started_at,
                  resolvedAt: row.resolved_at,
                },
              },
            ]
          : [];
      }),
      next:
        keys.results.length > HISTORY_PAGE && last
          ? `${last.at}|${last.key}`
          : null,
    });
  });

  app.get("/api/history/attention", requireOperator, async (context) => {
    const db = context.env.DB;
    const owner = context.get("identity").id;
    const owned = "node_id IN (SELECT id FROM nodes WHERE owner_user_id = ?)";
    const [failed, done, open, estate] = await Promise.all([
      db
        .prepare(
          `SELECT * FROM actions
           WHERE ${owned} AND kind <> 'trust' AND hidden_at IS NULL
             AND status IN ('failed', 'expired')
           ORDER BY requested_at DESC, id DESC`,
        )
        .bind(owner)
        .all<ActionRow>(),
      db
        .prepare(
          `SELECT a.* FROM actions a
           WHERE a.${owned} AND a.status = 'done'
             AND EXISTS (SELECT 1 FROM actions f
                         WHERE f.node_id = a.node_id AND f.kind = a.kind AND f.name = a.name
                           AND f.status IN ('failed', 'expired') AND f.hidden_at IS NULL
                           AND f.requested_at < a.requested_at)`,
        )
        .bind(owner)
        .all<ActionRow>(),
      db
        .prepare(
          `SELECT i.id, i.summary, i.started_at, c.name AS check_name, c.kind, c.target, c.node_id
           FROM incidents i JOIN checks c ON c.id = i.check_id
           WHERE i.status = 'OPEN' AND c.${owned}
           ORDER BY i.started_at, i.id`,
        )
        .bind(owner)
        .all<{
          id: string;
          summary: string | null;
          started_at: string;
          check_name: string;
          kind: string;
          target: string;
          node_id: string;
        }>(),
      loadEstate(db, owner),
    ]);
    return context.json({
      items: notFixed(
        failed.results,
        done.results,
        estate.health,
        Date.now(),
      ).map((row) => {
        const server = estate.server(row.node_id);
        const incident = open.results.find((entry) => {
          const watched =
            entry.node_id === row.node_id ? ownerOf(entry, server) : null;
          return watched !== null && touches(watched, row, server);
        });
        return {
          action: record(row),
          incident: incident
            ? {
                id: incident.id,
                checkName: incident.check_name,
                summary: incident.summary,
                startedAt: incident.started_at,
              }
            : null,
        };
      }),
    });
  });

  app.post("/api/history/:id/hide", requireOperator, async (context) => {
    const identity = context.get("identity");
    const result = await context.env.DB.prepare(
      `UPDATE actions SET hidden_at = ?, hidden_by = ?
       WHERE id = ? AND node_id IN (SELECT id FROM nodes WHERE owner_user_id = ?)`,
    )
      .bind(
        new Date().toISOString(),
        identity.email,
        context.req.param("id"),
        identity.id,
      )
      .run();
    if (result.meta.changes === 0) {
      return context.json({ code: "NOT_FOUND" }, 404);
    }
    return context.body(null, 204);
  });
}
