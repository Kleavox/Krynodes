import {
  STACKS_AGENT,
  compareVersions,
  type AgentActionResult,
} from "@krynodes/protocol";

const ACTION_TTL_MS = 10 * 60_000;
const ABANDON_MS = 15 * 60_000;
const COMPOSE_ABANDON_MS = 30 * 60_000;

export type ActionKind = "systemd" | "docker" | "compose" | "trust" | "host";
export type ActionVerb =
  | "start"
  | "stop"
  | "restart"
  | "deploy"
  | "rollback"
  | "trust"
  | "reboot"
  | "logs"
  | "remove"
  | "purge"
  | "restore"
  | "create"
  | "autorestart"
  | "manual"
  | "heal";
export type BatchMode = "rolling" | "parallel";
type ActionStatus =
  "queued" | "sent" | "done" | "failed" | "expired" | "cancelled" | "skipped";

interface ActionTarget {
  id?: string;
  nodeId: string;
  kind: ActionKind;
  name: string;
  signed?: unknown;
}

export interface ActionRow {
  id: string;
  batch_id: string;
  position: number;
  mode: BatchMode;
  node_id: string;
  kind: ActionKind;
  name: string;
  action: ActionVerb;
  status: ActionStatus;
  requested_by: string;
  requested_at: string;
  deliverable_at: string | null;
  sent_at: string | null;
  finished_at: string | null;
  exit_code: number | null;
  output: string | null;
  signed: string | null;
  device_id: string | null;
}

export const DELIVER_SQL = `UPDATE actions SET status = 'sent', sent_at = ?1
  WHERE id IN (
    SELECT id FROM actions
    WHERE status = 'queued' AND node_id = ?2 AND deliverable_at IS NOT NULL
    ORDER BY rowid LIMIT 10)
  RETURNING id, kind, name, action, deliverable_at, signed`;

export const EXPIRE_SQL = `UPDATE actions SET status = 'expired', finished_at = ?1
  WHERE status = 'queued' AND deliverable_at IS NOT NULL AND deliverable_at < ?2`;

const ABANDON_SQL = `UPDATE actions
  SET status = 'failed', finished_at = ?1, output = 'No result from the server'
  WHERE status = 'sent'
    AND sent_at < CASE WHEN kind = 'compose' THEN ?3 ELSE ?2 END`;

const SKIP_SQL = `UPDATE actions SET status = 'skipped', finished_at = ?1
  WHERE status = 'queued' AND deliverable_at IS NULL AND EXISTS (
    SELECT 1 FROM actions earlier
    WHERE earlier.batch_id = actions.batch_id
      AND earlier.position < actions.position
      AND earlier.status IN ('failed', 'expired', 'cancelled', 'skipped'))`;

const PROMOTE_SQL = `UPDATE actions SET deliverable_at = ?1
  WHERE status = 'queued' AND deliverable_at IS NULL AND NOT EXISTS (
    SELECT 1 FROM actions earlier
    WHERE earlier.batch_id = actions.batch_id
      AND earlier.position < actions.position
      AND earlier.status <> 'done')`;

const iso = (ms: number) => new Date(ms).toISOString();

export const UNIT_SQL =
  "CASE WHEN target LIKE '%.service' THEN target ELSE target || '.service' END";

export const unitOf = (target: string) =>
  target.endsWith(".service") ? target : `${target}.service`;

export function sweepStatements(
  db: D1Database,
  now: number,
): D1PreparedStatement[] {
  const at = iso(now);
  const cutoff = iso(now - ACTION_TTL_MS);
  return [
    db.prepare(EXPIRE_SQL).bind(at, cutoff),
    db
      .prepare(ABANDON_SQL)
      .bind(at, iso(now - ABANDON_MS), iso(now - COMPOSE_ABANDON_MS)),
    db.prepare(SKIP_SQL).bind(at),
    db.prepare(PROMOTE_SQL).bind(at),
  ];
}

const SETTLE_MS = 2 * 60_000;
const REBOOT_MS = 10 * 60_000;

export async function inMaintenance(
  db: D1Database,
  nodeId: string,
  now: number,
  connectedAt: number,
): Promise<boolean> {
  const rebootSince = now - connectedAt < SETTLE_MS ? REBOOT_MS : SETTLE_MS;
  const row = await db
    .prepare(
      `SELECT 1 AS planned FROM actions
       WHERE node_id = ?1 AND action NOT IN ('logs', 'autorestart', 'manual') AND (
         status IN ('queued', 'sent')
         OR (status IN ('done', 'failed') AND finished_at >=
           CASE WHEN action = 'reboot' THEN ?3 ELSE ?2 END))
       LIMIT 1`,
    )
    .bind(nodeId, iso(now - SETTLE_MS), iso(now - rebootSince))
    .first<{ planned: number }>();
  return row !== null;
}

export function createBatch(
  db: D1Database,
  input: {
    action: ActionVerb;
    mode: BatchMode;
    targets: ActionTarget[];
    requestedBy: string;
    now: number;
    deviceId?: string;
  },
) {
  const batchId = crypto.randomUUID();
  const at = iso(input.now);
  const actions = input.targets.map(({ signed: _, ...target }) => ({
    ...target,
    id: target.id ?? crypto.randomUUID(),
    status: "queued" as const,
  }));
  const rows = JSON.stringify(
    actions.map(({ id, nodeId, kind, name }, index) => ({
      id,
      nodeId,
      kind,
      name,
      signed: input.targets[index]?.signed ?? null,
    })),
  );
  const statement = db
    .prepare(
      `INSERT INTO actions (id, batch_id, position, mode, node_id, kind, name,
         action, status, requested_by, requested_at, deliverable_at, signed, device_id)
       SELECT json_extract(value, '$.id'), ?1, key, ?2,
              json_extract(value, '$.nodeId'), json_extract(value, '$.kind'),
              json_extract(value, '$.name'), ?3, 'queued', ?4, ?5,
              CASE WHEN ?2 = 'parallel' OR key = 0 THEN ?5 END,
              json_extract(value, '$.signed'), ?7
       FROM json_each(?6)`,
    )
    .bind(
      batchId,
      input.mode,
      input.action,
      input.requestedBy,
      at,
      rows,
      input.deviceId ?? null,
    );
  return { batchId, actions, statements: [statement] };
}

export async function deliverActions(
  db: D1Database,
  nodeId: string,
  now: number,
) {
  const rows = await db.prepare(DELIVER_SQL).bind(iso(now), nodeId).all<{
    id: string;
    kind: ActionKind;
    name: string;
    action: ActionVerb;
    deliverable_at: string;
    signed: string | null;
  }>();
  return rows.results.map((row) => ({
    id: row.id,
    kind: row.kind,
    name: row.name,
    action: row.action,
    expiresAt: iso(Date.parse(row.deliverable_at) + ACTION_TTL_MS),
    ...(row.signed === null
      ? {}
      : { signed: JSON.parse(row.signed) as unknown }),
  }));
}

export async function heartbeatActions(
  db: D1Database,
  nodeId: string,
  now: number,
) {
  await db.batch(sweepStatements(db, now));
  return deliverActions(db, nodeId, now);
}

function followUp(
  db: D1Database,
  nodeId: string,
  action: { kind: string; name: string; action: string },
  at: string,
): D1PreparedStatement[] {
  if (action.action === "autorestart" || action.action === "manual") {
    return [
      db
        .prepare(
          `UPDATE checks SET auto_restart = ?
           WHERE node_id = ? AND kind = 'SERVICE' AND ${UNIT_SQL} = ?`,
        )
        .bind(action.action === "autorestart" ? 1 : 0, nodeId, action.name),
    ];
  }
  if (action.kind === "docker" && action.action === "remove") {
    return [
      db
        .prepare(
          "DELETE FROM services WHERE node_id = ? AND kind = 'docker' AND name = ?",
        )
        .bind(nodeId, action.name),
    ];
  }
  if (action.kind !== "compose") return [];
  const stack = db
    .prepare("DELETE FROM stacks WHERE node_id = ? AND project = ?")
    .bind(nodeId, action.name);
  const removed = db
    .prepare("DELETE FROM removed_stacks WHERE node_id = ? AND project = ?")
    .bind(nodeId, action.name);
  if (action.action === "remove") {
    return [
      db
        .prepare(
          `INSERT OR REPLACE INTO removed_stacks (node_id, project, directory, removed_at)
           SELECT node_id, project, directory, ? FROM stacks WHERE node_id = ? AND project = ?`,
        )
        .bind(at, nodeId, action.name),
      stack,
    ];
  }
  if (action.action === "purge") return [stack, removed];
  if (action.action === "restore") return [removed];
  return [];
}

export async function actionResultStatements(
  db: D1Database,
  nodeId: string,
  results: AgentActionResult[],
  now: number,
): Promise<D1PreparedStatement[]> {
  const rows = await db
    .prepare(
      `SELECT id, kind, name, action FROM actions
       WHERE node_id = ? AND status = 'sent' AND id IN (SELECT value FROM json_each(?))`,
    )
    .bind(nodeId, JSON.stringify(results.map((result) => result.id)))
    .all<{ id: string; kind: string; name: string; action: string }>();
  const sent = new Map(rows.results.map((row) => [row.id, row]));
  return results.flatMap((result) => {
    const reported = Date.parse(result.finishedAt);
    const finished = iso(
      Number.isFinite(reported) ? Math.min(reported, now) : now,
    );
    const action = sent.get(result.id);
    const next =
      action && result.ok ? followUp(db, nodeId, action, finished) : [];
    return [
      db
        .prepare(
          `UPDATE actions SET status = ?, exit_code = ?, output = ?, finished_at = max(sent_at, ?)
           WHERE id = ? AND node_id = ? AND status = 'sent'`,
        )
        .bind(
          result.ok ? "done" : "failed",
          result.exitCode,
          result.output,
          finished,
          result.id,
          nodeId,
        ),
      ...next,
    ];
  });
}

const singleAction = (
  db: D1Database,
  input: {
    nodeId: string;
    name: string;
    action: "heal" | "manual";
    requestedBy: string;
    now: number;
    unless?: string;
  },
) => {
  const id = crypto.randomUUID();
  const at = iso(input.now);
  return db
    .prepare(
      `INSERT OR IGNORE INTO actions (id, batch_id, position, mode, node_id, kind, name, action,
         status, requested_by, requested_at, deliverable_at)
       SELECT ?1, ?1, 0, 'parallel', ?2, 'systemd', ?3, ?4, 'queued', ?5, ?6, ?6
       WHERE NOT EXISTS (
         SELECT 1 FROM checks
         WHERE node_id = ?2 AND kind = 'SERVICE' AND ${UNIT_SQL} = ?3 AND auto_restart = 1
           AND ?7 IS NOT NULL AND id <> ?7)`,
    )
    .bind(
      id,
      input.nodeId,
      input.name,
      input.action,
      input.requestedBy,
      at,
      input.unless ?? null,
    );
};

export function manualStatement(
  db: D1Database,
  input: {
    nodeId: string;
    name: string;
    requestedBy: string;
    now: number;
    checkId: string;
  },
) {
  return singleAction(db, {
    ...input,
    action: "manual",
    unless: input.checkId,
  });
}

export async function healStatements(
  db: D1Database,
  node: { id: string; agent_version: string | null },
  checkIds: string[],
  now: number,
): Promise<{ statement: D1PreparedStatement; checkIds: string[] }[]> {
  if (
    checkIds.length === 0 ||
    compareVersions(node.agent_version ?? "0.0.0", STACKS_AGENT) < 0
  ) {
    return [];
  }
  const rows = await db
    .prepare(
      `SELECT id, ${UNIT_SQL} AS unit FROM checks
       WHERE node_id = ? AND kind = 'SERVICE' AND auto_restart = 1
         AND id IN (SELECT value FROM json_each(?))`,
    )
    .bind(node.id, JSON.stringify(checkIds))
    .all<{ id: string; unit: string }>();
  const units = new Map<string, string[]>();
  for (const row of rows.results) {
    units.set(row.unit, [...(units.get(row.unit) ?? []), row.id]);
  }
  return [...units].map(([unit, ids]) => ({
    statement: singleAction(db, {
      nodeId: node.id,
      name: unit,
      action: "heal",
      requestedBy: "Krynodes",
      now,
    }),
    checkIds: ids,
  }));
}

export function cancelStatement(
  db: D1Database,
  batchId: string,
  ownerId: string,
  now: number,
): D1PreparedStatement {
  return db
    .prepare(
      `UPDATE actions SET status = 'cancelled', finished_at = ?
       WHERE batch_id = ? AND status = 'queued'
         AND node_id IN (SELECT id FROM nodes WHERE owner_user_id = ?)`,
    )
    .bind(iso(now), batchId, ownerId);
}
