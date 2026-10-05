import { staleAfterMs } from "../agent/windows";
import {
  isProtectedTarget,
  type AgentActionsRequest,
  type ServiceEntry,
  type StackEntry,
} from "@krynodes/protocol";

function seenAt(value: string | null): number {
  if (value === null) return Number.NaN;
  return Date.parse(
    /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/u.test(value)
      ? `${value.replace(" ", "T")}Z`
      : value,
  );
}

type Inventory = NonNullable<AgentActionsRequest["inventory"]>;

export interface InventoryNode {
  id: string;
  inventory_hash: string | null;
  refresh_requested_at: string | null;
}

interface ServiceRow {
  kind: string;
  name: string;
  state: string;
  since: string | null;
  system: number;
}

interface StackRow {
  project: string;
  directory: string;
  running: number;
  total: number;
  compose: number;
  rollback: number;
}

function stackChanged(row: StackRow | undefined, entry: StackEntry): boolean {
  return (
    !row ||
    row.directory !== entry.directory ||
    row.running !== entry.running ||
    row.total !== entry.total ||
    row.compose !== (entry.compose ? 1 : 0) ||
    row.rollback !== (entry.rollback ? 1 : 0)
  );
}

async function stackStatements(
  db: D1Database,
  nodeId: string,
  stacks: StackEntry[],
  at: string,
): Promise<D1PreparedStatement[]> {
  const existing = await db
    .prepare(
      "SELECT project, directory, running, total, compose, rollback FROM stacks WHERE node_id = ?",
    )
    .bind(nodeId)
    .all<StackRow>();
  const before = new Map(existing.results.map((row) => [row.project, row]));
  const after = new Set(stacks.map((stack) => stack.project));
  const upserts = stacks
    .filter((stack) => stackChanged(before.get(stack.project), stack))
    .map((stack) => ({
      ...stack,
      compose: stack.compose ? 1 : 0,
      rollback: stack.rollback ? 1 : 0,
    }));
  const removed = existing.results
    .filter((row) => !after.has(row.project))
    .map((row) => row.project);
  return [
    ...(upserts.length > 0
      ? [
          db
            .prepare(
              `INSERT INTO stacks (node_id, project, directory, running, total, compose, rollback, updated_at)
               SELECT ?1, json_extract(value, '$.project'), json_extract(value, '$.directory'),
                      json_extract(value, '$.running'), json_extract(value, '$.total'),
                      json_extract(value, '$.compose'), json_extract(value, '$.rollback'), ?2
               FROM json_each(?3) WHERE true
               ON CONFLICT (node_id, project) DO UPDATE SET
                 directory = excluded.directory, running = excluded.running,
                 total = excluded.total, compose = excluded.compose,
                 rollback = excluded.rollback, updated_at = excluded.updated_at`,
            )
            .bind(nodeId, at, JSON.stringify(upserts)),
        ]
      : []),
    ...(removed.length > 0
      ? [
          db
            .prepare(
              `DELETE FROM stacks
               WHERE node_id = ?1 AND project IN (SELECT value FROM json_each(?2))`,
            )
            .bind(nodeId, JSON.stringify(removed)),
        ]
      : []),
  ];
}

const keyOf = (service: { kind: string; name: string }) =>
  `${service.kind}:${service.name}`;

function changed(row: ServiceRow | undefined, entry: ServiceEntry): boolean {
  return (
    !row ||
    row.state !== entry.state ||
    row.since !== entry.since ||
    row.system !== (entry.system ? 1 : 0)
  );
}

export async function applyInventory(
  db: D1Database,
  node: InventoryNode,
  inventory: Inventory,
  now: number,
): Promise<string | null> {
  const at = new Date(now).toISOString();
  if (inventory.hash === node.inventory_hash) {
    if (node.refresh_requested_at !== null) {
      await db
        .prepare(
          "UPDATE nodes SET inventory_at = ?, refresh_requested_at = NULL WHERE id = ?",
        )
        .bind(at, node.id)
        .run();
    }
    return node.inventory_hash;
  }
  if (!inventory.services) return node.inventory_hash;

  const incoming = inventory.services.filter(
    (entry) => !isProtectedTarget(entry.kind, entry.name),
  );
  const existing = await db
    .prepare(
      "SELECT kind, name, state, since, system FROM services WHERE node_id = ?",
    )
    .bind(node.id)
    .all<ServiceRow>();
  const before = new Map(existing.results.map((row) => [keyOf(row), row]));
  const after = new Set(incoming.map(keyOf));
  const upserts = incoming
    .filter((entry) => changed(before.get(keyOf(entry)), entry))
    .map((entry) => ({ ...entry, system: entry.system ? 1 : 0 }));
  const removed = existing.results
    .filter((row) => !after.has(keyOf(row)))
    .map(keyOf);
  await db.batch([
    ...(upserts.length > 0
      ? [
          db
            .prepare(
              `INSERT INTO services (node_id, kind, name, state, since, system, updated_at)
               SELECT ?1, json_extract(value, '$.kind'), json_extract(value, '$.name'),
                      json_extract(value, '$.state'), json_extract(value, '$.since'),
                      json_extract(value, '$.system'), ?2
               FROM json_each(?3) WHERE true
               ON CONFLICT (node_id, kind, name) DO UPDATE SET
                 state = excluded.state, since = excluded.since,
                 system = excluded.system, updated_at = excluded.updated_at`,
            )
            .bind(node.id, at, JSON.stringify(upserts)),
        ]
      : []),
    ...(removed.length > 0
      ? [
          db
            .prepare(
              `DELETE FROM services
               WHERE node_id = ?1 AND (kind || ':' || name) IN (SELECT value FROM json_each(?2))`,
            )
            .bind(node.id, JSON.stringify(removed)),
        ]
      : []),
    ...(inventory.stacks
      ? await stackStatements(db, node.id, inventory.stacks, at)
      : []),
    ...(inventory.removed
      ? [
          db
            .prepare("DELETE FROM removed_stacks WHERE node_id = ?")
            .bind(node.id),
          db
            .prepare(
              `INSERT INTO removed_stacks (node_id, project, directory, removed_at)
               SELECT ?1, json_extract(value, '$.project'), json_extract(value, '$.directory'),
                      json_extract(value, '$.removedAt')
               FROM json_each(?2)`,
            )
            .bind(node.id, JSON.stringify(inventory.removed)),
        ]
      : []),
    ...(inventory.trust
      ? [
          db
            .prepare("UPDATE nodes SET trust_report = ? WHERE id = ?")
            .bind(JSON.stringify(inventory.trust), node.id),
        ]
      : []),
    db
      .prepare(
        `UPDATE nodes SET inventory_hash = ?, inventory_at = ?, refresh_requested_at = NULL,
           docker = COALESCE(?, docker)
         WHERE id = ?`,
      )
      .bind(inventory.hash, at, inventory.docker ?? null, node.id),
  ]);
  return inventory.hash;
}

export async function requestRefresh(
  db: D1Database,
  ownerId: string,
  nodeIds: string[] | undefined,
  now: number,
): Promise<string[]> {
  const rows = await db
    .prepare(
      `SELECT id, last_seen_at, interval_seconds FROM nodes
       WHERE owner_user_id = ? AND enrolled_at IS NOT NULL AND disabled_at IS NULL
       ORDER BY id`,
    )
    .bind(ownerId)
    .all<{
      id: string;
      last_seen_at: string | null;
      interval_seconds: number;
    }>();
  const wanted = rows.results.filter(
    (row) =>
      now - seenAt(row.last_seen_at) <= staleAfterMs(row.interval_seconds) &&
      (!nodeIds || nodeIds.includes(row.id)),
  );
  if (wanted.length === 0) return [];
  const at = new Date(now).toISOString();
  await db.batch(
    wanted.map((row) =>
      db
        .prepare("UPDATE nodes SET refresh_requested_at = ? WHERE id = ?")
        .bind(at, row.id),
    ),
  );
  return wanted.map((row) => row.id);
}
