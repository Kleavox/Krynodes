import { staleAfterMs } from "../agent/windows";
import { sha256 } from "../lib/crypto";
import { applyNetworkInventory } from "../network/document";
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
  access: string | null;
  public: string | null;
  containers: string | null;
  network: string | null;
  title: string | null;
  names: string | null;
}

const publicOf = (entry: StackEntry) =>
  entry.public && entry.public.length > 0 ? JSON.stringify(entry.public) : null;

const containersOf = (entry: StackEntry) =>
  entry.containers && entry.containers.length > 0
    ? JSON.stringify(entry.containers)
    : null;

const networkOf = (entry: StackEntry) =>
  entry.network ? JSON.stringify(entry.network) : null;

const namesOf = (entry: StackEntry) =>
  entry.names && Object.keys(entry.names).length > 0
    ? JSON.stringify(entry.names)
    : null;

function renames(row: StackRow | undefined, entry: StackEntry) {
  if (!row || row.names === namesOf(entry)) return [];
  const before = (row.names ? JSON.parse(row.names) : {}) as Record<
    string,
    string
  >;
  return Object.entries(entry.names ?? {}).flatMap(([service, to]) =>
    (before[service]
      ? [before[service]]
      : [`${entry.project}-${service}-1`, `${entry.project}_${service}_1`]
    )
      .filter((from) => from !== to)
      .map((from) => ({ from, to })),
  );
}

function stackChanged(row: StackRow | undefined, entry: StackEntry): boolean {
  return (
    !row ||
    row.directory !== entry.directory ||
    row.running !== entry.running ||
    row.total !== entry.total ||
    row.compose !== (entry.compose ? 1 : 0) ||
    row.rollback !== (entry.rollback ? 1 : 0) ||
    row.access !== (entry.access ?? null) ||
    row.public !== publicOf(entry) ||
    row.containers !== containersOf(entry) ||
    row.network !== networkOf(entry) ||
    row.title !== (entry.title ?? null) ||
    row.names !== namesOf(entry)
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
      "SELECT project, directory, running, total, compose, rollback, access, public, containers, network, title, names FROM stacks WHERE node_id = ?",
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
      access: stack.access ?? null,
      public: publicOf(stack),
      containers: containersOf(stack),
      network: networkOf(stack),
      title: stack.title ?? null,
      names: namesOf(stack),
    }));
  const moves = stacks.flatMap((stack) =>
    renames(before.get(stack.project), stack),
  );
  const removed = existing.results
    .filter((row) => !after.has(row.project))
    .map((row) => row.project);
  return [
    ...(upserts.length > 0
      ? [
          db
            .prepare(
              `INSERT INTO stacks (node_id, project, directory, running, total, compose, rollback, updated_at, access, public, containers, network, title, names)
               SELECT ?1, json_extract(value, '$.project'), json_extract(value, '$.directory'),
                      json_extract(value, '$.running'), json_extract(value, '$.total'),
                      json_extract(value, '$.compose'), json_extract(value, '$.rollback'), ?2,
                      json_extract(value, '$.access'), json_extract(value, '$.public'),
                      json_extract(value, '$.containers'), json_extract(value, '$.network'),
                      json_extract(value, '$.title'), json_extract(value, '$.names')
               FROM json_each(?3) WHERE true
               ON CONFLICT (node_id, project) DO UPDATE SET
                 directory = excluded.directory, running = excluded.running,
                 total = excluded.total, compose = excluded.compose,
                 rollback = excluded.rollback, updated_at = excluded.updated_at,
                 access = excluded.access, public = excluded.public,
                 containers = excluded.containers, network = excluded.network,
                 title = excluded.title, names = excluded.names`,
            )
            .bind(nodeId, at, JSON.stringify(upserts)),
        ]
      : []),
    ...(moves.length > 0
      ? [
          db
            .prepare(
              `UPDATE checks SET
                 target = (SELECT json_extract(value, '$.to') FROM json_each(?2)
                           WHERE json_extract(value, '$.from') = checks.target),
                 name = CASE WHEN name = target
                   THEN (SELECT json_extract(value, '$.to') FROM json_each(?2)
                         WHERE json_extract(value, '$.from') = checks.target)
                   ELSE name END,
                 updated_at = datetime('now')
               WHERE node_id = ?1 AND kind = 'CONTAINER'
                 AND target IN (SELECT json_extract(value, '$.from') FROM json_each(?2))`,
            )
            .bind(nodeId, JSON.stringify(moves)),
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

type Packages = NonNullable<Inventory["packages"]>;

const summaryOf = (packages: Packages) =>
  packages.apt
    ? JSON.stringify({
        waiting: packages.updates.length,
        security: packages.updates.filter((update) => update.security).length,
        held: packages.updates.filter((update) => update.held).length,
        checkedAt: packages.checkedAt,
        restart: packages.restart,
      })
    : null;

async function packagesStatement(
  db: D1Database,
  nodeId: string,
  packages: Packages,
  at: string,
): Promise<D1PreparedStatement> {
  const { readAt: _, ...listed } = packages as Packages & { readAt?: string };
  return db
    .prepare(
      `INSERT INTO packages (node_id, hash, report, updated_at) VALUES (?1, ?2, ?3, ?4)
       ON CONFLICT (node_id) DO UPDATE SET
         hash = excluded.hash, report = excluded.report, updated_at = excluded.updated_at
       WHERE packages.hash IS NOT excluded.hash`,
    )
    .bind(
      nodeId,
      await sha256(JSON.stringify(listed)),
      JSON.stringify(packages),
      at,
    );
}

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
    ...(inventory.packages
      ? [await packagesStatement(db, node.id, inventory.packages, at)]
      : []),
    db
      .prepare(
        `UPDATE nodes SET inventory_hash = ?1, inventory_at = ?2, refresh_requested_at = NULL,
           docker = COALESCE(?3, docker), seal_key = COALESCE(?4, seal_key),
           security = COALESCE(?5, security),
           vault = CASE WHEN ?6 = 1 THEN ?7 ELSE vault END,
           updates = CASE WHEN ?9 = 1 THEN ?10 ELSE updates END,
           tailscale = ?11,
           tailscale_vault = CASE WHEN ?12 = 1 THEN ?13 ELSE tailscale_vault END,
           bridges = CASE WHEN ?14 = 1 THEN ?15 ELSE bridges END
         WHERE id = ?8`,
      )
      .bind(
        inventory.hash,
        at,
        inventory.docker ?? null,
        inventory.sealKey ?? null,
        inventory.security ? JSON.stringify(inventory.security) : null,
        inventory.vault === undefined ? 0 : 1,
        inventory.vault ? JSON.stringify(inventory.vault) : null,
        node.id,
        inventory.packages === undefined ? 0 : 1,
        inventory.packages ? summaryOf(inventory.packages) : null,
        inventory.tailscale ? JSON.stringify(inventory.tailscale) : null,
        inventory.tailscaleVault === undefined ? 0 : 1,
        inventory.tailscaleVault
          ? JSON.stringify(inventory.tailscaleVault)
          : null,
        inventory.bridges === undefined ? 0 : 1,
        inventory.bridges ? JSON.stringify(inventory.bridges) : null,
      ),
  ]);
  await applyNetworkInventory(db, node.id, inventory.network ?? null, at);
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
  const ids = wanted.map((row) => row.id);
  await db
    .prepare(
      "UPDATE nodes SET refresh_requested_at = ? WHERE id IN (SELECT value FROM json_each(?))",
    )
    .bind(new Date(now).toISOString(), JSON.stringify(ids))
    .run();
  return ids;
}
