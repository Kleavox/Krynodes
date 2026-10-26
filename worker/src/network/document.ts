import {
  dnsName,
  networkDocumentSchema,
  signedDocumentSchema,
  type NetworkDocument,
  type NetworkInventory,
  type SignedDocument,
} from "@krynodes/protocol";

import { decodeJson } from "../lib/b64url";

export interface NetworkRow {
  cidr: string;
  port: number;
  mtu: number;
  version: number;
  document: string;
  deleted: number;
  stamp: string;
  created_at: string;
  created_by: string;
}

export interface Point {
  nodeId: string;
  stack: string;
  target: string;
}

export const readNetwork = (db: D1Database, owner: string) =>
  db
    .prepare(
      `SELECT cidr, port, mtu, version, document, deleted, stamp, created_at, created_by
       FROM network WHERE owner_user_id = ?`,
    )
    .bind(owner)
    .first<NetworkRow>();

export const liveRange = (row: NetworkRow | null) =>
  row && row.deleted === 0 ? row.cidr : null;

export function documentIn(signed: SignedDocument): NetworkDocument | null {
  const document = networkDocumentSchema.safeParse(decodeJson(signed.document));
  return document.success ? document.data : null;
}

export function storedDocument(text: string): {
  signed: SignedDocument;
  document: NetworkDocument;
} | null {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return null;
  }
  const signed = signedDocumentSchema.safeParse(raw);
  if (!signed.success) return null;
  const document = documentIn(signed.data);
  return document ? { signed: signed.data, document } : null;
}

const pointsOf = (text: string | null) => {
  try {
    const parsed = JSON.parse(text ?? "[]") as unknown;
    return Array.isArray(parsed)
      ? (parsed as { stack: string; target: string }[])
      : [];
  } catch {
    return [];
  }
};

export function pointsAt(
  address: string,
  name: string,
  members: { node_id: string; points: string | null }[],
): Point[] {
  const targets = new Set([address, `${dnsName(name)}.kry`]);
  return members.flatMap((row) =>
    pointsOf(row.points)
      .filter(
        (point) =>
          targets.has(point.target) || point.target.startsWith(`${address}:`),
      )
      .map((point) => ({
        nodeId: row.node_id,
        stack: point.stack,
        target: point.target,
      })),
  );
}

export async function applyNetworkInventory(
  db: D1Database,
  nodeId: string,
  inventory: NetworkInventory | null,
  at: string,
): Promise<void> {
  const row = await db
    .prepare(
      `SELECT n.owner_user_id, m.state, m.key, m.signer, m.port, m.uplink, m.points
       FROM nodes n LEFT JOIN network_members m ON m.node_id = n.id WHERE n.id = ?`,
    )
    .bind(nodeId)
    .first<{
      owner_user_id: string;
      state: string | null;
      key: string | null;
      signer: string | null;
      port: number | null;
      uplink: number | null;
      points: string | null;
    }>();
  if (!row) return;
  const prepared = inventory?.prepared;
  if (row.state === "in") {
    const points =
      inventory && inventory.points.length > 0
        ? JSON.stringify(inventory.points)
        : null;
    if (points === row.points) return;
    await db
      .prepare("UPDATE network_members SET points = ? WHERE node_id = ?")
      .bind(points, nodeId)
      .run();
    await refreshHolds(db, row.owner_user_id, at);
  } else if (
    prepared &&
    (row.state !== "waiting" ||
      row.key !== prepared.key ||
      row.signer !== prepared.signer ||
      row.port !== prepared.port ||
      row.uplink !== prepared.mtu)
  ) {
    await db
      .prepare(
        `INSERT INTO network_members (node_id, state, port, uplink, key, signer, since)
         VALUES (?1, 'waiting', ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (node_id) DO UPDATE SET
           state = 'waiting', address = NULL, port = excluded.port, uplink = excluded.uplink,
           key = excluded.key, signer = excluded.signer, mtu = NULL, endpoint = NULL,
           announce_key = NULL, announce_signature = NULL, points = NULL,
           since = CASE WHEN network_members.state = 'waiting'
             THEN network_members.since ELSE excluded.since END
         WHERE network_members.state <> 'in'`,
      )
      .bind(
        nodeId,
        prepared.port,
        prepared.mtu,
        prepared.key,
        prepared.signer,
        at,
      )
      .run();
  } else if (!prepared && row.state === "waiting") {
    await db
      .prepare(
        "DELETE FROM network_members WHERE node_id = ? AND state = 'waiting'",
      )
      .bind(nodeId)
      .run();
  }
}

async function refreshHolds(
  db: D1Database,
  owner: string,
  at: string,
): Promise<void> {
  const [held, members] = await Promise.all([
    db
      .prepare(
        `SELECT address, node_name, points FROM network_addresses
         WHERE owner_user_id = ? AND state = 'held'`,
      )
      .bind(owner)
      .all<{ address: string; node_name: string; points: string | null }>(),
    db
      .prepare(
        `SELECT m.node_id, m.points FROM network_members m
         JOIN nodes n ON n.id = m.node_id
         WHERE n.owner_user_id = ? AND m.state = 'in'`,
      )
      .bind(owner)
      .all<{ node_id: string; points: string | null }>(),
  ]);
  const changed = held.results.flatMap((row) => {
    const points = pointsAt(row.address, row.node_name, members.results);
    const text = points.length > 0 ? JSON.stringify(points) : null;
    return text === row.points ? [] : [{ address: row.address, points: text }];
  });
  if (changed.length === 0) return;
  await db
    .prepare(
      `UPDATE network_addresses
       SET state = CASE WHEN json_extract(item.value, '$.points') IS NULL THEN 'freed' ELSE 'held' END,
           points = json_extract(item.value, '$.points'),
           freed_at = CASE WHEN json_extract(item.value, '$.points') IS NULL THEN ?2 ELSE freed_at END
       FROM json_each(?3) AS item
       WHERE owner_user_id = ?1 AND address = json_extract(item.value, '$.address')`,
    )
    .bind(owner, at, JSON.stringify(changed))
    .run();
}
