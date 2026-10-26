import {
  agentHasFeatures,
  dnsName,
  FEATURE_AGENT,
  signedDocumentSchema,
} from "@krynodes/protocol";
import type { MiddlewareHandler } from "hono";
import { z } from "zod";

import { fleetLinks, pokeSoon } from "../fleet/client";
import { assertionUv } from "../lib/webauthn";
import { nextAddresses, type AddressRow } from "../network/addresses";
import {
  documentIn,
  liveRange,
  pointsAt,
  readNetwork,
  storedDocument,
} from "../network/document";
import { ownersRefusal } from "../trust/approval";
import { loadFleet } from "../trust/fleet";
import {
  invalidRequest,
  readJson,
  type KrynodesApp,
  type KrynodesContext,
  type KrynodesEnv,
} from "./shared";

const RANGE = /^10\.88\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.0\/24$/u;
const CHANGES = 20;

const documentBodySchema = z.object({
  signed: signedDocumentSchema,
  change: z.string().trim().min(1).max(300),
  detail: z.string().trim().max(2000).nullable().default(null),
});

const testBodySchema = z.object({
  change: z.string().trim().min(1).max(300),
  detail: z.string().trim().max(2000).nullable().default(null),
  nodes: z.array(z.string().uuid()).min(1).max(32),
});

interface MemberRow {
  node_id: string;
  name: string;
  state: "waiting" | "in" | "leaving";
  address: string | null;
  port: number;
  mtu: number | null;
  uplink: number | null;
  key: string;
  signer: string;
  endpoint: string | null;
  nat: number;
  announce_key: string | null;
  announce_signature: string | null;
  points: string | null;
  since: string;
  joined_at: string | null;
}

const membersOf = (db: D1Database, owner: string) =>
  db
    .prepare(
      `SELECT m.node_id, n.name, m.state, m.address, m.port, m.mtu, m.uplink, m.key,
              m.signer, m.endpoint, m.nat, m.announce_key, m.announce_signature,
              m.points, m.since, m.joined_at
       FROM network_members m JOIN nodes n ON n.id = m.node_id
       WHERE n.owner_user_id = ?
       ORDER BY m.address IS NULL, m.address, n.name`,
    )
    .bind(owner)
    .all<MemberRow>();

const addressesOf = (db: D1Database, owner: string) =>
  db
    .prepare(
      `SELECT address, state, node_id, node_name, freed_at, points
       FROM network_addresses WHERE owner_user_id = ?`,
    )
    .bind(owner)
    .all<
      AddressRow & {
        node_id: string | null;
        node_name: string;
        points: string | null;
      }
    >();

const heldOf = (
  rows: (AddressRow & { node_name: string; points: string | null })[],
) =>
  rows
    .filter((row) => row.state === "held")
    .map((row) => ({
      address: row.address,
      nodeName: row.node_name,
      points: JSON.parse(row.points ?? "[]") as unknown,
    }));

const refusal = (
  context: KrynodesContext,
  status: 400 | 404 | 409 | 422,
  code: string,
  message: string,
) => context.json({ code, message }, status);

export function registerNetworkRoutes(
  app: KrynodesApp,
  requireOperator: MiddlewareHandler<KrynodesEnv>,
): void {
  app.get("/api/network", requireOperator, async (context) => {
    const db = context.env.DB;
    const owner = context.get("identity").id;
    const [row, members, addresses, links, changes, stored] = await Promise.all(
      [
        readNetwork(db, owner),
        membersOf(db, owner),
        addressesOf(db, owner),
        db
          .prepare(
            `SELECT a, b, answering, since FROM network_links
             WHERE a IN (SELECT id FROM nodes WHERE owner_user_id = ?)
             ORDER BY a, b`,
          )
          .bind(owner)
          .all<{ a: string; b: string; answering: number; since: string }>(),
        db
          .prepare(
            `SELECT id, at, change, detail, requested_by, device_id FROM network_changes
             WHERE owner_user_id = ? ORDER BY at DESC, id DESC LIMIT ?`,
          )
          .bind(owner, CHANGES)
          .all<{
            id: string;
            at: string;
            change: string;
            detail: string | null;
            requested_by: string;
            device_id: string | null;
          }>(),
        db
          .prepare(
            `SELECT m.node_id, n.links FROM network_members m JOIN nodes n ON n.id = m.node_id
             WHERE n.owner_user_id = ? AND m.state = 'in' AND n.links IS NOT NULL`,
          )
          .bind(owner)
          .all<{ node_id: string; links: string }>(),
      ],
    );
    const live: Record<string, { at: number; links: unknown[] }> = {};
    for (const entry of stored.results) {
      try {
        live[entry.node_id] = JSON.parse(entry.links) as {
          at: number;
          links: unknown[];
        };
      } catch {
        continue;
      }
    }
    for (const [nodeId, entry] of Object.entries(
      (await fleetLinks(context.env, owner)) ?? {},
    )) {
      if (!live[nodeId] || live[nodeId].at < entry.at) live[nodeId] = entry;
    }
    return context.json({
      network:
        row && row.deleted === 0
          ? {
              range: row.cidr,
              port: row.port,
              mtu: row.mtu,
              version: row.version,
              createdAt: row.created_at,
              createdBy: row.created_by,
            }
          : null,
      version: row?.version ?? 0,
      document: row ? (storedDocument(row.document)?.document ?? null) : null,
      members: members.results
        .filter((member) => member.state !== "waiting")
        .map((member) => ({
          nodeId: member.node_id,
          name: member.name,
          state: member.state,
          address: member.address,
          port: member.port,
          mtu: member.mtu,
          key: member.key,
          signer: member.signer,
          endpoint: member.endpoint,
          nat: member.nat === 1,
          announced:
            member.announce_key && member.announce_signature
              ? {
                  key: member.announce_key,
                  signature: member.announce_signature,
                }
              : null,
          since: member.since,
          joinedAt: member.joined_at,
          points: JSON.parse(member.points ?? "[]") as unknown,
        })),
      waiting: members.results
        .filter((member) => member.state === "waiting")
        .map((member) => ({
          nodeId: member.node_id,
          name: member.name,
          key: member.key,
          signer: member.signer,
          port: member.port,
          mtu: member.uplink,
          since: member.since,
        })),
      links: links.results.map((link) => ({
        a: link.a,
        b: link.b,
        answering: link.answering === 1,
        since: link.since,
      })),
      live,
      held: addresses.results
        .filter((address) => address.state === "held")
        .map((address) => ({
          address: address.address,
          nodeId: address.node_id,
          nodeName: address.node_name,
          points: JSON.parse(address.points ?? "[]") as unknown,
        })),
      changes: changes.results.map((change) => ({
        id: change.id,
        at: change.at,
        change: change.change,
        detail: change.detail,
        requestedBy: change.requested_by,
        deviceId: change.device_id,
      })),
    });
  });

  app.get("/api/network/next", requireOperator, async (context) => {
    const db = context.env.DB;
    const owner = context.get("identity").id;
    const ids = (context.req.query("nodes") ?? "").split(",").filter(Boolean);
    const asked = context.req.query("range");
    if (
      ids.length === 0 ||
      ids.length > 32 ||
      new Set(ids).size !== ids.length ||
      ids.some((id) => !z.string().uuid().safeParse(id).success) ||
      (asked !== undefined && !RANGE.test(asked))
    ) {
      return invalidRequest(context);
    }
    const [row, members, addresses, nodes] = await Promise.all([
      readNetwork(db, owner),
      membersOf(db, owner),
      addressesOf(db, owner),
      db
        .prepare(
          `SELECT id, name FROM nodes WHERE owner_user_id = ?
           AND id IN (SELECT value FROM json_each(?))`,
        )
        .bind(owner, JSON.stringify(ids))
        .all<{ id: string; name: string }>(),
    ]);
    const range = asked ?? liveRange(row);
    if (nodes.results.length !== ids.length) {
      return refusal(context, 404, "NOT_FOUND", "A server was not found.");
    }
    if (!range) {
      return refusal(
        context,
        409,
        "NO_NETWORK",
        "There is no private network yet.",
      );
    }
    const sameRange = range === liveRange(row);
    const names = new Map(nodes.results.map((node) => [node.id, node.name]));
    const inside = new Map(
      sameRange
        ? members.results
            .filter((member) => member.state === "in" && member.address)
            .map((member) => [member.node_id, member.address!])
        : [],
    );
    const fresh = ids.filter((id) => !inside.has(id));
    let handed: string[];
    try {
      handed = nextAddresses(
        range,
        sameRange ? addresses.results : [],
        fresh.length,
      );
    } catch (error) {
      return refusal(context, 422, "NO_ADDRESS", (error as Error).message);
    }
    return context.json({
      addresses: ids.map((id) => ({
        nodeId: id,
        address: inside.get(id) ?? handed[fresh.indexOf(id)]!,
        name: `${dnsName(names.get(id)!)}.kry`,
      })),
      held: sameRange ? heldOf(addresses.results) : [],
    });
  });

  app.post("/api/network/document", requireOperator, async (context) => {
    const body = documentBodySchema.safeParse(await readJson(context));
    if (!body.success) return invalidRequest(context);
    const { signed, change, detail } = body.data;
    const document = documentIn(signed);
    if (!document || (document.deleted && document.members.length > 0)) {
      return invalidRequest(context);
    }
    if (!assertionUv(signed.grant.authenticatorData)) {
      return refusal(
        context,
        400,
        "FINGERPRINT_NEEDED",
        "This passkey did not verify a fingerprint. Use the fingerprint, or choose Use a phone in the passkey window.",
      );
    }
    const db = context.env.DB;
    const identity = context.get("identity");
    const owner = identity.id;
    const refused = await ownersRefusal(
      context.env,
      await loadFleet(db, owner),
      [signed.grant],
      identity.email,
    );
    if (refused) {
      return context.json(
        { code: refused.code, message: refused.message },
        refused.status,
      );
    }
    const [row, members, addresses, blocked, nodes] = await Promise.all([
      readNetwork(db, owner),
      membersOf(db, owner),
      addressesOf(db, owner),
      db
        .prepare("SELECT key FROM network_blocked WHERE owner_user_id = ?")
        .bind(owner)
        .all<{ key: string }>(),
      db
        .prepare(
          `SELECT id, name, agent_version FROM nodes
           WHERE owner_user_id = ? AND enrolled_at IS NOT NULL AND disabled_at IS NULL
             AND id IN (SELECT value FROM json_each(?))`,
        )
        .bind(
          owner,
          JSON.stringify(document.members.map((member) => member.node)),
        )
        .all<{ id: string; name: string; agent_version: string | null }>(),
    ]);
    if (document.version !== (row?.version ?? 0) + 1) {
      return refusal(
        context,
        409,
        "VERSION_NOT_NEXT",
        "Someone changed the network meanwhile. Open it again.",
      );
    }
    if (nodes.results.length !== document.members.length) {
      return refusal(context, 404, "NOT_FOUND", "A server was not found.");
    }
    const old = nodes.results.find(
      (node) => !agentHasFeatures(node.agent_version),
    );
    if (old) {
      return refusal(
        context,
        422,
        "AGENT_TOO_OLD",
        `Update the agent on ${old.name} to ${FEATURE_AGENT} or newer.`,
      );
    }
    const creating = !row || row.deleted === 1;
    const inside = new Map(
      creating
        ? []
        : members.results
            .filter((member) => member.state === "in")
            .map((member) => [member.node_id, member]),
    );
    const fixed = (message: string) =>
      refusal(context, 422, "NETWORK_FIXED", message);
    if (
      row &&
      !creating &&
      !document.deleted &&
      (document.range !== row.cidr ||
        document.port !== row.port ||
        document.mtu !== row.mtu)
    ) {
      return fixed(
        "The range, port and MTU stay as the network was made. Delete it and create it again to change them.",
      );
    }
    if (
      document.members.some(
        (member) =>
          inside.has(member.node) &&
          inside.get(member.node)!.address !== member.address,
      )
    ) {
      return fixed("Each server keeps its address for good.");
    }
    const joining = document.members.filter(
      (member) => !inside.has(member.node),
    );
    let handed: string[];
    try {
      handed = nextAddresses(
        document.range,
        creating ? [] : addresses.results,
        joining.length,
      );
    } catch (error) {
      return refusal(context, 422, "NO_ADDRESS", (error as Error).message);
    }
    const unexpected = joining.find(
      (member) => !handed.includes(member.address),
    );
    if (unexpected) {
      return refusal(
        context,
        422,
        "ADDRESS_NOT_NEXT",
        `${unexpected.address} is not the next free address. Open Add Server again.`,
      );
    }
    const kept = new Set(document.members.map((member) => member.node));
    const leaving = [...inside.values()].filter(
      (member) => !kept.has(member.node_id),
    );
    const blockedKeys = new Set(blocked.results.map((entry) => entry.key));
    const reused = document.members.find((member) =>
      blockedKeys.has(member.key),
    );
    if (reused) {
      return refusal(
        context,
        422,
        "KEY_BLOCKED",
        `${reused.name} has a key that was blocked. Make a new key on it first.`,
      );
    }
    const unblocked = document.deleted
      ? undefined
      : leaving.find((member) => !document.blocked.includes(member.key));
    if (unblocked) {
      return refusal(
        context,
        422,
        "KEY_NOT_BLOCKED",
        `The document still accepts ${unblocked.name}'s key.`,
      );
    }

    const at = new Date().toISOString();
    const names = new Map(nodes.results.map((node) => [node.id, node.name]));
    const staying = members.results.filter(
      (member) => member.state === "in" && kept.has(member.node_id),
    );
    const statements: D1PreparedStatement[] = [
      creating
        ? db
            .prepare(
              `INSERT INTO network (owner_user_id, cidr, port, mtu, version, document, deleted,
                 stamp, created_at, created_by)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9)
               ON CONFLICT (owner_user_id) DO UPDATE SET
                 cidr = excluded.cidr, port = excluded.port, mtu = excluded.mtu,
                 version = excluded.version, document = excluded.document,
                 deleted = excluded.deleted, stamp = excluded.stamp,
                 created_at = excluded.created_at, created_by = excluded.created_by`,
            )
            .bind(
              owner,
              document.range,
              document.port,
              document.mtu,
              document.version,
              JSON.stringify(signed),
              document.deleted ? 1 : 0,
              at,
              identity.email,
            )
        : db
            .prepare(
              `UPDATE network SET version = ?2, document = ?3, deleted = ?4, stamp = ?5
               WHERE owner_user_id = ?1`,
            )
            .bind(
              owner,
              document.version,
              JSON.stringify(signed),
              document.deleted ? 1 : 0,
              at,
            ),
    ];
    if (creating || document.deleted) {
      statements.push(
        db
          .prepare("DELETE FROM network_addresses WHERE owner_user_id = ?")
          .bind(owner),
      );
    }
    if (document.members.length > 0) {
      statements.push(
        db
          .prepare(
            `INSERT INTO network_members (node_id, state, address, port, mtu, key, signer,
               endpoint, nat, since, joined_at)
             SELECT json_extract(value, '$.node'), 'in', json_extract(value, '$.address'),
                    json_extract(value, '$.port'), json_extract(value, '$.mtu'),
                    json_extract(value, '$.key'), json_extract(value, '$.signer'),
                    json_extract(value, '$.endpoint'), json_extract(value, '$.nat'), ?1, ?1
             FROM json_each(?2) WHERE true
             ON CONFLICT (node_id) DO UPDATE SET
               address = excluded.address, port = excluded.port, mtu = excluded.mtu,
               key = excluded.key, signer = excluded.signer, endpoint = excluded.endpoint,
               nat = excluded.nat,
               announce_key = CASE WHEN network_members.announce_key = excluded.key
                 THEN NULL ELSE network_members.announce_key END,
               announce_signature = CASE WHEN network_members.announce_key = excluded.key
                 THEN NULL ELSE network_members.announce_signature END,
               since = CASE WHEN network_members.state = 'in'
                 THEN network_members.since ELSE excluded.since END,
               joined_at = CASE WHEN network_members.state = 'in'
                 THEN network_members.joined_at ELSE excluded.joined_at END,
               state = 'in'`,
          )
          .bind(
            at,
            JSON.stringify(
              document.members.map((member) => ({
                ...member,
                nat: member.nat ? 1 : 0,
              })),
            ),
          ),
        db
          .prepare(
            `INSERT OR REPLACE INTO network_addresses
               (owner_user_id, address, state, node_id, node_name, freed_at, points)
             SELECT ?1, json_extract(value, '$.address'), 'used', json_extract(value, '$.node'),
                    json_extract(value, '$.name'), NULL, NULL
             FROM json_each(?2)`,
          )
          .bind(
            owner,
            JSON.stringify(
              document.members.map((member) => ({
                address: member.address,
                node: member.node,
                name: names.get(member.node) ?? member.name,
              })),
            ),
          ),
      );
    }
    if (leaving.length > 0) {
      const ids = JSON.stringify(leaving.map((member) => member.node_id));
      statements.push(
        db
          .prepare(
            `UPDATE network_members SET state = 'leaving', since = ?1
             WHERE node_id IN (SELECT value FROM json_each(?2))`,
          )
          .bind(at, ids),
        db
          .prepare(
            `DELETE FROM network_links
             WHERE a IN (SELECT value FROM json_each(?1)) OR b IN (SELECT value FROM json_each(?1))`,
          )
          .bind(ids),
      );
      if (!document.deleted) {
        const released = leaving.map((member) => {
          const points = pointsAt(member.address!, member.name, staying);
          return {
            address: member.address,
            node: member.node_id,
            name: member.name,
            points: points.length > 0 ? JSON.stringify(points) : null,
          };
        });
        statements.push(
          db
            .prepare(
              `INSERT OR REPLACE INTO network_addresses
                 (owner_user_id, address, state, node_id, node_name, freed_at, points)
               SELECT ?1, json_extract(value, '$.address'),
                      CASE WHEN json_extract(value, '$.points') IS NULL THEN 'freed' ELSE 'held' END,
                      json_extract(value, '$.node'), json_extract(value, '$.name'),
                      CASE WHEN json_extract(value, '$.points') IS NULL THEN ?2 END,
                      json_extract(value, '$.points')
               FROM json_each(?3)`,
            )
            .bind(owner, at, JSON.stringify(released)),
        );
      }
    }
    if (document.blocked.length > 0) {
      const owners = new Map(
        members.results.map((member) => [member.key, member.node_id]),
      );
      statements.push(
        db
          .prepare(
            `INSERT OR IGNORE INTO network_blocked (owner_user_id, key, node_id, at)
             SELECT ?1, json_extract(value, '$.key'), json_extract(value, '$.node'), ?2
             FROM json_each(?3)`,
          )
          .bind(
            owner,
            at,
            JSON.stringify(
              document.blocked.map((key) => ({
                key,
                node: owners.get(key) ?? null,
              })),
            ),
          ),
      );
    }
    const joins = joining.map((member) => member.node);
    const leaves = leaving.map((member) => member.node_id);
    statements.push(
      changeStatement(db, {
        owner,
        at,
        change,
        detail,
        requestedBy: identity.email,
        deviceId: signed.grant.credentialId,
        nodes: [...new Set([...inside.keys(), ...kept])],
        joins,
        leaves,
      }),
      db
        .prepare(
          "UPDATE devices SET last_used_at = ? WHERE id = ? AND owner_user_id = ?",
        )
        .bind(at, signed.grant.credentialId, owner),
    );
    await db.batch(statements);
    pokeSoon(context, owner, [...kept, ...leaves]);
    return context.json({ version: document.version });
  });

  app.post("/api/network/tests", requireOperator, async (context) => {
    const body = testBodySchema.safeParse(await readJson(context));
    if (!body.success) return invalidRequest(context);
    const db = context.env.DB;
    const identity = context.get("identity");
    const owned = await db
      .prepare(
        `SELECT COUNT(*) AS n FROM nodes WHERE owner_user_id = ?
         AND id IN (SELECT value FROM json_each(?))`,
      )
      .bind(identity.id, JSON.stringify(body.data.nodes))
      .first<{ n: number }>();
    if (owned?.n !== new Set(body.data.nodes).size) {
      return refusal(context, 404, "NOT_FOUND", "A server was not found.");
    }
    const id = crypto.randomUUID();
    await changeStatement(db, {
      id,
      owner: identity.id,
      at: new Date().toISOString(),
      change: body.data.change,
      detail: body.data.detail,
      requestedBy: identity.email,
      deviceId: null,
      nodes: body.data.nodes,
      joins: [],
      leaves: [],
    }).run();
    return context.json({ id }, 201);
  });
}

export function changeStatement(
  db: D1Database,
  change: {
    id?: string;
    owner: string;
    at: string;
    change: string;
    detail: string | null;
    requestedBy: string;
    deviceId: string | null;
    nodes: string[];
    joins: string[];
    leaves: string[];
  },
) {
  return db
    .prepare(
      `INSERT INTO network_changes (id, owner_user_id, at, change, detail, requested_by,
         device_id, nodes, joins, leaves)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      change.id ?? crypto.randomUUID(),
      change.owner,
      change.at,
      change.change,
      change.detail,
      change.requestedBy,
      change.deviceId,
      JSON.stringify(change.nodes),
      JSON.stringify(change.joins),
      JSON.stringify(change.leaves),
    );
}
