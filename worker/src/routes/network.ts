import { documentHash, pickAddresses } from "@krynodes/protocol";
import { z } from "zod";

import type { KrynodesApp, KrynodesContext } from "../env";
import {
  announce,
  onlineNodes,
  pushDocument,
  refreshLinks,
} from "../fleet/client";
import { assertionVerified } from "../lib/webauthn";
import { MAX_SIGNED, readSigned } from "../network/document";
import {
  liveRange,
  networkView,
  readNetwork,
  storedDocument,
} from "../network/view";
import { invalidRequest, isUnique, readJson } from "./shared";

const RANGE = /^10\.88\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.0\/24$/u;
const TOPICS = ["network", "fleet", "history"];
const MAX_CHANGES = 50;

const documentBodySchema = z.strictObject({
  signed: z.string().min(1).max(MAX_SIGNED),
  change: z.string().trim().min(1).max(300),
  detail: z.string().trim().max(2000).nullable().default(null),
});

const nodeIds = z.array(z.string().uuid()).min(1).max(32);

interface MachineRow {
  id: string;
  name: string;
  kind: string;
  seal_key: string | null;
  seen_ip: string | null;
  state: "requested" | "rejected" | "in" | "leaving" | null;
  key: string | null;
  signer: string | null;
  ready: number | null;
  reason: string | null;
  port: number | null;
  mtu: number | null;
  address: string | null;
  announce_key: string | null;
  announce_signature: string | null;
}

const machinesAnd = (db: D1Database, ids: string[]) =>
  db
    .prepare(
      `SELECT n.id, n.name, n.kind, n.seal_key, n.seen_ip, m.state, m.key, m.signer, m.ready, m.reason,
              m.port, m.mtu, m.address, m.announce_key, m.announce_signature
       FROM nodes n LEFT JOIN network_members m ON m.node_id = n.id
       WHERE n.id IN (SELECT value FROM json_each(?1)) OR m.state = 'in'`,
    )
    .bind(JSON.stringify(ids))
    .all<MachineRow>()
    .then((rows) => new Map(rows.results.map((row) => [row.id, row])));

const refuse = (
  context: KrynodesContext,
  status: 400 | 404 | 409 | 422,
  code: string,
  message: string,
) => context.json({ code, message }, status);

const random = () => crypto.getRandomValues(new Uint32Array(1))[0]! / 2 ** 32;

const changeStatement = (
  db: D1Database,
  at: string,
  change: string,
  detail: string | null,
  nodes: string[],
) =>
  db
    .prepare(
      "INSERT INTO network_changes (id, at, change, detail, nodes) VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(crypto.randomUUID(), at, change, detail, JSON.stringify(nodes));

const notRequested = (context: KrynodesContext, name: string) =>
  refuse(
    context,
    422,
    "NOT_REQUESTED",
    `${name} has not asked to join the private network.`,
  );

const REQUEST_FLIPS = {
  reject: {
    from: "requested",
    to: "rejected",
    code: "NOT_REQUESTED",
    refused: (name: string) => `${name} has not asked to join.`,
    change: (name: string) => `Reject ${name}'s request to join`,
  },
  again: {
    from: "rejected",
    to: "requested",
    code: "NOT_REJECTED",
    refused: (name: string) => `${name} was not rejected.`,
    change: (name: string) => `Ask ${name} to join again`,
  },
} as const;

export function registerNetworkRoutes(app: KrynodesApp): void {
  app.get("/api/network", async (context) => {
    await refreshLinks(context.env);
    return context.json(await networkView(context.env.DB));
  });

  app.get("/api/network/applied", async (context) => {
    const db = context.env.DB;
    const [row, members, online] = await Promise.all([
      readNetwork(db),
      db
        .prepare(
          `SELECT m.node_id AS node, n.name, m.applied, m.failure
           FROM network_members m JOIN nodes n ON n.id = m.node_id
           WHERE m.state = 'in' ORDER BY m.address, n.name`,
        )
        .all<{
          node: string;
          name: string;
          applied: number;
          failure: string | null;
        }>(),
      onlineNodes(context.env),
    ]);
    return context.json({
      version: row?.version ?? 0,
      members: members.results.map((member) => ({
        ...member,
        online: online.has(member.node),
      })),
    });
  });

  app.get("/api/network/current", async (context) => {
    const db = context.env.DB;
    const row = await readNetwork(db);
    const current = liveRange(row)
      ? await storedDocument(db, row!.version)
      : null;
    if (!current) {
      return refuse(context, 404, "NO_NETWORK", "There is no private network.");
    }
    return context.json({
      version: current.document.version,
      hash: current.hash,
      document: current.signed.document,
    });
  });

  app.get("/api/network/next", async (context) => {
    const ids = nodeIds.safeParse(
      (context.req.query("for") ?? "").split(",").filter(Boolean),
    );
    const asked = context.req.query("range");
    const db = context.env.DB;
    const row = await readNetwork(db);
    const live = liveRange(row);
    if (
      !ids.success ||
      new Set(ids.data).size !== ids.data.length ||
      (asked !== undefined && (!RANGE.test(asked) || asked === live))
    ) {
      return invalidRequest(context);
    }
    const range = live ?? asked;
    if (!range) return invalidRequest(context);
    const machines = await machinesAnd(db, ids.data);
    for (const id of ids.data) {
      const machine = machines.get(id);
      if (!machine) {
        return refuse(context, 404, "NOT_FOUND", "A server was not found.");
      }
      if (machine.state !== "requested") {
        return notRequested(context, machine.name);
      }
    }
    const held = live
      ? await db
          .prepare(
            "SELECT address, freed_at IS NOT NULL AS freed FROM network_addresses",
          )
          .all<{ address: string; freed: number }>()
      : { results: [] };
    let addresses: string[];
    try {
      addresses = pickAddresses(
        range,
        held.results.filter((one) => !one.freed).map((one) => one.address),
        held.results.filter((one) => one.freed).map((one) => one.address),
        ids.data.length,
        random,
      );
    } catch (error) {
      if (!(error instanceof RangeError)) throw error;
      return refuse(
        context,
        422,
        "NO_ADDRESS",
        `${range} has no free address for every new member.`,
      );
    }
    const current = row ? await storedDocument(db, row.version) : null;
    return context.json({
      document: current?.document ?? null,
      hash: current?.hash ?? null,
      prepared: Object.fromEntries(
        ids.data.map((id) => {
          const machine = machines.get(id)!;
          return [
            id,
            {
              key: machine.key,
              signer: machine.signer,
              port: machine.port,
              mtu: machine.mtu,
            },
          ];
        }),
      ),
      addresses: Object.fromEntries(
        ids.data.map((id, index) => [id, addresses[index]!]),
      ),
      seen: Object.fromEntries(
        ids.data.map((id) => [id, machines.get(id)!.seen_ip]),
      ),
      relayPorts: Object.fromEntries(
        (current?.document.members ?? []).flatMap((member) =>
          member.relay ? [[member.node, member.relay]] : [],
        ),
      ),
    });
  });

  app.post("/api/network/document", async (context) => {
    const body = documentBodySchema.safeParse(await readJson(context));
    const read = body.success ? readSigned(body.data.signed) : null;
    if (
      !body.success ||
      !read ||
      (read.document.deleted && read.document.members.length > 0)
    ) {
      return invalidRequest(context);
    }
    if (!assertionVerified(read.signed.grant.authenticatorData)) {
      return refuse(
        context,
        400,
        "VERIFICATION_NEEDED",
        "This passkey was opened without your fingerprint, face or PIN. Open it with one of those.",
      );
    }
    const { document } = read;
    const db = context.env.DB;
    const row = await readNetwork(db);
    const parent = row
      ? await db
          .prepare("SELECT hash FROM network_documents WHERE version = ?")
          .bind(row.version)
          .first<string>("hash")
      : null;
    if (
      document.version !== (row?.version ?? 0) + 1 ||
      document.parent !== (parent ?? undefined)
    ) {
      return refuse(
        context,
        409,
        "VERSION_NOT_NEXT",
        "Someone changed the network meanwhile. Open it again.",
      );
    }
    const creating = !row || row.deleted === 1;
    if (!creating && document.range !== row.cidr) {
      return refuse(
        context,
        422,
        "RANGE_CHANGED",
        `The network keeps its range ${row.cidr}. Delete it and create it again to change it.`,
      );
    }
    const machines = await machinesAnd(
      db,
      document.members.map((member) => member.node),
    );
    const held = creating
      ? new Map<string, { node_id: string; name: string }>()
      : await db
          .prepare(
            `SELECT a.address, a.node_id, n.name FROM network_addresses a
             JOIN nodes n ON n.id = a.node_id WHERE a.freed_at IS NULL`,
          )
          .all<{ address: string; node_id: string; name: string }>()
          .then(
            (rows) => new Map(rows.results.map((row) => [row.address, row])),
          );
    for (const member of document.members) {
      const machine = machines.get(member.node);
      if (!machine) {
        return refuse(
          context,
          404,
          "NOT_FOUND",
          `${member.name} is not enrolled.`,
        );
      }
      if ((member.kind ?? "server") !== machine.kind) {
        return refuse(
          context,
          422,
          "WRONG_KIND",
          `The document lists ${machine.name} as the wrong kind of member.`,
        );
      }
      const joined = machine.state === "in";
      if (!joined && machine.state !== "requested") {
        return notRequested(context, machine.name);
      }
      const announced =
        joined &&
        machine.announce_signature !== null &&
        member.key === machine.announce_key;
      if (
        member.signer !== machine.signer ||
        member.sealKey !== machine.seal_key ||
        (member.key !== machine.key && !announced)
      ) {
        return refuse(
          context,
          422,
          "KEY_CHANGED",
          `${machine.name}'s keys differ from the ones it reported. Open it again.`,
        );
      }
      if (joined && member.address !== machine.address) {
        return refuse(
          context,
          422,
          "ADDRESS_CHANGED",
          `${machine.name} keeps its address ${machine.address}.`,
        );
      }
      if (!joined && machine.ready !== 1) {
        return refuse(
          context,
          422,
          "NOT_READY",
          machine.reason
            ? `${machine.name} cannot join: ${machine.reason}`
            : `${machine.name} is not ready to join the private network.`,
        );
      }
      const holder = held.get(member.address);
      if (!joined && holder && holder.node_id !== member.node) {
        return refuse(
          context,
          422,
          "ADDRESS_TAKEN",
          `${member.address} is still held by ${holder.name}. Open it again.`,
        );
      }
    }
    const kept = new Set(document.members.map((member) => member.node));
    const leaving = [...machines.values()]
      .filter((machine) => machine.state === "in" && !kept.has(machine.id))
      .map((machine) => machine.id);
    const owners = new Map<string, string>();
    for (const machine of machines.values()) {
      for (const key of [machine.key, machine.announce_key]) {
        if (key) owners.set(key, machine.id);
      }
    }
    const blocked = [
      ...new Set([
        ...document.blocked,
        ...document.members.filter((one) => one.cut).map((one) => one.key),
      ]),
    ].map((key) => ({ key, node: owners.get(key) ?? null }));
    const at = new Date().toISOString();
    const statements = [
      db
        .prepare(
          `INSERT INTO network (id, cidr, port, mtu, version, dns, deleted, created_at)
           VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)
           ON CONFLICT (id) DO UPDATE SET
             cidr = excluded.cidr, port = excluded.port, mtu = excluded.mtu,
             version = excluded.version, dns = excluded.dns, deleted = excluded.deleted,
             created_at = CASE WHEN network.deleted = 1
               THEN excluded.created_at ELSE network.created_at END`,
        )
        .bind(
          document.range,
          document.port,
          document.mtu,
          document.version,
          document.dns ? JSON.stringify(document.dns) : null,
          document.deleted ? 1 : 0,
          at,
        ),
      db
        .prepare(
          "INSERT INTO network_documents (version, signed, hash, created_at) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(
          document.version,
          body.data.signed,
          await documentHash(read.body),
          at,
        ),
      ...(creating || document.deleted
        ? [db.prepare("DELETE FROM network_addresses")]
        : []),
      ...(creating
        ? [db.prepare("DELETE FROM network_members WHERE state = 'leaving'")]
        : []),
      db
        .prepare(
          `INSERT INTO network_members (node_id, state, key, signer, address, port, mtu,
             endpoint, nat, since, joined_at)
           SELECT json_extract(value, '$.node'), 'in', json_extract(value, '$.key'),
                  json_extract(value, '$.signer'), json_extract(value, '$.address'),
                  json_extract(value, '$.port'), json_extract(value, '$.mtu'),
                  json_extract(value, '$.endpoint'), json_extract(value, '$.nat'), ?1, ?1
           FROM json_each(?2) WHERE true
           ON CONFLICT (node_id) DO UPDATE SET
             key = excluded.key, signer = excluded.signer, address = excluded.address,
             port = excluded.port, mtu = excluded.mtu, endpoint = excluded.endpoint,
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
          `INSERT INTO network_addresses (address, node_id, freed_at)
           SELECT json_extract(value, '$.address'), json_extract(value, '$.node'), NULL
           FROM json_each(?1) WHERE true
           ON CONFLICT (address) DO UPDATE SET node_id = excluded.node_id, freed_at = NULL`,
        )
        .bind(JSON.stringify(document.members)),
      db
        .prepare(
          `UPDATE network_members SET state = 'leaving', since = ?1
           WHERE node_id IN (SELECT value FROM json_each(?2))`,
        )
        .bind(at, JSON.stringify(leaving)),
      db
        .prepare(
          `DELETE FROM network_links
           WHERE a IN (SELECT value FROM json_each(?1)) OR b IN (SELECT value FROM json_each(?1))`,
        )
        .bind(JSON.stringify(leaving)),
      db
        .prepare(
          `UPDATE network_addresses SET freed_at = ?1
           WHERE freed_at IS NULL AND node_id IN (SELECT value FROM json_each(?2))`,
        )
        .bind(at, JSON.stringify(leaving)),
      db
        .prepare(
          `INSERT OR IGNORE INTO network_blocked (key, node_id, at)
           SELECT json_extract(value, '$.key'), json_extract(value, '$.node'), ?1
           FROM json_each(?2)`,
        )
        .bind(at, JSON.stringify(blocked)),
      changeStatement(db, at, body.data.change, body.data.detail, [
        ...kept,
        ...leaving,
      ]),
    ];
    try {
      await db.batch(statements);
    } catch (error) {
      if (!isUnique(error)) throw error;
      return refuse(
        context,
        409,
        "VERSION_NOT_NEXT",
        "Someone changed the network meanwhile. Open it again.",
      );
    }
    await pushDocument(context.env, document.version);
    await announce(context.env, TOPICS);
    return context.json({ version: document.version });
  });

  for (const [verb, flip] of Object.entries(REQUEST_FLIPS)) {
    app.post(`/api/network/requests/:node/${verb}`, async (context) => {
      const db = context.env.DB;
      const id = context.req.param("node");
      const machine = await db
        .prepare(
          "SELECT n.name, m.state FROM nodes n JOIN network_members m ON m.node_id = n.id WHERE n.id = ?",
        )
        .bind(id)
        .first<{ name: string; state: string }>();
      if (!machine) {
        return refuse(context, 404, "NOT_FOUND", "The machine was not found.");
      }
      if (machine.state !== flip.from) {
        return refuse(context, 409, flip.code, flip.refused(machine.name));
      }
      const at = new Date().toISOString();
      const flipped = await db
        .prepare(
          "UPDATE network_members SET state = ?1, since = ?2 WHERE node_id = ?3 AND state = ?4",
        )
        .bind(flip.to, at, id, flip.from)
        .run();
      if (!flipped.meta.changes) {
        return refuse(context, 409, flip.code, flip.refused(machine.name));
      }
      await changeStatement(db, at, flip.change(machine.name), null, [
        id,
      ]).run();
      await announce(context.env, TOPICS);
      return context.json({ state: flip.to });
    });
  }

  app.get("/api/network/changes", async (context) => {
    const asked = Number(context.req.query("limit"));
    const limit =
      Number.isInteger(asked) && asked >= 1
        ? Math.min(asked, MAX_CHANGES)
        : MAX_CHANGES;
    const rows = await context.env.DB.prepare(
      "SELECT id, at, change, detail, nodes FROM network_changes ORDER BY at DESC, rowid DESC LIMIT ?",
    )
      .bind(limit)
      .all<{
        id: string;
        at: string;
        change: string;
        detail: string | null;
        nodes: string;
      }>();
    return context.json(
      rows.results.map((row) => ({
        ...row,
        nodes: JSON.parse(row.nodes) as string[],
      })),
    );
  });
}
