import { readSigned, type ReadDocument } from "./document";

export interface NetworkRow {
  cidr: string;
  port: number;
  mtu: number;
  version: number;
  dns: string | null;
  deleted: number;
}

export const readNetwork = (db: D1Database) =>
  db
    .prepare(
      "SELECT cidr, port, mtu, version, dns, deleted FROM network WHERE id = 1",
    )
    .first<NetworkRow>();

export const liveRange = (row: NetworkRow | null) =>
  row && row.deleted === 0 ? row.cidr : null;

export async function storedDocument(
  db: D1Database,
  version: number,
): Promise<(ReadDocument & { hash: string }) | null> {
  const row = await db
    .prepare("SELECT signed, hash FROM network_documents WHERE version = ?")
    .bind(version)
    .first<{ signed: string; hash: string }>();
  const read = row ? readSigned(row.signed) : null;
  return read && row ? { ...read, hash: row.hash } : null;
}

interface MemberRow {
  node_id: string;
  name: string;
  kind: string;
  hostname: string | null;
  os: string | null;
  seal_key: string | null;
  state: "requested" | "rejected" | "in" | "leaving";
  key: string | null;
  signer: string | null;
  ready: number;
  reason: string | null;
  address: string | null;
  port: number | null;
  mtu: number | null;
  endpoint: string | null;
  nat: number;
  applied: number;
  failure: string | null;
  announce_key: string | null;
  announce_signature: string | null;
  since: string;
  joined_at: string | null;
}

export async function networkView(db: D1Database) {
  const [row, members, links] = await Promise.all([
    readNetwork(db),
    db
      .prepare(
        `SELECT m.*, n.name, n.kind, n.hostname, n.os, n.seal_key
         FROM network_members m JOIN nodes n ON n.id = m.node_id
         ORDER BY m.address IS NULL, m.address, m.since, n.name`,
      )
      .all<MemberRow>(),
    db
      .prepare(
        "SELECT a, b, answering, ms, since FROM network_links ORDER BY a, b",
      )
      .all<{
        a: string;
        b: string;
        answering: number;
        ms: number | null;
        since: string;
      }>(),
  ]);
  const live = liveRange(row) ? await storedDocument(db, row!.version) : null;
  const inState = (...states: MemberRow["state"][]) =>
    members.results.filter((member) => states.includes(member.state));
  return {
    network: row
      ? {
          range: row.cidr,
          port: row.port,
          mtu: row.mtu,
          version: row.version,
          dns: row.dns === null ? null : (JSON.parse(row.dns) as string[]),
          deleted: row.deleted === 1,
        }
      : null,
    members: inState("in", "leaving").map((member) => ({
      node: member.node_id,
      name: member.name,
      kind: member.kind,
      state: member.state,
      address: member.address,
      key: member.key,
      signer: member.signer,
      port: member.port,
      mtu: member.mtu,
      endpoint: member.endpoint,
      nat: member.nat === 1,
      applied: member.applied,
      failure: member.failure,
      announced:
        member.announce_key && member.announce_signature
          ? { key: member.announce_key, signature: member.announce_signature }
          : null,
      since: member.since,
      joinedAt: member.joined_at,
    })),
    requests: inState("requested").map((member) => ({
      node: member.node_id,
      name: member.name,
      kind: member.kind,
      hostname: member.hostname,
      os: member.os,
      key: member.key,
      signer: member.signer,
      sealKey: member.seal_key,
      ready: member.ready === 1,
      reason: member.reason,
      since: member.since,
    })),
    rejected: inState("rejected").map((member) => ({
      node: member.node_id,
      name: member.name,
    })),
    allow: live?.document.allow ?? [],
    links: links.results.map((link) => ({
      a: link.a,
      b: link.b,
      answering: link.answering === 1,
      ms: link.ms,
      since: link.since,
    })),
  };
}
