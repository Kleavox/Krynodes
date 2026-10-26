import {
  NETWORK,
  type NetworkBeat,
  type NetworkLink,
  type NetworkReply,
  type SignedDocument,
} from "@krynodes/protocol";

interface Member {
  node_id: string;
  state: "waiting" | "in" | "leaving";
  key: string;
  endpoint: string | null;
  nat: number;
  announce_key: string | null;
  announce_signature: string | null;
}

type Pairs = Record<string, 0 | 1>;

const PAIRS = "networkPairs";

export interface NetworkTurn {
  reply: NetworkReply | null;
  stamp: string | null;
  poke: string[];
}

export class HubNetwork {
  readonly latest = new Map<string, { at: number; links: NetworkLink[] }>();
  private cache: { stamp: string; members: Member[] } | null = null;
  private readonly db: D1Database;
  private readonly storage: DurableObjectStorage;

  constructor(db: D1Database, storage: DurableObjectStorage) {
    this.db = db;
    this.storage = storage;
  }

  async beat(
    nodeId: string,
    ownerId: string,
    sent: string | undefined,
    beat: NetworkBeat,
    now: number,
  ): Promise<NetworkTurn> {
    this.latest.set(nodeId, { at: now, links: beat.links });
    const row = await this.db
      .prepare(
        `SELECT stamp, CASE WHEN version > ?2 THEN document END AS document
         FROM network WHERE owner_user_id = ?1`,
      )
      .bind(ownerId, beat.version)
      .first<{ stamp: string; document: string | null }>();
    if (!row) return { reply: null, stamp: null, poke: [] };
    const members = await this.members(ownerId, row.stamp);
    const self = members.find((member) => member.node_id === nodeId);
    const peers = members.filter(
      (member) => member.state === "in" && member.node_id !== nodeId,
    );
    const statements: D1PreparedStatement[] = [];
    const poke: string[] = [];
    let pairs: Pairs | null = null;
    if (self?.state === "leaving" && beat.key === null) {
      statements.push(
        this.db
          .prepare(
            "DELETE FROM network_members WHERE node_id = ? AND state = 'leaving'",
          )
          .bind(nodeId),
      );
    }
    if (self?.state === "in") {
      const announce = beat.announce;
      if (
        announce &&
        announce.key !== self.key &&
        announce.key !== self.announce_key
      ) {
        statements.push(
          this.db
            .prepare(
              `UPDATE network_members SET announce_key = ?, announce_signature = ?
               WHERE node_id = ? AND state = 'in'`,
            )
            .bind(announce.key, announce.signature, nodeId),
          this.db
            .prepare("UPDATE network SET stamp = ? WHERE owner_user_id = ?")
            .bind(crypto.randomUUID(), ownerId),
        );
        poke.push(...peers.map((peer) => peer.node_id));
      }
      const flipped = await this.flips(nodeId, peers, beat.links, now);
      if (flipped) {
        pairs = flipped.pairs;
        statements.push(...flipped.statements);
      }
    }
    if (statements.length > 0) {
      await this.db.batch(statements);
      this.cache = null;
    }
    if (pairs) await this.storage.put(PAIRS, pairs);
    const reply: NetworkReply = {};
    if (row.document) {
      reply.document = JSON.parse(row.document) as SignedDocument;
    }
    if (self?.state === "in" && sent !== row.stamp) {
      const endpoints = peers.flatMap((peer) =>
        peer.endpoint && peer.nat === 0
          ? [{ key: peer.key, endpoint: peer.endpoint }]
          : [],
      );
      const announced = peers.flatMap((peer) =>
        peer.announce_key && peer.announce_signature
          ? [
              {
                node: peer.node_id,
                key: peer.announce_key,
                signature: peer.announce_signature,
              },
            ]
          : [],
      );
      if (endpoints.length > 0) reply.endpoints = endpoints;
      if (announced.length > 0) reply.announced = announced;
    }
    return {
      reply: Object.keys(reply).length > 0 ? reply : null,
      stamp: row.stamp,
      poke,
    };
  }

  private async members(ownerId: string, stamp: string): Promise<Member[]> {
    if (this.cache?.stamp === stamp) return this.cache.members;
    const rows = (
      await this.db
        .prepare(
          `SELECT m.node_id, m.state, m.key, m.endpoint, m.nat, m.announce_key,
                  m.announce_signature
           FROM network_members m JOIN nodes n ON n.id = m.node_id
           WHERE n.owner_user_id = ?`,
        )
        .bind(ownerId)
        .all<Member>()
    ).results;
    const inside = new Set(
      rows.filter((row) => row.state === "in").map((row) => row.node_id),
    );
    const stored = await this.storage.get<Pairs>(PAIRS);
    if (stored) {
      const kept = Object.fromEntries(
        Object.entries(stored).filter(([pair]) =>
          pair.split("|").every((id) => inside.has(id)),
        ),
      );
      if (Object.keys(kept).length < Object.keys(stored).length) {
        await this.storage.put(PAIRS, kept);
      }
    }
    this.cache = { stamp, members: rows };
    return rows;
  }

  private async flips(
    nodeId: string,
    peers: Member[],
    links: NetworkLink[],
    now: number,
  ) {
    const byKey = new Map<string, string>();
    for (const peer of peers) {
      byKey.set(peer.key, peer.node_id);
      if (peer.announce_key) byKey.set(peer.announce_key, peer.node_id);
    }
    const pairs = (await this.storage.get<Pairs>(PAIRS)) ?? {};
    const statements: D1PreparedStatement[] = [];
    for (const link of links) {
      const peer = byKey.get(link.key);
      if (!peer) continue;
      const [a, b] = nodeId < peer ? [nodeId, peer] : [peer, nodeId];
      const answering =
        link.handshake !== null &&
        now / 1000 - link.handshake < NETWORK.answerSeconds
          ? 1
          : 0;
      if (pairs[`${a}|${b}`] === answering) continue;
      pairs[`${a}|${b}`] = answering;
      statements.push(
        this.db
          .prepare(
            `INSERT INTO network_links (a, b, answering, since) VALUES (?, ?, ?, ?)
             ON CONFLICT (a, b) DO UPDATE SET
               answering = excluded.answering, since = excluded.since`,
          )
          .bind(a, b, answering, new Date(now).toISOString()),
      );
    }
    return statements.length > 0 ? { pairs, statements } : null;
  }
}
