import {
  NETWORK,
  type NetworkBeat,
  type NetworkLink,
  type NetworkReply,
  type SignedDocument,
} from "@krynodes/protocol";

import { storedDocument } from "../network/document";

interface Member {
  node_id: string;
  kind: string;
  state: "waiting" | "in" | "leaving";
  key: string;
  endpoint: string | null;
  nat: number;
  announce_key: string | null;
  announce_signature: string | null;
  applied: number | null;
}

type Pairs = Record<string, 0 | 1>;

const PAIRS = "networkPairs";

export interface NetworkTurn {
  reply: NetworkReply | null;
  stamp: string | null;
  poke: string[];
  changed?: boolean;
}

export class HubNetwork {
  readonly latest = new Map<string, { at: number; links: NetworkLink[] }>();
  private readonly meets = new Map<string, string>();
  private readonly told = new Map<string, string>();
  private heldNow: string | null = null;
  private cache: { stamp: string; members: Member[]; cut: Set<string> } | null =
    null;
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
    laptop = false,
  ): Promise<NetworkTurn> {
    this.latest.set(nodeId, { at: now, links: beat.links });
    const row = await this.db
      .prepare(
        `SELECT stamp, version, CASE WHEN version > ?2 THEN document END AS document
         FROM network WHERE owner_user_id = ?1`,
      )
      .bind(ownerId, beat.version)
      .first<{ stamp: string; version: number; document: string | null }>();
    if (!row) return { reply: null, stamp: null, poke: [] };
    const { members, cut } = await this.members(ownerId, row.stamp);
    const self = members.find((member) => member.node_id === nodeId);
    const usable = (member: Member) =>
      member.state === "in" && !cut.has(member.node_id);
    const laptops = members.filter(
      (member) => member.kind === "laptop" && usable(member),
    );
    const behind = members.filter(
      (member) =>
        member.kind !== "laptop" && member.nat === 1 && usable(member),
    );
    const meetingPoint = (id: string | undefined) =>
      members.find(
        (member) =>
          member.node_id === id &&
          member.kind !== "laptop" &&
          member.nat === 0 &&
          member.endpoint !== null &&
          usable(member),
      );
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
      const flipped = laptop
        ? null
        : await this.flips(
            nodeId,
            peers.filter((peer) => peer.kind !== "laptop"),
            beat.links,
            now,
          );
      if (flipped) {
        pairs = flipped.pairs;
        statements.push(...flipped.statements);
      }
    }
    if (laptop && self?.kind === "laptop" && self.applied !== beat.version) {
      statements.push(
        this.db
          .prepare("UPDATE network_members SET applied = ? WHERE node_id = ?")
          .bind(beat.version, nodeId),
      );
    }
    if (
      laptop &&
      self?.kind === "laptop" &&
      usable(self) &&
      beat.meet !== undefined &&
      beat.meet !== this.meets.get(nodeId) &&
      meetingPoint(beat.meet)
    ) {
      this.meets.set(nodeId, beat.meet);
      poke.push(...behind.map((member) => member.node_id));
    }
    if (statements.length > 0) {
      await this.db.batch(statements);
      this.cache = null;
    }
    if (pairs) await this.storage.put(PAIRS, pairs);
    const reply: NetworkReply = {};
    const document = await this.nextFor(nodeId, ownerId, beat.version, row);
    if (document) reply.document = JSON.parse(document) as SignedDocument;
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
    if (!laptop && self && behind.includes(self)) {
      const meetings = laptops.flatMap((member) => {
        const via = meetingPoint(this.meets.get(member.node_id));
        return via ? [{ laptop: member.node_id, via: via.node_id }] : [];
      });
      if (meetings.length > 0 && this.tell(nodeId, meetings)) {
        reply.meetings = meetings;
      }
    }
    if (laptop && self?.kind === "laptop") {
      const held = await this.held(ownerId);
      if (this.tell(nodeId, held)) reply.held = held;
    }
    return {
      reply: Object.keys(reply).length > 0 ? reply : null,
      stamp: row.stamp,
      poke,
      ...(statements.length > 0 ? { changed: true } : {}),
    };
  }

  async heldMoved(ownerId: string): Promise<boolean> {
    const held = JSON.stringify(await this.held(ownerId));
    if (held === this.heldNow) return false;
    this.heldNow = held;
    return true;
  }

  private async held(ownerId: string): Promise<string[]> {
    return (
      await this.db
        .prepare(
          `SELECT q.node_id FROM quarantines q JOIN nodes n ON n.id = q.node_id
           WHERE n.owner_user_id = ? AND q.released_at IS NULL
           ORDER BY q.node_id LIMIT 32`,
        )
        .bind(ownerId)
        .all<{ node_id: string }>()
    ).results.map((entry) => entry.node_id);
  }

  forget(nodeId: string): void {
    this.told.delete(nodeId);
  }

  private tell(nodeId: string, value: unknown): boolean {
    const text = JSON.stringify(value);
    if (this.told.get(nodeId) === text) return false;
    this.told.set(nodeId, text);
    return true;
  }

  private async nextFor(
    nodeId: string,
    ownerId: string,
    version: number,
    row: { version: number; document: string | null },
  ): Promise<string | null> {
    if (!row.document || version === 0 || row.version <= version + 1) {
      return row.document;
    }
    const steps = (
      await this.db
        .prepare(
          `SELECT version, document FROM network_documents
           WHERE owner_user_id = ? AND version IN (?, ?)`,
        )
        .bind(ownerId, version, version + 1)
        .all<{ version: number; document: string }>()
    ).results;
    const applied = steps.find((step) => step.version === version);
    const next = steps.find((step) => step.version === version + 1);
    const member = storedDocument(
      applied?.document ?? "",
    )?.document.members.some((entry) => entry.node === nodeId);
    return next && member ? next.document : row.document;
  }

  private async members(ownerId: string, stamp: string) {
    if (this.cache?.stamp === stamp) return this.cache;
    const [rows, current] = await Promise.all([
      this.db
        .prepare(
          `SELECT m.node_id, n.kind, m.state, m.key, m.endpoint, m.nat, m.announce_key,
                  m.announce_signature, m.applied
           FROM network_members m JOIN nodes n ON n.id = m.node_id
           WHERE n.owner_user_id = ?`,
        )
        .bind(ownerId)
        .all<Member>()
        .then((result) => result.results),
      this.db
        .prepare("SELECT document FROM network WHERE owner_user_id = ?")
        .bind(ownerId)
        .first<{ document: string }>(),
    ]);
    const cut = new Set(
      (storedDocument(current?.document ?? "")?.document.members ?? [])
        .filter((member) => member.cut)
        .map((member) => member.node),
    );
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
    this.cache = { stamp, members: rows, cut };
    return this.cache;
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
        link.ms !== null ||
        (link.handshake !== null &&
          now / 1000 - link.handshake < NETWORK.answerSeconds)
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
