import {
  NETWORK,
  networkPreparedSchema,
  networkRekeySchema,
  type AgentMessage,
  type HubMessage,
  type NetworkDocument,
  type NetworkHello,
  type NetworkLink,
} from "@krynodes/protocol";

import { fromB64url } from "../lib/b64url";
import { storedDocument } from "../network/view";

type Member = NetworkDocument["members"][number];
type Hints = Extract<HubMessage, { type: "hints" }>;
type Applied = Extract<AgentMessage, { type: "applied" }>;
type State = "requested" | "rejected" | "in" | "leaving";

interface Row {
  state: State;
  key: string | null;
  signer: string | null;
  ready: number;
  reason: string | null;
  port: number | null;
  mtu: number | null;
  applied: number;
  failure: string | null;
  announce_key: string | null;
  announce_signature: string | null;
}

interface Announced {
  node: string;
  key: string;
  signature: string;
}

export interface Fleet {
  send(nodeId: string, message: HubMessage): void;
  online(): string[];
  announce(topics: string[]): void;
}

const MAX_OFFERED = 64;
const MAX_HINTS = 32;
const REFRESH_EVERY_MS = 60_000;
const REFRESHED = "refreshed";
const MEETINGS = "meetings";
const OFFERED = "offered:";
const encoder = new TextEncoder();

const meetingPoint = (member: Member) =>
  member.kind !== "laptop" &&
  !member.nat &&
  member.endpoint !== null &&
  member.cut !== true;

const relayed = (member: Member) =>
  member.kind !== "laptop" && member.nat && member.cut !== true;

const isLaptop = (member: Member) =>
  member.kind === "laptop" && member.cut !== true;

export function meetingFor(
  document: NetworkDocument,
  chosen: string | undefined,
): string | null {
  const points = document.members.filter(meetingPoint).map((one) => one.node);
  if (chosen !== undefined && points.includes(chosen)) return chosen;
  return points.sort()[0] ?? null;
}

export function viaOf(
  document: NetworkDocument,
  meetings: Record<string, string>,
): Record<string, string> {
  if (!document.members.some(relayed)) return {};
  return Object.fromEntries(
    document.members.filter(isLaptop).flatMap((laptop) => {
      const via = meetingFor(document, meetings[laptop.node]);
      return via ? [[laptop.node, via]] : [];
    }),
  );
}

export const answering = (link: NetworkLink, now: number) =>
  link.ms !== null ||
  (link.handshake !== null &&
    now / 1000 - link.handshake < NETWORK.answerSeconds);

export function msMoved(stored: number | null, next: number | null): boolean {
  if (stored === null || next === null) return stored !== next;
  return Math.abs(stored - next) >= Math.max(1, Math.min(stored, next) / 5);
}

const hints = (parts: Partial<Omit<Hints, "type">>): Hints => ({
  type: "hints",
  endpoints: [],
  announced: [],
  meetings: [],
  held: [],
  connected: [],
  ...parts,
});

const connectedOf = (document: NetworkDocument, online: ReadonlySet<string>) =>
  document.members
    .filter(relayed)
    .map((one) => one.node)
    .filter((node) => online.has(node))
    .sort()
    .slice(0, MAX_HINTS);

export function hintsFor(
  document: NetworkDocument,
  self: Member,
  announced: Announced[],
  meetings: Record<string, string>,
  online: ReadonlySet<string>,
): Hints {
  const peers = document.members.filter(
    (one) => one.node !== self.node && one.cut !== true,
  );
  const renamed = new Map(announced.map((one) => [one.node, one.key]));
  const met = (laptops: Member[]) =>
    laptops.flatMap((laptop) => {
      const via = meetingFor(document, meetings[laptop.node]);
      return via ? [{ laptop: laptop.node, via }] : [];
    });
  const laptop = isLaptop(self);
  return hints({
    endpoints: peers
      .filter(meetingPoint)
      .map((peer) => ({
        key: renamed.get(peer.node) ?? peer.key,
        endpoint: peer.endpoint!,
      }))
      .slice(0, MAX_HINTS),
    announced: announced
      .filter((one) => peers.some((peer) => peer.node === one.node))
      .slice(0, MAX_HINTS),
    meetings: (laptop
      ? met([self])
      : relayed(self)
        ? met(document.members.filter(isLaptop))
        : []
    ).slice(0, MAX_HINTS),
    connected: laptop ? connectedOf(document, online) : [],
  });
}

async function signedBy(
  signer: string,
  node: string,
  key: string,
  signature: string,
): Promise<boolean> {
  try {
    const publicKey = await crypto.subtle.importKey(
      "raw",
      fromB64url(signer),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      { name: "Ed25519" },
      publicKey,
      fromB64url(signature),
      encoder.encode(`krynodes-network-key\n${node}\n${key}`),
    );
  } catch {
    return false;
  }
}

const isMember = (state: State | null) => state === "in" || state === "leaving";

export class HubNetwork {
  private readonly db: D1Database;
  private readonly storage: DurableObjectStorage;
  private readonly fleet: Fleet;

  constructor(db: D1Database, storage: DurableObjectStorage, fleet: Fleet) {
    this.db = db;
    this.storage = storage;
    this.fleet = fleet;
  }

  async hello(nodeId: string, hello: NetworkHello): Promise<void> {
    const row = await this.row(nodeId);
    let state = row?.state ?? null;
    const topics = new Set<string>();
    if (state === "leaving" && (await this.left(nodeId, hello.version))) {
      await this.letGo(nodeId);
      state = null;
    }
    if (state === null) {
      await this.db
        .prepare(
          `INSERT INTO network_members (node_id, state, key, signer, ready, reason, applied, since)
           VALUES (?1, 'requested', ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT (node_id) DO NOTHING`,
        )
        .bind(
          nodeId,
          hello.key,
          hello.signer,
          hello.ready ? 1 : 0,
          hello.reason,
          hello.version,
          new Date().toISOString(),
        )
        .run();
      topics.add("network").add("fleet");
    } else if (
      row &&
      !isMember(state) &&
      (row.key !== hello.key ||
        row.signer !== hello.signer ||
        row.ready !== (hello.ready ? 1 : 0) ||
        row.reason !== hello.reason ||
        row.applied !== hello.version)
    ) {
      await this.db
        .prepare(
          "UPDATE network_members SET key = ?1, signer = ?2, ready = ?3, reason = ?4, applied = ?5 WHERE node_id = ?6 AND state = ?7",
        )
        .bind(
          hello.key,
          hello.signer,
          hello.ready ? 1 : 0,
          hello.reason,
          hello.version,
          nodeId,
          state,
        )
        .run();
      topics.add("network");
    } else if (row && isMember(state) && row.applied !== hello.version) {
      await this.setApplied(nodeId, hello.version);
      topics.add("network");
    }
    if (topics.size > 0) this.fleet.announce([...topics]);
    await this.offer(nodeId, state, hello.version);
    if (state !== "in") return;
    const document = await this.live();
    if (!document) return;
    await this.hint(nodeId, document);
    this.tellLaptops(nodeId, document);
  }

  async gone(nodeId: string): Promise<void> {
    const document = await this.live();
    if (document) this.tellLaptops(nodeId, document);
  }

  private tellLaptops(nodeId: string, document: NetworkDocument) {
    if (!document.members.some((one) => one.node === nodeId && relayed(one))) {
      return;
    }
    this.sendAll(
      document.members.filter(isLaptop).map((one) => one.node),
      hints({}),
      document,
    );
  }

  private sendAll(
    targets: string[],
    message: Hints,
    document: NetworkDocument | null,
  ) {
    const online = new Set(this.fleet.online());
    const laptops = new Set(
      document?.members.filter(isLaptop).map((one) => one.node) ?? [],
    );
    const connected = document ? connectedOf(document, online) : [];
    for (const target of targets) {
      if (!online.has(target)) continue;
      this.fleet.send(
        target,
        laptops.has(target) ? { ...message, connected } : message,
      );
    }
  }

  async applied(nodeId: string, message: Applied): Promise<void> {
    const row = await this.row(nodeId);
    const state = row?.state ?? null;
    if (!message.ok) {
      if (row && isMember(state) && row.failure !== message.message) {
        await this.db
          .prepare("UPDATE network_members SET failure = ? WHERE node_id = ?")
          .bind(message.message, nodeId)
          .run();
        this.fleet.announce(["network"]);
      }
      return;
    }
    if (state === "leaving" && (await this.left(nodeId, message.version))) {
      await this.letGo(nodeId);
      this.fleet.announce(["network", "fleet"]);
      return;
    }
    if (row && (row.applied !== message.version || row.failure !== null)) {
      await this.setApplied(nodeId, message.version);
      this.fleet.announce(["network"]);
    }
    await this.offerAgain(nodeId, state, message.version);
  }

  private async offerAgain(
    nodeId: string,
    state: State | null,
    applied: number,
  ) {
    if ((await this.storage.get<number>(OFFERED + nodeId)) === applied) {
      await this.offer(nodeId, state, applied);
    }
  }

  async push(version: number): Promise<void> {
    const online = new Set(this.fleet.online());
    const behind = await this.db
      .prepare(
        "SELECT node_id, state, applied FROM network_members WHERE state IN ('in', 'leaving') AND applied < ?",
      )
      .bind(version)
      .all<{ node_id: string; state: State; applied: number }>();
    for (const row of behind.results) {
      if (online.has(row.node_id)) {
        await this.offer(row.node_id, row.state, row.applied);
      }
    }
  }

  async links(nodeId: string, links: NetworkLink[]): Promise<void> {
    const document = await this.live();
    if (
      !document?.members.some((one) => one.node === nodeId && one.cut !== true)
    ) {
      return;
    }
    const peers = document.members.filter(
      (one) => one.node !== nodeId && one.cut !== true,
    );
    const byKey = new Map(peers.map((one) => [one.key, one.node]));
    for (const one of await this.announcedPeers(nodeId)) {
      if (peers.some((peer) => peer.node === one.node)) {
        byKey.set(one.key, one.node);
      }
    }
    const stored = await this.db
      .prepare(
        "SELECT a, b, answering, ms FROM network_links WHERE a = ?1 OR b = ?1",
      )
      .bind(nodeId)
      .all<{ a: string; b: string; answering: number; ms: number | null }>();
    const known = new Map(
      stored.results.map((link) => [`${link.a}|${link.b}`, link]),
    );
    const now = Date.now();
    const since = new Date(now).toISOString();
    const seen = new Set<string>();
    const statements: D1PreparedStatement[] = [];
    for (const link of links) {
      const peer = byKey.get(link.key);
      if (!peer || seen.has(peer)) continue;
      seen.add(peer);
      const [a, b] = nodeId < peer ? [nodeId, peer] : [peer, nodeId];
      const up = answering(link, now);
      const ms = up ? link.ms : null;
      const before = known.get(`${a}|${b}`);
      if (
        before &&
        before.answering === (up ? 1 : 0) &&
        !msMoved(before.ms, ms)
      ) {
        continue;
      }
      statements.push(
        this.db
          .prepare(
            `INSERT INTO network_links (a, b, answering, ms, since) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (a, b) DO UPDATE SET ms = excluded.ms,
               since = CASE WHEN network_links.answering = excluded.answering
                 THEN network_links.since ELSE excluded.since END,
               answering = excluded.answering`,
          )
          .bind(a, b, up ? 1 : 0, ms, since),
      );
    }
    if (statements.length === 0) return;
    await this.db.batch(statements);
    this.fleet.announce(["network", "fleet"]);
  }

  async announce(nodeId: string, key: string, signature: string) {
    const row = await this.row(nodeId);
    if (row?.state === "in") await this.take(nodeId, row, key, signature);
  }

  async meet(nodeId: string, via: string): Promise<void> {
    const document = await this.live();
    const self = document?.members.find((one) => one.node === nodeId);
    if (
      !document ||
      !self ||
      !isLaptop(self) ||
      !document.members.some((one) => one.node === via && meetingPoint(one))
    ) {
      return;
    }
    const meetings =
      (await this.storage.get<Record<string, string>>(MEETINGS)) ?? {};
    if (meetings[nodeId] === via) return;
    meetings[nodeId] = via;
    await this.storage.put(MEETINGS, meetings);
    this.sendAll(
      [nodeId, ...document.members.filter(relayed).map((one) => one.node)],
      hints({ meetings: [{ laptop: nodeId, via }] }),
      document,
    );
  }

  async via(): Promise<Record<string, string>> {
    const document = await this.live();
    if (!document) return {};
    return viaOf(
      document,
      (await this.storage.get<Record<string, string>>(MEETINGS)) ?? {},
    );
  }

  async refresh(): Promise<void> {
    const now = Date.now();
    const last = await this.storage.get<number>(REFRESHED);
    if (last !== undefined && now - last < REFRESH_EVERY_MS) return;
    await this.storage.put(REFRESHED, now);
    const members = await this.db
      .prepare("SELECT node_id FROM network_members WHERE state = 'in'")
      .all<{ node_id: string }>();
    for (const { node_id } of members.results) {
      this.fleet.send(node_id, { type: "refresh" });
    }
  }

  async result(nodeId: string, action: string, message: string) {
    let value: unknown;
    try {
      value = JSON.parse(message);
    } catch {
      return;
    }
    const row = await this.row(nodeId);
    if (!row) return;
    if (action === "rekey") {
      const rekey = networkRekeySchema.safeParse(value);
      if (!rekey.success) return;
      if (row.state === "in") {
        await this.take(nodeId, row, rekey.data.key, rekey.data.signature);
        return;
      }
      await this.request(nodeId, row, { ...row, ...rekey.data });
      return;
    }
    if (action === "prepare") {
      const prepared = networkPreparedSchema.safeParse(value);
      if (prepared.success) {
        await this.request(nodeId, row, { ...row, ...prepared.data });
      }
    }
  }

  private async request(
    nodeId: string,
    row: Row,
    next: Pick<Row, "key" | "signer" | "port" | "mtu">,
  ) {
    if (
      isMember(row.state) ||
      (row.key === next.key &&
        row.signer === next.signer &&
        row.port === next.port &&
        row.mtu === next.mtu)
    ) {
      return;
    }
    await this.db
      .prepare(
        "UPDATE network_members SET key = ?1, signer = ?2, port = ?3, mtu = ?4 WHERE node_id = ?5 AND state = ?6",
      )
      .bind(next.key, next.signer, next.port, next.mtu, nodeId, row.state)
      .run();
    this.fleet.announce(["network"]);
  }

  private async take(nodeId: string, row: Row, key: string, signature: string) {
    if (
      !row.signer ||
      key === row.key ||
      key === row.announce_key ||
      !(await signedBy(row.signer, nodeId, key, signature))
    ) {
      return;
    }
    await this.db
      .prepare(
        "UPDATE network_members SET announce_key = ?1, announce_signature = ?2 WHERE node_id = ?3 AND state = 'in'",
      )
      .bind(key, signature, nodeId)
      .run();
    this.fleet.announce(["network"]);
    const peers = await this.db
      .prepare(
        "SELECT node_id FROM network_members WHERE state = 'in' AND node_id != ?",
      )
      .bind(nodeId)
      .all<{ node_id: string }>();
    this.sendAll(
      peers.results.map((one) => one.node_id),
      hints({ announced: [{ node: nodeId, key, signature }] }),
      await this.live(),
    );
  }

  private async hint(nodeId: string, document: NetworkDocument) {
    const self = document.members.find((one) => one.node === nodeId);
    if (!self || self.cut === true) return;
    const meetings =
      (await this.storage.get<Record<string, string>>(MEETINGS)) ?? {};
    this.fleet.send(
      nodeId,
      hintsFor(
        document,
        self,
        await this.announcedPeers(nodeId),
        meetings,
        new Set(this.fleet.online()),
      ),
    );
  }

  private async offer(nodeId: string, state: State | null, reported: number) {
    const latest = await this.latest();
    if (latest === null || reported >= latest) return;
    const listed = (await this.membersAt(reported))?.has(nodeId) ?? false;
    if (!listed && !isMember(state)) return;
    const documents = await (
      listed
        ? this.db
            .prepare(
              "SELECT version, signed FROM network_documents WHERE version > ? ORDER BY version LIMIT ?",
            )
            .bind(reported, MAX_OFFERED)
        : this.db
            .prepare(
              "SELECT version, signed FROM network_documents WHERE version = ?",
            )
            .bind(latest)
    ).all<{ version: number; signed: string }>();
    for (const { version, signed } of documents.results) {
      this.fleet.send(nodeId, { type: "document", version, signed });
    }
    const last = documents.results.at(-1);
    if (last) await this.storage.put(OFFERED + nodeId, last.version);
  }

  private latest() {
    return this.db
      .prepare("SELECT MAX(version) AS version FROM network_documents")
      .first<number | null>("version");
  }

  private async live(): Promise<NetworkDocument | null> {
    const latest = await this.latest();
    const read = latest === null ? null : await storedDocument(this.db, latest);
    return read && read.document.deleted !== true ? read.document : null;
  }

  private async membersAt(version: number): Promise<Set<string> | null> {
    const read = version > 0 ? await storedDocument(this.db, version) : null;
    return read ? new Set(read.document.members.map((one) => one.node)) : null;
  }

  private async left(nodeId: string, version: number): Promise<boolean> {
    const members = await this.membersAt(version);
    return members !== null && !members.has(nodeId);
  }

  private letGo(nodeId: string) {
    return this.db
      .prepare(
        "DELETE FROM network_members WHERE node_id = ? AND state = 'leaving'",
      )
      .bind(nodeId)
      .run();
  }

  private setApplied(nodeId: string, version: number) {
    return this.db
      .prepare(
        "UPDATE network_members SET applied = ?1, failure = NULL WHERE node_id = ?2",
      )
      .bind(version, nodeId)
      .run();
  }

  private row(nodeId: string) {
    return this.db
      .prepare(
        `SELECT state, key, signer, ready, reason, port, mtu, applied, failure,
                announce_key, announce_signature
         FROM network_members WHERE node_id = ?`,
      )
      .bind(nodeId)
      .first<Row>();
  }

  private async announcedPeers(nodeId: string): Promise<Announced[]> {
    const rows = await this.db
      .prepare(
        `SELECT node_id AS node, announce_key AS key, announce_signature AS signature
         FROM network_members
         WHERE state = 'in' AND node_id != ? AND announce_key IS NOT NULL
           AND announce_signature IS NOT NULL`,
      )
      .bind(nodeId)
      .all<Announced>();
    return rows.results;
  }
}
