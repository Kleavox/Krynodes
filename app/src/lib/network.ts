import {
  DEFAULT_RULE,
  IPV4,
  links,
  NETWORK,
  networkDocumentSchema,
  networkTestSchema,
  pickRange,
  type NetworkDocument,
  type NetworkMember,
  type NetworkRule,
} from "@krynodes/protocol";

import type { FleetNode, JoinRequest, LaptopCode, NetworkView } from "../types";
import { metricText } from "./format";
import { ApiError } from "./http";
import { failure } from "./passkeys";
import { seal } from "./seal";

export interface Base {
  document: NetworkDocument;
  hash: string;
}

export type Joiner = Pick<
  NetworkMember,
  | "node"
  | "name"
  | "key"
  | "signer"
  | "sealKey"
  | "port"
  | "endpoint"
  | "nat"
  | "kind"
>;

const LAPTOP_DNS: [string, string] = ["1.1.1.1", "1.0.0.1"];

export const randomUnit = () =>
  crypto.getRandomValues(new Uint32Array(1))[0]! / 2 ** 32;

export function rangeFor(used: string[], random = randomUnit): string {
  const range = pickRange(used, random);
  if (!range) {
    throw new Error(
      "Every 10.88.x.0/24 clashes with a network on these servers.",
    );
  }
  return range;
}

export const pickMtu = (mtus: (number | null)[]) =>
  Math.min(
    1420,
    Math.max(
      1280,
      Math.min(1500, ...mtus.map((mtu) => mtu ?? 1500)) - NETWORK.mtuMargin,
    ),
  );

function placeRelays(members: NetworkMember[]) {
  const behind = members
    .filter((member) => member.kind !== "laptop" && member.nat && !member.cut)
    .map((member) => member.node);
  const laptops = members.filter((member) => member.kind === "laptop");
  const held = laptops.map((laptop) =>
    Object.fromEntries(
      Object.entries(laptop.relay ?? {}).filter(([node]) =>
        behind.includes(node),
      ),
    ),
  );
  const used = new Set(held.flatMap((relay) => Object.values(relay)));
  let next: number = NETWORK.relayPort;
  for (const [index, laptop] of laptops.entries()) {
    const relay = held[index]!;
    for (const node of behind) {
      if (relay[node] !== undefined) continue;
      while (used.has(next)) next++;
      if (next > NETWORK.lastRelayPort) {
        throw new Error(
          "There is no relay port left for another laptop and server behind NAT. Remove a laptop or a server behind NAT first.",
        );
      }
      used.add(next);
      relay[node] = next;
    }
    laptop.relay = relay;
  }
}

function settle(document: NetworkDocument): NetworkDocument {
  placeRelays(document.members);
  return networkDocumentSchema.parse(document);
}

const copy = (document: NetworkDocument): NetworkDocument =>
  structuredClone(document);

export function newDocument(
  range: string,
  port: number,
  mtu: number,
  previous: Base | null,
): NetworkDocument {
  return settle({
    v: 1,
    version: (previous?.document.version ?? 0) + 1,
    range,
    port,
    mtu,
    ...(previous ? { parent: previous.hash } : {}),
    members: [],
    blocked: [],
    allow: [DEFAULT_RULE],
  });
}

export function nextOf(base: Base): NetworkDocument {
  const next = copy(base.document);
  next.version += 1;
  next.parent = base.hash;
  return next;
}

export async function withJoiner(
  document: NetworkDocument,
  joiner: Joiner,
  address: string,
): Promise<NetworkDocument> {
  const next = copy(document);
  const prefix = next.range.slice(0, -4);
  if (
    !address.startsWith(prefix) ||
    next.members.some((member) => member.address === address)
  ) {
    throw new Error(`${address} is not a free address of ${next.range}.`);
  }
  if (next.blocked.includes(joiner.key)) {
    throw new Error(
      `${joiner.name}'s key was taken out of the network and cannot come back. Remove and prepare it again for a new key.`,
    );
  }
  if (!joiner.sealKey) {
    throw new Error(`${joiner.name} has not reported its seal key yet.`);
  }
  const member: NetworkMember = {
    node: joiner.node,
    name: joiner.name,
    address,
    key: joiner.key,
    signer: joiner.signer,
    sealKey: joiner.sealKey,
    port: joiner.port,
    mtu: null,
    endpoint: joiner.nat ? null : joiner.endpoint,
    nat: joiner.nat,
    psk: {},
    ...(joiner.kind ? { kind: joiner.kind } : {}),
  };
  for (const peer of next.members) {
    if (!links(peer, member)) continue;
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const [forPeer, forJoiner] = await Promise.all([
      seal(peer.sealKey, secret),
      seal(member.sealKey, secret),
    ]);
    peer.psk[member.node] = forPeer;
    member.psk[peer.node] = forJoiner;
  }
  next.members.push(member);
  return settle(next);
}

const names = (side: NetworkRule["from"] | NetworkRule["to"], node: string) =>
  "node" in side && side.node === node;

export function withoutMember(
  document: NetworkDocument,
  node: string,
): NetworkDocument {
  const next = copy(document);
  const gone = next.members.find((member) => member.node === node);
  if (gone && !next.blocked.includes(gone.key)) next.blocked.push(gone.key);
  next.members = next.members.filter((member) => member.node !== node);
  for (const member of next.members) delete member.psk[node];
  next.allow = next.allow.filter(
    (rule) => !names(rule.from, node) && !names(rule.to, node),
  );
  return settle(next);
}

export const canExit = (member: {
  kind?: "server" | "laptop";
  nat: boolean;
  endpoint: string | null;
}) => member.kind !== "laptop" && !member.nat && member.endpoint !== null;

export function withExit(
  document: NetworkDocument,
  node: string | null,
): NetworkDocument {
  const next = copy(document);
  if (node !== null) {
    const server = next.members.find((member) => member.node === node);
    if (!server) throw new Error("That server is not in the private network.");
    if (!canExit(server)) {
      throw new Error(
        `${server.name} needs a public address to be an Exit Node for Laptops.`,
      );
    }
    next.dns ??= [...LAPTOP_DNS];
  }
  for (const member of next.members) {
    if (member.node === node) member.exit = true;
    else delete member.exit;
  }
  return settle(next);
}

export function withoutNetwork(document: NetworkDocument): NetworkDocument {
  const next = copy(document);
  next.deleted = true;
  next.blocked = [
    ...new Set([...next.blocked, ...next.members.map((member) => member.key)]),
  ];
  next.members = [];
  next.allow = [];
  return settle(next);
}

export function withNewKey(
  document: NetworkDocument,
  node: string,
  key: string,
  signer: string,
): NetworkDocument {
  const next = copy(document);
  const member = next.members.find((one) => one.node === node);
  if (!member) throw new Error("That machine is not in the private network.");
  if (member.signer !== signer || next.blocked.includes(key)) {
    throw new Error(
      `${member.name} reported different keys; nothing was changed`,
    );
  }
  if (member.key !== key) {
    next.blocked.push(member.key);
    member.key = key;
  }
  return settle(next);
}

export function withDns(
  document: NetworkDocument,
  typed: string[],
): NetworkDocument {
  const dns = typed.map((one) => one.trim()).filter((one) => one !== "");
  if (dns.length === 0) {
    throw new Error("Enter at least one DNS address, like 1.1.1.1.");
  }
  const wrong = dns.find((one) => !IPV4.test(one));
  if (wrong !== undefined) {
    throw new Error(`${wrong} is not an IPv4 address.`);
  }
  const next = copy(document);
  next.dns = dns;
  return settle(next);
}

export function laptopInstall(code: LaptopCode): string {
  const args = ["install", "--code", code.code, "--origin", code.origin];
  if (code.endpoint !== code.origin) args.push("--endpoint", code.endpoint);
  return `& "$HOME\\Downloads\\krynodes-windows-amd64.exe" ${args.join(" ")} | Out-Host`;
}

export function testLines(
  message: string | null,
  name: string,
  peer: string,
): string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(message ?? "");
  } catch {
    parsed = null;
  }
  const read = networkTestSchema.safeParse(parsed);
  if (!read.success) {
    throw new Error(`${name} sent an answer Krynodes cannot read.`);
  }
  const { up, hasKey, firewall, handshakes, small, large } = read.data;
  return [
    `The tunnel on ${name} is ${up ? "up" : "down"}.`,
    `${name} ${hasKey ? "knows" : "does not know"} ${peer}'s key.`,
    `The firewall on ${name} ${firewall.lets ? "lets in" : "blocks"} the network port.`,
    handshakes.answered > 0
      ? `${peer} answered a handshake.`
      : `${peer} did not answer a handshake.`,
    `Round trip ${metricText(small.ms, " ms")}, ${small.lost} of ${small.sent} lost.`,
    `Largest packet ${large.passed ?? "--"}.`,
  ];
}

const pathOf = (
  via: string | null | undefined,
  names: ReadonlyMap<string, string>,
  direct = "Direct",
) => (via ? `Via ${names.get(via) ?? via}` : direct);

export function fleetRow(
  node: Pick<FleetNode, "address" | "via" | "ms">,
  names: ReadonlyMap<string, string>,
) {
  if (!node.address) return null;
  return {
    address: node.address,
    path: pathOf(node.via, names),
    ms: metricText(node.ms ?? null, " ms"),
  };
}

export const appliedText = (
  member: Pick<NetworkView["members"][number], "applied" | "failure">,
  version: number,
) => member.failure ?? (member.applied >= version ? "Applied" : "Applying…");

export function memberRow(
  view: NetworkView,
  node: Pick<FleetNode, "id" | "via" | "ms">,
) {
  const member = view.members.find((one) => one.node === node.id);
  if (!member) return null;
  const version = view.network?.version ?? 0;
  return {
    address: member.address ?? "--",
    path: pathOf(
      node.via,
      new Map(view.members.map((one) => [one.node, one.name])),
      member.kind !== "laptop" && !member.endpoint ? "Behind NAT" : "Direct",
    ),
    ms: metricText(node.ms ?? null, " ms"),
    state: appliedText(member, version),
  };
}

const REFUSALS: Record<string, string> = {
  VERSION_NOT_NEXT: "Someone changed the network meanwhile. Open it again.",
  KEY_CHANGED:
    "A machine's keys differ from the ones it reported. Open it again.",
  NOT_REQUESTED: "This machine has not asked to join the private network.",
  NOT_READY: "This machine is not ready to join the private network.",
  WRONG_KIND: "The document lists a machine as the wrong kind of member.",
  RANGE_CHANGED:
    "The network keeps its range. Delete it and create it again to change it.",
  ADDRESS_CHANGED: "A member keeps its address in the private network.",
  ADDRESS_TAKEN:
    "That address is still held by another machine. Open it again.",
};

export function networkFailure(error: unknown): string {
  if (
    error instanceof ApiError &&
    !error.details?.message &&
    error.code !== undefined &&
    Object.hasOwn(REFUSALS, error.code)
  ) {
    return REFUSALS[error.code]!;
  }
  return failure(error);
}

type Listener = Pick<NetworkMember, "node" | "name" | "port" | "endpoint">;

export const listeners = (document: NetworkDocument, online: Set<string>) =>
  document.members.filter(
    (member) =>
      member.kind !== "laptop" &&
      !member.nat &&
      member.endpoint !== null &&
      !member.cut &&
      online.has(member.node),
  );

export function probePlan(
  joiner: { node: string; port: number; public: string },
  heard: Listener[],
) {
  if (heard.length === 0) return [];
  return [
    {
      node: joiner.node,
      args: {
        port: String(joiner.port),
        peers: heard.map((member) => member.endpoint!).join(" "),
      },
    },
    ...heard.map((member) => ({
      node: member.node,
      args: {
        port: String(member.port),
        peers: `${joiner.public}:${joiner.port}`,
      },
    })),
  ];
}

const hostOf = (endpoint: string) =>
  endpoint.slice(0, endpoint.lastIndexOf(":")).replace(/^\[|\]$/gu, "");

export const probeArrived = (heard: Listener[], arrived: string[]) =>
  heard.some((member) => arrived.includes(hostOf(member.endpoint!)));

export const exitOf = (document: NetworkDocument | undefined) =>
  document === undefined
    ? undefined
    : (document.members.find((member) => member.exit)?.node ?? null);

export const firstReadyServer = (requests: JoinRequest[]) =>
  requests.find((request) => request.kind === "server" && request.ready);

export const testPeers = (view: Pick<NetworkView, "members">, node: string) =>
  view.members.filter(
    (member) => member.node !== node && member.address !== null,
  );

export const requestCount = (nodes: Pick<FleetNode, "request">[] | undefined) =>
  nodes?.filter((node) => node.request === "requested").length ?? 0;
