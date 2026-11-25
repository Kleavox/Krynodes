import { z } from "zod";

export const NETWORK = {
  interface: "kry0",
  port: 51820,
  lastPort: 51919,
  relayPort: 51920,
  lastRelayPort: 52175,
  pool: "10.88.0.0/16",
  pool6: "fd88:88::/64",
  keepalive: 25,
  answerSeconds: 180,
  readSeconds: 120,
  mtuMargin: 80,
  variable: "KRY_PRIVATE_IP",
  places: 32,
  moveReaches: 8,
} as const;

const OCTET = "(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
const HOST = "(25[0-4]|2[0-4]\\d|1\\d\\d|[1-9]\\d?)";
const RANGE = new RegExp(`^10\\.88\\.${OCTET}\\.0/24$`, "u");
const POOL_HOST = new RegExp(`^10\\.88\\.${OCTET}\\.${HOST}$`, "u");
const SUBNET = new RegExp(
  `^${OCTET}\\.${OCTET}\\.${OCTET}\\.${OCTET}(?:/(\\d{1,2}))?$`,
  "u",
);
const PORT_RANGE = /^(\d{1,5})(-(\d{1,5}))?\/(tcp|udp)$/u;
export const IPV4 = new RegExp(`^${OCTET}(\\.${OCTET}){3}$`, "u");
const ENDPOINT = new RegExp(
  `^(${OCTET}(\\.${OCTET}){3}|\\[[0-9A-Fa-f:.]{2,45}\\]):(\\d{1,5})$`,
  "u",
);

export function dnsName(name: string): string {
  const label = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, "-")
    .replace(/^-+|-+$/gu, "")
    .slice(0, 63)
    .replace(/-+$/u, "");
  return label || "server";
}

function inRange(range: string, address: string): boolean {
  return POOL_HOST.test(address) && address.startsWith(range.slice(0, -4));
}

function endpointPort(endpoint: string): number | null {
  const parts = ENDPOINT.exec(endpoint);
  return parts ? Number(parts.at(-1)) : null;
}

export function laptopAddress6(address: string): string {
  if (!POOL_HOST.test(address)) {
    throw new RangeError(`${address} is not an address of ${NETWORK.pool}`);
  }
  const [third, fourth] = address.split(".").slice(2).map(Number);
  return `${NETWORK.pool6.slice(0, -3)}${third!.toString(16)}:${fourth!.toString(16)}`;
}

export const wireguardKey = z
  .string()
  .regex(/^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/u);
export const b64url = z
  .string()
  .min(1)
  .max(4096)
  .regex(/^[A-Za-z0-9_-]+$/u);
const port = z.number().int().min(NETWORK.port).max(NETWORK.lastPort);
const relayPort = z
  .number()
  .int()
  .min(NETWORK.relayPort)
  .max(NETWORK.lastRelayPort);
const mtu = z.number().int().min(1280).max(1500);
export const endpoint = z
  .string()
  .max(64)
  .refine((value) => {
    const found = endpointPort(value);
    return found !== null && found >= 1 && found <= 65535;
  });

export const sealKeySchema = z.string().regex(/^[A-Za-z0-9_-]{87}$/u);

const memberSchema = z.strictObject({
  node: z.string().uuid(),
  name: z.string().min(1).max(100),
  address: z.string().regex(POOL_HOST),
  key: wireguardKey,
  signer: wireguardKey,
  sealKey: sealKeySchema,
  port,
  mtu: mtu.nullable(),
  endpoint: endpoint.nullable(),
  nat: z.boolean(),
  psk: z.record(z.string().uuid(), b64url),
  kind: z.enum(["laptop"]).optional(),
  relay: z.record(z.string().uuid(), relayPort).optional(),
  exit: z.literal(true).optional(),
  rekey: z.literal(true).optional(),
  cut: z.literal(true).optional(),
});

type Member = z.infer<typeof memberSchema>;

const isLaptop = (member: Member) => member.kind === "laptop";

export function links(a: Member, b: Member): boolean {
  return !(isLaptop(a) && isLaptop(b));
}

const ipv4 = z.string().regex(IPV4);

const distinct = (values: (string | number)[]) =>
  new Set(values).size === values.length;

const nodeId = z.string().uuid();

function parsePort(
  text: string,
): { first: number; last: number; protocol: string } | null {
  const found = PORT_RANGE.exec(text);
  if (!found) return null;
  const ranged = found[3] !== undefined;
  const first = Number(found[1]);
  const last = ranged ? Number(found[3]) : first;
  const spelled =
    String(first) === found[1] && (!ranged || String(last) === found[3]);
  const inside = first >= 1 && last <= 65535 && (!ranged || first < last);
  return spelled && inside ? { first, last, protocol: found[4]! } : null;
}

const portRange = z.string().refine((text) => parsePort(text) !== null);

function disjoint(ports: string[]): boolean {
  const spans = ports.flatMap((text) => parsePort(text) ?? []);
  return spans.every((a, i) =>
    spans.every(
      (b, j) =>
        i >= j ||
        a.protocol !== b.protocol ||
        a.last < b.first ||
        b.last < a.first,
    ),
  );
}

const ruleSchema = z.strictObject({
  from: z.union([
    z.strictObject({ node: nodeId }),
    z.strictObject({ group: z.enum(["laptops", "servers"]) }),
  ]),
  to: z.union([
    z.strictObject({ node: nodeId }),
    z.strictObject({ group: z.literal("servers") }),
  ]),
  ports: z.union([
    z.literal("all"),
    z.array(portRange).min(1).max(8).refine(disjoint),
  ]),
});

type Rule = z.infer<typeof ruleSchema>;

const sideKey = (side: Rule["from"] | Rule["to"]) =>
  "node" in side ? `node:${side.node}` : `group:${side.group}`;

const ruleKey = (rule: Rule) =>
  [
    sideKey(rule.from),
    sideKey(rule.to),
    rule.ports === "all" ? "all" : [...rule.ports].sort().join(","),
  ].join(" ");

function rulesHold(document: { members: Member[]; allow: Rule[] }): boolean {
  const members = new Map(document.members.map((one) => [one.node, one]));
  return (
    document.allow.every(({ from, to }) => {
      if ("node" in from && !members.has(from.node)) return false;
      if ("node" in to) {
        const target = members.get(to.node);
        if (target === undefined || isLaptop(target)) return false;
      }
      return !("node" in from && "node" in to && from.node === to.node);
    }) && distinct(document.allow.map(ruleKey))
  );
}

const relayed = (member: Member) =>
  !isLaptop(member) && member.nat && member.cut === undefined;

function relayHeld(member: Member, behind: string[]): boolean {
  const { relay } = member;
  if (!isLaptop(member)) return relay === undefined;
  return (
    relay !== undefined &&
    Object.keys(relay).length === behind.length &&
    behind.every((node) => Object.hasOwn(relay, node))
  );
}

const bodyHash = z.string().regex(/^[A-Za-z0-9_-]{43}$/u);

export const networkDocumentSchema = z
  .strictObject({
    v: z.literal(1),
    version: z.number().int().positive(),
    range: z.string().regex(RANGE),
    port,
    mtu,
    deleted: z.literal(true).optional(),
    parent: bodyHash.optional(),
    dns: z.array(ipv4).min(1).max(2).optional(),
    members: z.array(memberSchema).max(32),
    blocked: z.array(wireguardKey).max(1000),
    allow: z.array(ruleSchema).max(64),
  })
  .refine((document) => {
    const nodes = new Set(document.members.map((member) => member.node));
    const behind = document.members.filter(relayed).map((one) => one.node);
    return (
      nodes.size === document.members.length &&
      distinct(document.members.map((member) => member.address)) &&
      distinct(document.members.map((member) => member.key)) &&
      distinct(
        document.members.flatMap((member) => Object.values(member.relay ?? {})),
      ) &&
      document.members.every((member) => {
        const linked = document.members
          .filter((other) => other !== member && links(member, other))
          .map((other) => other.node);
        const held = Object.keys(member.psk);
        return (
          inRange(document.range, member.address) &&
          !document.blocked.includes(member.key) &&
          (member.exit === undefined || (!isLaptop(member) && !member.nat)) &&
          relayHeld(member, behind) &&
          held.length === linked.length &&
          linked.every((peer) => Object.hasOwn(member.psk, peer))
        );
      })
    );
  })
  .refine(rulesHold);

const portText = z
  .string()
  .regex(/^\d{5}$/u)
  .refine(
    (text) => Number(text) >= NETWORK.port && Number(text) <= NETWORK.lastPort,
  );

const PROBE_PEERS = 31;

const peersText = z
  .string()
  .max(1600)
  .refine((text) => {
    const peers = text.split(" ");
    return (
      peers.length >= 1 &&
      peers.length <= PROBE_PEERS &&
      peers.every((peer) => {
        const found = endpointPort(peer);
        return (
          found !== null && found >= NETWORK.port && found <= NETWORK.lastPort
        );
      })
    );
  });

const NETWORK_ARGS: Record<string, z.ZodType> = {
  inspect: z.strictObject({}),
  probe: z.strictObject({ port: portText, peers: peersText }),
  test: z.strictObject({
    peer: z.string().uuid(),
    address: z.string().regex(POOL_HOST),
    mtu: z
      .string()
      .regex(/^\d{4}$/u)
      .refine((text) => Number(text) >= 1280 && Number(text) <= 1500),
  }),
  prepare: z.strictObject({
    range: z.string().regex(RANGE),
    port: portText,
    parent: bodyHash.optional(),
  }),
  unprepare: z.strictObject({}),
  rekey: z.strictObject({}),
  drop: z.strictObject({
    node: z.string().uuid(),
    key: wireguardKey,
    address: z.string().regex(POOL_HOST),
  }),
};

export const NETWORK_VERBS: readonly string[] = Object.freeze(
  Object.keys(NETWORK_ARGS),
);

export function networkArgsValid(verb: string, args: unknown): boolean {
  return (
    Object.hasOwn(NETWORK_ARGS, verb) &&
    NETWORK_ARGS[verb]!.safeParse(args).success
  );
}

const unix = z.number().int().nonnegative();
const count = z.number().int().nonnegative();
const ms = z.number().nonnegative().nullable();

export const networkLinkSchema = z.strictObject({
  key: wireguardKey,
  handshake: unix.nullable(),
  rx: count,
  tx: count,
  endpoint: endpoint.nullable(),
  ms,
});

export const laptopEnrollSchema = z.strictObject({
  key: wireguardKey,
  signer: wireguardKey,
  port,
  sealKey: sealKeySchema,
});

const cidr = z.string().max(64);

export const networkInspectSchema = z.strictObject({
  kernel: z.strictObject({
    ok: z.boolean(),
    version: z.string().max(64).nullable(),
    reason: z.string().max(300).nullable(),
  }),
  tools: z.boolean(),
  iptables: z.boolean(),
  used: z.array(cidr).max(200),
  others: z
    .array(
      z.strictObject({
        name: z.string().max(15),
        address: cidr.nullable(),
        port: z.number().int().min(1).max(65535).nullable(),
      }),
    )
    .max(16),
  port: port.nullable(),
  mtu: z.number().int().min(576).max(65535).nullable(),
  public: ipv4.nullable(),
});

export const networkProbeSchema = z.strictObject({
  listened: z.boolean(),
  arrived: z.array(z.string().max(45)).max(PROBE_PEERS),
});

export const networkTestSchema = z.strictObject({
  up: z.boolean(),
  hasKey: z.boolean(),
  version: count.nullable(),
  clock: unix,
  publicAddress: z.string().max(45).nullable(),
  firewall: z.strictObject({ lets: z.boolean(), rule: z.boolean().nullable() }),
  handshakes: z.strictObject({
    sent: count,
    received: count,
    answered: count,
    third: z.boolean().nullable(),
  }),
  small: z.strictObject({ sent: count, lost: count, ms }),
  large: z.strictObject({
    passed: mtu.nullable(),
    tried: z.array(mtu).max(8),
  }),
});

export const networkPreparedSchema = z.strictObject({
  key: wireguardKey,
  signer: wireguardKey,
  port,
  mtu: z.number().int().min(576).max(65535).nullable(),
});

export const networkRekeySchema = z.strictObject({
  key: wireguardKey,
  signer: wireguardKey,
  fingerprint: z.string().regex(/^[0-9A-F]{4}(-[0-9A-F]{4}){3}$/u),
  signature: b64url,
});

export const networkInventorySchema = z.strictObject({
  prepared: networkPreparedSchema.optional(),
  points: z
    .array(
      z.strictObject({
        stack: z.string().max(63),
        target: z.string().max(253),
      }),
    )
    .max(200),
});

const portName = z.string().regex(/^\d{1,5}\/(tcp|udp)$/u);

export const placeSchema = z
  .string()
  .regex(new RegExp(`^${OCTET}(\\.${OCTET}){3}:\\d{1,5}\\/(tcp|udp)$`, "u"));

const serveSchema = z
  .strictObject({
    port: portName,
    all: z.literal(true).optional(),
    to: z.array(z.string().uuid()).min(1).max(32).optional(),
  })
  .refine((serve) => (serve.all === true) !== (serve.to !== undefined));

export const stackNetworkSchema = z.strictObject({
  serves: z.array(serveSchema).max(16),
  reaches: z.array(placeSchema).max(NETWORK.places),
  private: z.array(portName).max(64),
});

export type NetworkDocument = z.infer<typeof networkDocumentSchema>;
export type StackNetwork = z.infer<typeof stackNetworkSchema>;
export type NetworkMember = NetworkDocument["members"][number];
export type NetworkRule = NetworkDocument["allow"][number];
export type NetworkLink = z.infer<typeof networkLinkSchema>;
export type NetworkInspect = z.infer<typeof networkInspectSchema>;
export type NetworkTest = z.infer<typeof networkTestSchema>;
export type NetworkInventory = z.infer<typeof networkInventorySchema>;

export async function joinFingerprint(
  key: string,
  signer: string,
  sealKey: string,
): Promise<string> {
  const text = `krynodes-join-v1\n${key}\n${signer}\n${sealKey}`;
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  const hex = Array.from(new Uint8Array(digest).slice(0, 8), (byte) =>
    byte.toString(16).padStart(2, "0"),
  )
    .join("")
    .toUpperCase();
  return hex.match(/.{4}/gu)!.join("-");
}

function span(entry: string): [number, number] | null {
  if (entry.includes(":")) return null;
  const found = SUBNET.exec(entry);
  const bits = found?.[5] === undefined ? 32 : Number(found[5]);
  if (!found || bits > 32) {
    throw new RangeError(`${entry} is not an IPv4 address or subnet`);
  }
  const address = found
    .slice(1, 5)
    .reduce((sum, octet) => sum * 256 + Number(octet), 0);
  const size = 2 ** (32 - bits);
  const start = Math.floor(address / size) * size;
  return [start, start + size - 1];
}

const POOL_START = 10 * 2 ** 24 + 88 * 2 ** 16;

function below(size: number, random: () => number): number {
  const value = random();
  if (!(value >= 0 && value < 1)) {
    throw new RangeError(`${value} is not a number from 0 up to 1`);
  }
  return Math.min(size - 1, Math.floor(value * size));
}

export function pickRange(used: string[], random: () => number): string | null {
  const spans = used.map(span).filter((one) => one !== null);
  const free = Array.from({ length: 256 }, (_, x) => x).filter((x) => {
    const start = POOL_START + x * 256;
    return spans.every(([first, last]) => last < start || first > start + 255);
  });
  if (free.length === 0) return null;
  return `10.88.${free[below(free.length, random)]!}.0/24`;
}

function draw(pool: number[], count: number, random: () => number): number[] {
  const rest = [...pool];
  const picked: number[] = [];
  while (picked.length < count && rest.length > 0) {
    picked.push(rest.splice(below(rest.length, random), 1)[0]!);
  }
  return picked;
}

export function pickAddresses(
  range: string,
  taken: string[],
  freed: string[],
  count: number,
  random: () => number,
): string[] {
  if (!RANGE.test(range)) {
    throw new RangeError(`${range} is not a /24 of ${NETWORK.pool}`);
  }
  if (!Number.isInteger(count) || count < 0) {
    throw new RangeError(`${count} is not a number of addresses`);
  }
  const prefix = range.slice(0, -4);
  const hostOf = (address: string) =>
    inRange(range, address) ? Number(address.slice(prefix.length)) : 0;
  const held = new Set(taken.map(hostOf));
  const before = new Set(freed.map(hostOf));
  const open = Array.from({ length: 254 }, (_, i) => i + 1).filter(
    (host) => !held.has(host),
  );
  const fresh = draw(
    open.filter((host) => !before.has(host)),
    count,
    random,
  );
  const again = draw(
    open.filter((host) => before.has(host)),
    count - fresh.length,
    random,
  );
  if (fresh.length + again.length < count) {
    throw new RangeError(`${range} has no ${count} free addresses`);
  }
  return [...fresh, ...again].map((host) => `${prefix}${host}`);
}

export const DOCUMENT_TAG = "krynodes-document-v1\n";

export const DEFAULT_RULE: NetworkRule = {
  from: { group: "laptops" },
  to: { group: "servers" },
  ports: "all",
};

export async function documentHash(
  body: Uint8Array<ArrayBuffer>,
): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", body));
  return btoa(String.fromCharCode(...digest))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}
