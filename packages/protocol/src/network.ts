import { z } from "zod";

import { OFFER_ENTRY, PEER_ENTRY } from "./bridges";

export const NETWORK = {
  interface: "kry0",
  port: 51820,
  lastPort: 51919,
  pool: "10.88.0.0/16",
  tailscale: "100.64.0.0/10",
  keepalive: 25,
  answerSeconds: 180,
  mtuMargin: 80,
  variable: "KRY_PRIVATE_IP",
  places: 32,
  moveReaches: 8,
} as const;

const OCTET = "(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
const HOST = "(25[0-4]|2[0-4]\\d|1\\d\\d|[1-9]\\d?)";
const RANGE = new RegExp(`^10\\.88\\.${OCTET}\\.0/24$`, "u");
const POOL_HOST = new RegExp(`^10\\.88\\.${OCTET}\\.${HOST}$`, "u");
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

const wireguardKey = z
  .string()
  .regex(/^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/u);
const b64url = z
  .string()
  .min(1)
  .max(4096)
  .regex(/^[A-Za-z0-9_-]+$/u);
const port = z.number().int().min(NETWORK.port).max(NETWORK.lastPort);
const mtu = z.number().int().min(1280).max(1500);
const endpoint = z
  .string()
  .max(64)
  .refine((value) => {
    const found = endpointPort(value);
    return found !== null && found >= 1 && found <= 65535;
  });

const memberSchema = z.strictObject({
  node: z.string().uuid(),
  name: z.string().min(1).max(100),
  address: z.string().regex(POOL_HOST),
  key: wireguardKey,
  signer: wireguardKey,
  port,
  mtu: mtu.nullable(),
  endpoint: endpoint.nullable(),
  nat: z.boolean(),
  psk: z.record(z.string().uuid(), b64url),
  rekey: z.literal(true).optional(),
  cut: z.literal(true).optional(),
});

const distinct = (values: string[]) => new Set(values).size === values.length;

export const networkDocumentSchema = z
  .strictObject({
    v: z.literal(1),
    version: z.number().int().positive(),
    range: z.string().regex(RANGE),
    port,
    mtu,
    deleted: z.literal(true).optional(),
    parent: z
      .string()
      .regex(/^[A-Za-z0-9_-]{43}$/u)
      .optional(),
    knocks: z
      .strictObject({
        scan: z.union([z.literal(5), z.literal(10), z.literal(20)]),
        stop: z.boolean(),
      })
      .optional(),
    members: z.array(memberSchema).max(32),
    blocked: z.array(wireguardKey).max(1000),
  })
  .refine((document) => {
    const nodes = new Set(document.members.map((member) => member.node));
    return (
      nodes.size === document.members.length &&
      distinct(document.members.map((member) => member.address)) &&
      distinct(document.members.map((member) => member.key)) &&
      document.members.every(
        (member) =>
          inRange(document.range, member.address) &&
          !document.blocked.includes(member.key) &&
          Object.keys(member.psk).length === nodes.size - 1 &&
          Object.keys(member.psk).every(
            (peer) => peer !== member.node && nodes.has(peer),
          ),
      )
    );
  });

const portText = z
  .string()
  .regex(/^\d{5}$/u)
  .refine(
    (text) => Number(text) >= NETWORK.port && Number(text) <= NETWORK.lastPort,
  );

const peersText = z
  .string()
  .max(1200)
  .refine((text) => {
    const peers = text.split(" ");
    return (
      peers.length >= 1 &&
      peers.length <= 16 &&
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
  prepare: z.strictObject({ range: z.string().regex(RANGE), port: portText }),
  unprepare: z.strictObject({}),
  rekey: z.strictObject({}),
  drop: z.strictObject({
    node: z.string().uuid(),
    key: wireguardKey,
    address: z.string().regex(POOL_HOST),
  }),
  tighten: z.strictObject({
    scan: z.enum(["5", "10", "20"]),
    stop: z.enum(["true", "false"]),
  }),
};

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

export const networkBeatSchema = z.strictObject({
  version: count,
  key: wireguardKey.nullable(),
  links: z.array(networkLinkSchema).max(32),
  announce: z.strictObject({ key: wireguardKey, signature: b64url }).optional(),
});

const cidr = z.string().max(64);

export const networkInspectSchema = z.strictObject({
  kernel: z.strictObject({
    ok: z.boolean(),
    version: z.string().max(64).nullable(),
    reason: z.string().max(300).nullable(),
  }),
  tools: z.boolean(),
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
});

export const networkProbeSchema = z.strictObject({
  listened: z.boolean(),
  arrived: z.array(z.string().max(45)).max(16),
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
  offers: z.array(z.string().regex(OFFER_ENTRY)).max(64).optional(),
  peers: z.array(z.string().regex(PEER_ENTRY)).max(64).optional(),
});

export type NetworkDocument = z.infer<typeof networkDocumentSchema>;
export type StackNetwork = z.infer<typeof stackNetworkSchema>;
export type NetworkMember = NetworkDocument["members"][number];
export type NetworkBeat = z.infer<typeof networkBeatSchema>;
export type NetworkLink = z.infer<typeof networkLinkSchema>;
export type NetworkInspect = z.infer<typeof networkInspectSchema>;
export type NetworkTest = z.infer<typeof networkTestSchema>;
export type NetworkInventory = z.infer<typeof networkInventorySchema>;
