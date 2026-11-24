import {
  links,
  networkDocumentSchema,
  type NetworkDocument,
  type NetworkRule,
} from "@krynodes/protocol";

export const S1 = "11111111-1111-4111-8111-111111111111";
export const S2 = "22222222-2222-4222-8222-222222222222";
export const S3 = "33333333-3333-4333-8333-333333333333";
export const L1 = "44444444-4444-4444-8444-444444444444";
export const L2 = "55555555-5555-4555-8555-555555555555";

const wgKey = (fill: number) =>
  btoa(String.fromCharCode(...new Uint8Array(32).fill(fill)));

const member = (
  node: string,
  name: string,
  host: number,
  fill: number,
  extra: Partial<NetworkDocument["members"][number]> = {},
): NetworkDocument["members"][number] => ({
  node,
  name,
  address: `10.88.37.${host}`,
  key: wgKey(fill),
  signer: wgKey(fill + 100),
  sealKey: "A".repeat(87),
  port: 51820,
  mtu: null,
  endpoint: extra.kind === "laptop" ? null : `203.0.113.${host}:51820`,
  nat: false,
  psk: {},
  ...extra,
});

export function network(allow: NetworkRule[]): NetworkDocument {
  const members = [
    member(S1, "server-1", 11, 1),
    member(S2, "server-2", 12, 2),
    member(S3, "server-3", 13, 3),
    member(L1, "laptop-1", 21, 4, { kind: "laptop", nat: true, relay: {} }),
    member(L2, "laptop-2", 22, 5, { kind: "laptop", nat: true, relay: {} }),
  ];
  for (const one of members) {
    for (const other of members) {
      if (one !== other && links(one, other)) one.psk[other.node] = "c2VhbGVk";
    }
  }
  return networkDocumentSchema.parse({
    v: 1,
    version: 4,
    range: "10.88.37.0/24",
    port: 51820,
    mtu: 1420,
    members,
    blocked: [],
    allow,
  });
}

export const ALL_LAPTOPS_TO_ALL_SERVERS: NetworkRule = {
  from: { group: "laptops" },
  to: { group: "servers" },
  ports: "all",
};

export const SERVER_1_TO_SERVER_2: NetworkRule = {
  from: { node: S1 },
  to: { node: S2 },
  ports: ["22/tcp"],
};

export const document = () =>
  network([ALL_LAPTOPS_TO_ALL_SERVERS, SERVER_1_TO_SERVER_2]);
