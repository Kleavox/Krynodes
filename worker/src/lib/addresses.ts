import { NETWORK } from "@krynodes/protocol";

import { canonicalAddress, inRanges } from "./ranges";

const IPV4 =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/u;
const IPV6 = /^[0-9a-f]{0,4}(:[0-9a-f]{0,4}){2,7}$/iu;
const NAME = /^[A-Za-z0-9._@:-]{1,15}$/u;
const MOST_INTERFACES = 64;
const SAME_ROUND_MS = 60 * 60_000;

export function familyOf(address: string): 4 | 6 | null {
  if (IPV4.test(address)) return 4;
  return address.length <= 39 && IPV6.test(address) ? 6 : null;
}

export interface Interface {
  name: string;
  address: string;
}

export function readInterfaces(body: unknown): Interface[] | null {
  if (typeof body !== "object" || body === null || !("interfaces" in body)) {
    return null;
  }
  const { interfaces } = body as { interfaces: unknown };
  if (!Array.isArray(interfaces)) return null;
  const kept = new Map<string, Interface>();
  for (const entry of interfaces) {
    if (kept.size === MOST_INTERFACES) break;
    if (typeof entry !== "object" || entry === null) continue;
    const { name, address } = entry as { name?: unknown; address?: unknown };
    if (typeof name !== "string" || typeof address !== "string") continue;
    if (!NAME.test(name) || !familyOf(address)) continue;
    kept.set(`${name} ${address}`, { name, address });
  }
  return kept.size > 0 ? [...kept.values()] : null;
}

type Owner = "own" | "router";

export interface Address {
  label: string;
  family: 4 | 6;
  address: string;
  router: boolean;
  network: string | null;
  owner: Owner | null;
}

export interface AddressColumns {
  ipv4: string | null;
  ipv4_at: string | null;
  ipv4_network: string | null;
  ipv4_owner: string | null;
  ipv6: string | null;
  ipv6_at: string | null;
  ipv6_network: string | null;
  ipv6_owner: string | null;
  interfaces: string | null;
}

function storedInterfaces(text: string | null): Interface[] | null {
  if (text === null) return null;
  try {
    return readInterfaces({ interfaces: JSON.parse(text) as unknown });
  } catch {
    return null;
  }
}

const ownerOf = (value: string | null): Owner | null =>
  value === "own" || value === "router" ? value : null;

export function listAddresses(
  row: AddressColumns,
  ranges: string[],
): Address[] {
  const interfaces = storedInterfaces(row.interfaces);
  const held = new Set(
    (interfaces ?? []).map((entry) => canonicalAddress(entry.address)),
  );
  const seen = (
    [
      [4, row.ipv4, row.ipv4_at, row.ipv4_network, row.ipv4_owner],
      [6, row.ipv6, row.ipv6_at, row.ipv6_network, row.ipv6_owner],
    ] as const
  ).flatMap(([family, address, at, network, owner]) =>
    address && at && familyOf(address) === family
      ? [
          {
            family,
            address,
            at: Date.parse(at),
            network,
            owner: ownerOf(owner),
          },
        ]
      : [],
  );
  const newest = Math.max(...seen.map((entry) => entry.at));
  const listed: Address[] = seen
    .filter((entry) => entry.at >= newest - SAME_ROUND_MS)
    .map(({ family, address, network, owner }) => ({
      label: `IPv${family}`,
      family,
      address,
      router:
        owner === null
          ? interfaces !== null && !held.has(canonicalAddress(address))
          : owner === "router",
      network,
      owner,
    }));
  const shown = new Set(listed.map((entry) => canonicalAddress(entry.address)));
  const vpn = (interfaces ?? [])
    .filter(
      (entry) =>
        inRanges(entry.address, ranges) &&
        !shown.has(canonicalAddress(entry.address)),
    )
    .map((entry) => ({ ...entry, family: familyOf(entry.address)! }))
    .sort((a, b) => a.name.localeCompare(b.name) || a.family - b.family)
    .map(({ name, address, family }) => ({
      label: name,
      family,
      address,
      router: false,
      network: name === NETWORK.interface ? "Private Network" : null,
      owner: null,
    }));
  return [...listed, ...vpn];
}
