import {
  ADMIN_KEY_ARG,
  ADMIN_NAME,
  OFFER_ENTRY,
  PEER_ENTRY,
} from "@krynodes/protocol";

const PRIVATE: [number, number][] = [
  [0x0a000000, 8],
  [0xac100000, 12],
  [0xc0a80000, 16],
];

const maskOf = (prefix: number) =>
  prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;

function privateSubnet(text: string): boolean {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/u.exec(
    text,
  );
  if (!match) return false;
  const octets = match.slice(1, 5).map(Number);
  const prefix = Number(match[5]);
  if (octets.some((octet) => octet > 255) || prefix < 16 || prefix > 28) {
    return false;
  }
  const base = octets.reduce((value, octet) => value * 256 + octet, 0) >>> 0;
  return (
    (base & maskOf(prefix)) >>> 0 === base &&
    PRIVATE.some(([range, bits]) => (base & maskOf(bits)) >>> 0 === range)
  );
}

const keysAre = (args: Record<string, string>, keys: string[]) =>
  Object.keys(args).sort().join() === [...keys].sort().join();

export function bridgeArgsValid(
  action: string,
  args: Record<string, string>,
): boolean {
  if (action === "remove") return keysAre(args, []);
  return (
    action === "create" &&
    keysAre(args, ["kind", "subnet"]) &&
    (args.kind === "contained" || args.kind === "full") &&
    privateSubnet(args.subnet!)
  );
}

const list = (text: string | undefined) =>
  text === undefined || text === "" ? [] : text.split(",");

export function adminArgsValid(args: Record<string, string>): boolean {
  const keys = list(args.keys);
  return (
    keysAre(args, ["name", "keys"]) &&
    ADMIN_NAME.test(args.name!) &&
    args.name !== "root" &&
    keys.length >= 1 &&
    keys.length <= 4 &&
    keys.every((key) => ADMIN_KEY_ARG.test(key))
  );
}

export function stackNetworkArgsValid(args: Record<string, string>): boolean {
  const offers = list(args.offers);
  const peers = list(args.peers);
  return (
    offers.length <= 64 &&
    peers.length <= 64 &&
    offers.every((entry) => OFFER_ENTRY.test(entry)) &&
    peers.every((entry) => PEER_ENTRY.test(entry))
  );
}

export const hasStackNetworkArgs = (args: Record<string, string>) =>
  list(args.offers).length > 0 || list(args.peers).length > 0;
