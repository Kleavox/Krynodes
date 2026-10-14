import { parseTimestamp } from "./format";

const SAME_ROUND_MS = 60 * 60_000;

export interface ServerAddress {
  family: 4 | 6;
  address: string;
}

interface Seen {
  ipv4?: string | null;
  ipv4_at?: string | null;
  ipv6?: string | null;
  ipv6_at?: string | null;
}

export function serverAddresses(node: Seen): ServerAddress[] {
  const found = [
    { family: 4 as const, address: node.ipv4, at: node.ipv4_at },
    { family: 6 as const, address: node.ipv6, at: node.ipv6_at },
  ].flatMap((entry) =>
    entry.address && entry.at
      ? [{ ...entry, at: parseTimestamp(entry.at) }]
      : [],
  );
  if (found.length === 0) return [];
  const newest = Math.max(...found.map((entry) => entry.at));
  return found
    .filter((entry) => entry.at >= newest - SAME_ROUND_MS)
    .map(({ family, address }) => ({ family, address: address! }));
}

export function maskAddress({ family, address }: ServerAddress): string {
  if (family === 4) {
    const parts = address.split(".");
    return `${parts[0]}.•.•.${parts.at(-1)}`;
  }
  const groups = address.split(":").filter((group) => group !== "");
  return `${groups[0]}:•••:${groups.at(-1)}`;
}
