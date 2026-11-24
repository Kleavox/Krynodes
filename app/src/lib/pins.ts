import {
  documentHash,
  joinFingerprint,
  type NetworkDocument,
} from "@krynodes/protocol";

import type { JoinRequest } from "../types";

export interface PinStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

export interface Unchecked {
  node: string;
  name: string;
  fingerprint: string;
  line: string;
  warning?: string;
}

interface Anchor {
  pins: Record<string, string>;
  version: number;
  hash: string | null;
}

interface Base {
  document: NetworkDocument;
  hash: string;
}

const KEY = "krynodes:network-anchor";

export function browserStore(): PinStore | null {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

export function memoryStore(): PinStore {
  const kept = new Map<string, string>();
  return {
    getItem: (key) => kept.get(key) ?? null,
    setItem: (key, value) => void kept.set(key, value),
  };
}

const empty = (): Anchor => ({ pins: {}, version: 0, hash: null });

function read(store: PinStore | null): Anchor {
  try {
    const raw = store?.getItem(KEY);
    if (!raw) return empty();
    const parsed = JSON.parse(raw) as Partial<Anchor> | null;
    const pins = parsed?.pins;
    if (
      typeof pins !== "object" ||
      pins === null ||
      Array.isArray(pins) ||
      !Object.values(pins).every((one) => typeof one === "string") ||
      !Number.isInteger(parsed?.version) ||
      (parsed?.hash !== null && typeof parsed?.hash !== "string")
    ) {
      return empty();
    }
    return { pins, version: parsed.version!, hash: parsed.hash };
  } catch {
    return empty();
  }
}

export function remember(
  store: PinStore | null,
  checked: { node: string; fingerprint: string }[],
  seen?: { version: number; hash: string },
): void {
  const anchor = read(store);
  for (const one of checked) anchor.pins[one.node] = one.fingerprint;
  if (seen && seen.version >= anchor.version) {
    anchor.version = seen.version;
    anchor.hash = seen.hash;
  }
  try {
    store?.setItem(KEY, JSON.stringify(anchor));
  } catch {
    return;
  }
}

export async function fingerprintOf(
  request: Pick<JoinRequest, "name" | "kind" | "key" | "signer" | "sealKey">,
) {
  if (!request.key || !request.signer || !request.sealKey) {
    throw new Error(`${request.name} has not reported its network keys yet.`);
  }
  const where =
    request.kind === "laptop"
      ? "in the tray, Fingerprint"
      : "run sudo kry network fingerprint on it";
  return {
    fingerprint: await joinFingerprint(
      request.key,
      request.signer,
      request.sealKey,
    ),
    line: `Check that ${request.name} shows the same fingerprint: ${where}.`,
  };
}

export function checkBase(base: Base, store: PinStore | null): void {
  const anchor = read(store);
  if (base.document.version < anchor.version) {
    throw new Error(
      "The network document is older than the one this browser last signed or checked. Nothing was signed.",
    );
  }
  if (base.document.version === anchor.version && base.hash !== anchor.hash) {
    throw new Error(
      "The network document is not the one this browser last signed or checked. Nothing was signed.",
    );
  }
}

export async function checkAnchor(
  current: Base,
  store: PinStore | null,
): Promise<Unchecked[]> {
  checkBase(current, store);
  const { pins } = read(store);
  const unchecked: Unchecked[] = [];
  for (const member of current.document.members) {
    const shown = await fingerprintOf({
      ...member,
      kind: member.kind ?? "server",
    });
    const pinned = pins[member.node];
    if (pinned === undefined) {
      unchecked.push({ node: member.node, name: member.name, ...shown });
    } else if (pinned !== shown.fingerprint) {
      unchecked.push({
        node: member.node,
        name: member.name,
        ...shown,
        warning: `${member.name}'s keys changed since this browser last saw them. Check them on ${member.name} before you go on.`,
      });
    }
  }
  return unchecked;
}

export const hashOf = (document: NetworkDocument) =>
  documentHash(new TextEncoder().encode(JSON.stringify(document)));
