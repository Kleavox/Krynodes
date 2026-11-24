import { DOCUMENT_TAG, type NetworkDocument } from "@krynodes/protocol";

import type { ActionKind } from "../types";
import { serverNow } from "./http";
import { assert, b64url, sha256, type Approval } from "./passkeys";

const SESSION_MS = 5 * 60_000;
const COMMAND_GRACE_MS = 60 * 60_000;
const CHANGE_MS = 10 * 60_000;

interface SignedGrant extends Approval {
  grant: string;
}

export interface Session {
  key: CryptoKey;
  grant: SignedGrant;
  expiresAt: number;
  offset: number;
}

export interface TrustKey {
  id: string;
  name: string;
  alg: number;
  publicKey: string;
}

export interface CommandTarget {
  id: string;
  nodeId: string;
  kind: ActionKind;
  name: string;
  action: string;
  args?: Record<string, string>;
}

const encoder = new TextEncoder();
const iso = (ms: number) => new Date(ms).toISOString();

export async function createSession(
  access: string[],
  rpId: string,
  now = Date.now(),
): Promise<Session> {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  );
  const spki = await crypto.subtle.exportKey("spki", pair.publicKey);
  const expiresAt = now + SESSION_MS;
  const offset = serverNow(now) - now;
  const grantBytes = encoder.encode(
    JSON.stringify({
      v: 1,
      rpId,
      sessionKey: b64url(spki),
      issuedAt: iso(now + offset),
      expiresAt: iso(expiresAt + offset),
      nonce: b64url(crypto.getRandomValues(new Uint8Array(16))),
    }),
  );
  const approval = await assert(await sha256(grantBytes), rpId, access);
  return {
    key: pair.privateKey,
    grant: { grant: b64url(grantBytes), ...approval },
    expiresAt,
    offset,
  };
}

let current: Session | null = null;
const ended = new WeakSet<Session>();
let timer: ReturnType<typeof setTimeout> | undefined;
let prompts = 0;
let watching = false;

const hidden = () =>
  typeof document !== "undefined" && document.visibilityState === "hidden";

export function endSession(): void {
  clearTimeout(timer);
  if (current) ended.add(current);
  current = null;
}

function usable(session: Session) {
  if (ended.has(session) || Date.now() >= session.expiresAt) {
    throw new Error(
      "Your passkey session has ended. Start again; nothing was sent.",
    );
  }
}

export function activeSession(now = Date.now()): Session | null {
  if (current && now >= current.expiresAt) endSession();
  return current;
}

function watchVisibility() {
  if (watching || typeof document === "undefined") return;
  watching = true;
  document.addEventListener("visibilitychange", () => {
    if (hidden() && prompts === 0) endSession();
  });
}

export async function openSession(access: string[]): Promise<Session> {
  watchVisibility();
  const open = activeSession();
  if (open && access.includes(open.grant.credentialId)) return open;
  prompts += 1;
  let next: Session;
  try {
    next = await createSession(access, location.hostname);
  } finally {
    prompts -= 1;
    if (hidden()) endSession();
  }
  endSession();
  if (hidden()) {
    ended.add(next);
  } else {
    current = next;
    timer = setTimeout(endSession, next.expiresAt - Date.now());
  }
  return next;
}

export function buildCommand(
  session: Session,
  target: CommandTarget,
  now = Date.now(),
) {
  return {
    v: 1,
    id: target.id,
    nodeId: target.nodeId,
    kind: target.kind,
    name: target.name,
    action: target.action,
    issuedAt: iso(now + session.offset),
    expiresAt: iso(session.expiresAt + session.offset + COMMAND_GRACE_MS),
    ...(target.args ? { args: target.args } : {}),
  };
}

export async function signCommand(
  session: Session,
  command: object,
): Promise<string> {
  usable(session);
  const bytes = encoder.encode(JSON.stringify(command));
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    session.key,
    bytes,
  );
  return JSON.stringify({
    grant: session.grant,
    command: b64url(bytes),
    signature: b64url(signature),
  });
}

export async function signDocument(
  session: Session,
  document: NetworkDocument,
): Promise<string> {
  usable(session);
  const bytes = encoder.encode(JSON.stringify(document));
  const tag = encoder.encode(DOCUMENT_TAG);
  const tagged = new Uint8Array(tag.length + bytes.length);
  tagged.set(tag);
  tagged.set(bytes, tag.length);
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    session.key,
    tagged,
  );
  return JSON.stringify({
    grant: session.grant,
    document: b64url(bytes),
    signature: b64url(signature),
  });
}

export function buildChange(
  change: {
    origin: string;
    version: number;
    core: TrustKey[];
    access: Record<string, string[]>;
  },
  now = serverNow(),
): Uint8Array<ArrayBuffer> {
  return encoder.encode(
    JSON.stringify({
      v: 1,
      origin: change.origin,
      rpId: new URL(change.origin).hostname,
      version: change.version,
      issuedAt: iso(now),
      expiresAt: iso(now + CHANGE_MS),
      core: change.core.map(({ id, name, alg, publicKey }) => ({
        id,
        name,
        alg,
        publicKey,
      })),
      requireUv: true,
      access: change.access,
    }),
  );
}

export async function signChange(
  change: Uint8Array<ArrayBuffer>,
  approvers: string[],
  rpId: string,
): Promise<string> {
  const approval = await assert(await sha256(change), rpId, approvers);
  return JSON.stringify({ change: b64url(change), approvals: [approval] });
}
