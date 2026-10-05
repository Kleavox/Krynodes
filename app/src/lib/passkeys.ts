import type { ActionKind } from "../types";

export const SESSION_MS = 5 * 60_000;
const COMMAND_GRACE_MS = 60 * 60_000;
const BROWSER_KEY = "kry.devices";

export interface Approval {
  credentialId: string;
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
}

interface SignedGrant extends Approval {
  grant: string;
}

export interface SignedCommand {
  grant: SignedGrant;
  command: string;
  signature: string;
}

export interface Session {
  key: CryptoKey;
  grant: SignedGrant;
  issuedAt: number;
  expiresAt: number;
}

export interface DeviceInput {
  id: string;
  name: string;
  alg: number;
  publicKey: string;
  verifies: boolean;
}

const encoder = new TextEncoder();
const iso = (ms: number) => new Date(ms).toISOString();

export function b64url(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (const byte of view) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

export function fromB64url(text: string): Uint8Array<ArrayBuffer> {
  const padded = text.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

const sha256 = async (bytes: Uint8Array<ArrayBuffer>) =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

const random = (length: number) =>
  crypto.getRandomValues(new Uint8Array(length));

const NOT_TOUCHED =
  "The passkey was not touched. Try again and confirm on your device.";

const NO_FINGERPRINT =
  "This passkey did not verify a fingerprint. Use the fingerprint, or choose Use a phone or a security key.";

const HINTS = ["client-device", "security-key", "hybrid"];

export function nameFor(transports: string[], fallback: string): string {
  if (transports.includes("hybrid")) return "Phone";
  if (transports.some((item) => ["usb", "nfc", "ble"].includes(item))) {
    return "Security key";
  }
  return fallback;
}

function requireFingerprint(
  authenticatorData: ArrayBuffer,
  attachment: string | null | undefined,
) {
  const flags = new Uint8Array(authenticatorData)[32] ?? 0;
  if ((flags & 0x01) !== 0x01) {
    const detail = [
      `flags 0x${flags.toString(16).padStart(2, "0")}`,
      attachment ?? "unknown authenticator",
    ].join(", ");
    throw new Error(`${NOT_TOUCHED} (${detail})`);
  }
  if ((flags & 0x04) !== 0x04) throw new Error(NO_FINGERPRINT);
}

export function thisBrowser(): string[] {
  try {
    const stored: unknown = JSON.parse(
      localStorage.getItem(BROWSER_KEY) ?? "[]",
    );
    return Array.isArray(stored)
      ? stored.filter((id): id is string => typeof id === "string")
      : [];
  } catch {
    return [];
  }
}

function remember(id: string) {
  try {
    const known = thisBrowser();
    if (known.includes(id)) return;
    localStorage.setItem(
      BROWSER_KEY,
      JSON.stringify([...known, id].slice(-10)),
    );
  } catch {
    return;
  }
}

export async function registerDevice(
  name: string,
  rpId: string,
  user: { id: string; name: string },
  existing: string[],
  options: { guessed?: boolean } = {},
): Promise<DeviceInput> {
  const credential = (await navigator.credentials.create({
    publicKey: {
      rp: { id: rpId, name: "Krynodes" },
      user: {
        id: encoder.encode(user.id),
        name: user.name,
        displayName: user.name,
      },
      challenge: random(32),
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      authenticatorSelection: {
        userVerification: "required",
        residentKey: "preferred",
      },
      hints: HINTS,
      attestation: "none",
      excludeCredentials: existing.map((id) => ({
        type: "public-key" as const,
        id: fromB64url(id),
      })),
      timeout: 120_000,
    },
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("No passkey was created.");
  const response = credential.response as AuthenticatorAttestationResponse;
  requireFingerprint(
    response.getAuthenticatorData(),
    credential.authenticatorAttachment,
  );
  const publicKey = response.getPublicKey();
  if (!publicKey)
    throw new Error("This browser does not share the passkey's public key.");
  if (credential.authenticatorAttachment !== "cross-platform") {
    remember(credential.id);
  }
  return {
    id: credential.id,
    name: options.guessed
      ? nameFor(response.getTransports?.() ?? [], name)
      : name,
    alg: response.getPublicKeyAlgorithm(),
    publicKey: b64url(publicKey),
    verifies: true,
  };
}

async function assert(
  bytes: Uint8Array<ArrayBuffer>,
  rpId: string,
  devices: string[],
): Promise<Approval> {
  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: await sha256(bytes),
      rpId,
      allowCredentials: devices.map((id) => ({
        type: "public-key" as const,
        id: fromB64url(id),
      })),
      userVerification: "required",
      hints: HINTS,
      timeout: 120_000,
    },
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("The passkey did not answer.");
  const response = credential.response as AuthenticatorAssertionResponse;
  requireFingerprint(
    response.authenticatorData,
    credential.authenticatorAttachment,
  );
  if (credential.authenticatorAttachment !== "cross-platform") {
    remember(credential.id);
  }
  return {
    credentialId: credential.id,
    authenticatorData: b64url(response.authenticatorData),
    clientDataJSON: b64url(response.clientDataJSON),
    signature: b64url(response.signature),
  };
}

export function approveChange(
  change: string,
  devices: string[],
  rpId: string,
): Promise<Approval> {
  return assert(fromB64url(change), rpId, devices);
}

export async function createSession(
  devices: string[],
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
  const grantBytes = encoder.encode(
    JSON.stringify({
      v: 1,
      rpId,
      sessionKey: b64url(spki),
      issuedAt: iso(now),
      expiresAt: iso(expiresAt),
      nonce: b64url(random(16)),
    }),
  );
  const approval = await assert(grantBytes, rpId, devices);
  return {
    key: pair.privateKey,
    grant: { grant: b64url(grantBytes), ...approval },
    issuedAt: now,
    expiresAt,
  };
}

export interface CommandTarget {
  nodeId: string;
  kind: ActionKind;
  name: string;
  compose?: string;
}

export function actionCommand(
  target: CommandTarget & { id: string; action: string },
  session: Session,
  now = Date.now(),
) {
  return {
    v: 1,
    id: target.id,
    nodeId: target.nodeId,
    kind: target.kind,
    name: target.name,
    action: target.action,
    issuedAt: iso(now),
    expiresAt: iso(session.expiresAt + COMMAND_GRACE_MS),
    ...(target.compose ? { compose: target.compose } : {}),
  };
}

export async function signCommand(
  session: Session,
  command: object,
): Promise<SignedCommand> {
  const bytes = encoder.encode(JSON.stringify(command));
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    session.key,
    bytes,
  );
  return {
    grant: session.grant,
    command: b64url(bytes),
    signature: b64url(signature),
  };
}

export async function signIntent(
  session: Session,
  op: string,
  target: string,
  origin: string,
  now = Date.now(),
): Promise<string> {
  const signed = await signCommand(session, {
    v: 1,
    op,
    target,
    at: iso(now),
    origin,
  });
  return b64url(encoder.encode(JSON.stringify(signed)));
}

export interface SignedTarget extends CommandTarget {
  id: string;
  signed: SignedCommand;
}

export function signTargets(
  session: Session,
  action: string,
  targets: CommandTarget[],
  now = Date.now(),
): Promise<SignedTarget[]> {
  return Promise.all(
    targets.map(async ({ nodeId, kind, name, compose }) => {
      const id = crypto.randomUUID();
      return {
        id,
        nodeId,
        kind,
        name,
        signed: await signCommand(
          session,
          actionCommand(
            { id, nodeId, kind, name, action, compose },
            session,
            now,
          ),
        ),
      };
    }),
  );
}
