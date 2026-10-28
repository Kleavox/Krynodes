import { fromB64url, toB64url } from "./b64url";

const encoder = new TextEncoder();

export interface StoredKey {
  alg: number;
  publicKey: string;
}

export interface SignedAssertion {
  credentialId: string;
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
}

const sha256 = async (data: Uint8Array) =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(data)));

const equal = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((byte, index) => byte === b[index]);

function p1363(der: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(64);
  let offset = 2;
  for (const slot of [0, 32]) {
    const length = der[offset + 1] ?? 0;
    const value = der.slice(offset + 2, offset + 2 + length);
    const trimmed = value.slice(Math.max(0, value.length - 32));
    out.set(trimmed, slot + 32 - trimmed.length);
    offset += 2 + length;
  }
  return out;
}

async function verifySignature(
  key: StoredKey,
  signature: Uint8Array<ArrayBuffer>,
  data: Uint8Array<ArrayBuffer>,
): Promise<boolean> {
  const spki = fromB64url(key.publicKey);
  if (key.alg === -7) {
    const imported = await crypto.subtle.importKey(
      "spki",
      spki,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      imported,
      p1363(signature),
      data,
    );
  }
  const imported = await crypto.subtle.importKey(
    "spki",
    spki,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify("RSASSA-PKCS1-v1_5", imported, signature, data);
}

export const assertionUv = (authenticatorData: string) =>
  ((fromB64url(authenticatorData)[32] ?? 0) & 0x04) !== 0;

export const assertionSynced = (authenticatorData: string) =>
  ((fromB64url(authenticatorData)[32] ?? 0) & 0x08) !== 0;

export async function verifyAssertion(
  key: StoredKey,
  assertion: SignedAssertion,
  expected: { origin: string; rpId: string; challenge: Uint8Array },
): Promise<{ uv: boolean }> {
  const authData = fromB64url(assertion.authenticatorData);
  const clientBytes = fromB64url(assertion.clientDataJSON);
  let client: {
    type?: unknown;
    challenge?: unknown;
    origin?: unknown;
    crossOrigin?: unknown;
  };
  try {
    client = JSON.parse(new TextDecoder().decode(clientBytes)) as typeof client;
  } catch {
    throw new Error("client data is not JSON");
  }
  if (client.type !== "webauthn.get") {
    throw new Error("client data is not an assertion");
  }
  if (client.challenge !== toB64url(expected.challenge)) {
    throw new Error("challenge does not match");
  }
  if (client.origin !== expected.origin) {
    throw new Error("origin does not match");
  }
  if (client.crossOrigin === true) throw new Error("cross-origin assertion");
  if (authData.length < 37) throw new Error("authenticator data is too short");
  if (
    !equal(authData.slice(0, 32), await sha256(encoder.encode(expected.rpId)))
  ) {
    throw new Error("rp id does not match");
  }
  const flags = authData[32] ?? 0;
  if ((flags & 0x01) === 0) throw new Error("the passkey was not touched");
  const signed = new Uint8Array(authData.length + 32);
  signed.set(authData);
  signed.set(await sha256(clientBytes), authData.length);
  if (!(await verifySignature(key, fromB64url(assertion.signature), signed))) {
    throw new Error("passkey signature is invalid");
  }
  return { uv: (flags & 0x04) !== 0 };
}

export async function fingerprint(publicKey: string): Promise<string> {
  const digest = await sha256(fromB64url(publicKey));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 16);
}
