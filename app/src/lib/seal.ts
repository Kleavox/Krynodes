import { b64url, fromB64url } from "./passkeys";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const INFO = encoder.encode("krynodes-seal-v1");
const FROM_NODE_INFO = encoder.encode("krynodes-seal-from-node-v1");
const CURVE = { name: "ECDH", namedCurve: "P-256" } as const;

function join(...parts: Uint8Array[]) {
  const joined = new Uint8Array(
    parts.reduce((length, part) => length + part.length, 0),
  );
  let at = 0;
  for (const part of parts) {
    joined.set(part, at);
    at += part.length;
  }
  return joined;
}

async function cipherKey(
  secret: Uint8Array<ArrayBuffer>,
  salt: Uint8Array<ArrayBuffer>,
  info: Uint8Array<ArrayBuffer>,
  usage: "encrypt" | "decrypt",
) {
  const base = await crypto.subtle.importKey("raw", secret, "HKDF", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    [usage],
  );
}

export async function seal(
  publicKey: string,
  plaintext: string | Uint8Array<ArrayBuffer>,
): Promise<string> {
  const recipientRaw = fromB64url(publicKey);
  const recipient = await crypto.subtle.importKey(
    "raw",
    recipientRaw,
    CURVE,
    false,
    [],
  );
  const ephemeral = (await crypto.subtle.generateKey(CURVE, true, [
    "deriveBits",
  ])) as CryptoKeyPair;
  const shared = await crypto.subtle.deriveBits(
    { name: "ECDH", public: recipient },
    ephemeral.privateKey,
    256,
  );
  const epk = new Uint8Array(
    await crypto.subtle.exportKey("raw", ephemeral.publicKey),
  );
  const key = await cipherKey(
    new Uint8Array(shared),
    join(epk, recipientRaw),
    INFO,
    "encrypt",
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const body =
    typeof plaintext === "string" ? encoder.encode(plaintext) : plaintext;
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, body);
  return b64url(
    encoder.encode(
      JSON.stringify({
        v: 1,
        epk: b64url(epk),
        iv: b64url(iv),
        ct: b64url(ct),
      }),
    ),
  );
}

export async function oneTimeKey() {
  const pair = (await crypto.subtle.generateKey(CURVE, false, [
    "deriveBits",
  ])) as CryptoKeyPair;
  const publicRaw = new Uint8Array(
    await crypto.subtle.exportKey("raw", pair.publicKey),
  );
  return { privateKey: pair.privateKey, to: b64url(publicRaw), publicRaw };
}

export async function openFromNode(
  privateKey: CryptoKey,
  publicRaw: Uint8Array<ArrayBuffer>,
  nodeSealKey: string,
  sealed: string,
): Promise<string> {
  const body = JSON.parse(decoder.decode(fromB64url(sealed))) as {
    v?: unknown;
    epk?: unknown;
    iv?: unknown;
    ct?: unknown;
  } | null;
  if (
    body?.v !== 2 ||
    typeof body.epk !== "string" ||
    typeof body.iv !== "string" ||
    typeof body.ct !== "string"
  ) {
    throw new Error("The sealed message is not valid.");
  }
  const epk = fromB64url(body.epk);
  const nodeRaw = fromB64url(nodeSealKey);
  const ephemeral = await crypto.subtle.importKey("raw", epk, CURVE, false, []);
  const node = await crypto.subtle.importKey("raw", nodeRaw, CURVE, false, []);
  const fromEphemeral = await crypto.subtle.deriveBits(
    { name: "ECDH", public: ephemeral },
    privateKey,
    256,
  );
  const fromNode = await crypto.subtle.deriveBits(
    { name: "ECDH", public: node },
    privateKey,
    256,
  );
  const key = await cipherKey(
    join(new Uint8Array(fromEphemeral), new Uint8Array(fromNode)),
    join(epk, nodeRaw, publicRaw),
    FROM_NODE_INFO,
    "decrypt",
  );
  return decoder.decode(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromB64url(body.iv) },
      key,
      fromB64url(body.ct),
    ),
  );
}
