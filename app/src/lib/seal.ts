import { b64url, fromB64url } from "./passkeys";

const encoder = new TextEncoder();
const INFO = encoder.encode("krynodes-seal-v1");
const CURVE = { name: "ECDH", namedCurve: "P-256" } as const;

const decoder = new TextDecoder();

export interface SealPair {
  privateKey: CryptoKey;
  raw: Uint8Array<ArrayBuffer>;
  public: string;
}

async function cipherKey(
  shared: ArrayBuffer,
  epk: Uint8Array<ArrayBuffer>,
  recipient: Uint8Array<ArrayBuffer>,
  usage: "encrypt" | "decrypt",
) {
  const salt = new Uint8Array(epk.length + recipient.length);
  salt.set(epk);
  salt.set(recipient, epk.length);
  const base = await crypto.subtle.importKey("raw", shared, "HKDF", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: INFO },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    [usage],
  );
}

export async function sealPair(): Promise<SealPair> {
  const pair = (await crypto.subtle.generateKey(CURVE, false, [
    "deriveBits",
  ])) as CryptoKeyPair;
  const raw = new Uint8Array(
    await crypto.subtle.exportKey("raw", pair.publicKey),
  );
  return { privateKey: pair.privateKey, raw, public: b64url(raw) };
}

export async function openSealed(
  pair: SealPair,
  sealed: string,
): Promise<string> {
  const body = JSON.parse(decoder.decode(fromB64url(sealed))) as {
    v?: unknown;
    epk?: unknown;
    iv?: unknown;
    ct?: unknown;
  };
  if (
    body.v !== 1 ||
    typeof body.epk !== "string" ||
    typeof body.iv !== "string" ||
    typeof body.ct !== "string"
  ) {
    throw new Error("The sealed message is not valid.");
  }
  const epk = fromB64url(body.epk);
  const ephemeral = await crypto.subtle.importKey("raw", epk, CURVE, false, []);
  const shared = await crypto.subtle.deriveBits(
    { name: "ECDH", public: ephemeral },
    pair.privateKey,
    256,
  );
  const key = await cipherKey(shared, epk, pair.raw, "decrypt");
  return decoder.decode(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromB64url(body.iv) },
      key,
      fromB64url(body.ct),
    ),
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
  const key = await cipherKey(shared, epk, recipientRaw, "encrypt");
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
