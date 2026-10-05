import { b64url, fromB64url } from "./passkeys";

const encoder = new TextEncoder();
const INFO = encoder.encode("krynodes-seal-v1");
const CURVE = { name: "ECDH", namedCurve: "P-256" } as const;

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
  const salt = new Uint8Array(epk.length + recipientRaw.length);
  salt.set(epk);
  salt.set(recipientRaw, epk.length);
  const base = await crypto.subtle.importKey("raw", shared, "HKDF", false, [
    "deriveKey",
  ]);
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: INFO },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
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
