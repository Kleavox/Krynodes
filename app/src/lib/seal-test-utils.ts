import { b64url, fromB64url } from "./passkeys";

const CURVE = { name: "ECDH", namedCurve: "P-256" } as const;

const decoder = new TextDecoder();

export async function recipient() {
  const pair = (await crypto.subtle.generateKey(CURVE, true, [
    "deriveBits",
  ])) as CryptoKeyPair;
  const raw = new Uint8Array(
    await crypto.subtle.exportKey("raw", pair.publicKey),
  );
  return { privateKey: pair.privateKey, raw, public: b64url(raw) };
}

type Recipient = Awaited<ReturnType<typeof recipient>>;

export async function open(to: Recipient, sealed: string) {
  const body = JSON.parse(decoder.decode(fromB64url(sealed))) as {
    v: number;
    epk: string;
    iv: string;
    ct: string;
  };
  const epk = fromB64url(body.epk);
  const ephemeral = await crypto.subtle.importKey("raw", epk, CURVE, false, []);
  const shared = await crypto.subtle.deriveBits(
    { name: "ECDH", public: ephemeral },
    to.privateKey,
    256,
  );
  const base = await crypto.subtle.importKey("raw", shared, "HKDF", false, [
    "deriveKey",
  ]);
  const salt = new Uint8Array(epk.length + to.raw.length);
  salt.set(epk);
  salt.set(to.raw, epk.length);
  const key = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info: new TextEncoder().encode("krynodes-seal-v1"),
    },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  return {
    version: body.v,
    text: decoder.decode(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fromB64url(body.iv) },
        key,
        fromB64url(body.ct),
      ),
    ),
  };
}
