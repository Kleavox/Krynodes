import { describe, expect, it } from "vitest";

import { b64url, fromB64url } from "./passkeys";
import { seal } from "./seal";

const decoder = new TextDecoder();

async function recipient() {
  const pair = (await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  )) as CryptoKeyPair;
  const raw = new Uint8Array(
    await crypto.subtle.exportKey("raw", pair.publicKey),
  );
  return { pair, raw, public: b64url(raw) };
}

async function open(
  privateKey: CryptoKey,
  publicRaw: Uint8Array,
  sealed: string,
) {
  const body = JSON.parse(decoder.decode(fromB64url(sealed))) as {
    v: number;
    epk: string;
    iv: string;
    ct: string;
  };
  const epk = fromB64url(body.epk);
  const ephemeral = await crypto.subtle.importKey(
    "raw",
    epk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const shared = await crypto.subtle.deriveBits(
    { name: "ECDH", public: ephemeral },
    privateKey,
    256,
  );
  const base = await crypto.subtle.importKey("raw", shared, "HKDF", false, [
    "deriveKey",
  ]);
  const salt = new Uint8Array(epk.length + publicRaw.length);
  salt.set(epk);
  salt.set(publicRaw, epk.length);
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

describe("sealing for a server", () => {
  it("seals so that only the server's key opens it", async () => {
    const server = await recipient();
    const sealed = await seal(server.public, "SMTP_PASSWORD=hunter2");
    expect(await open(server.pair.privateKey, server.raw, sealed)).toEqual({
      version: 1,
      text: "SMTP_PASSWORD=hunter2",
    });
    const other = await recipient();
    await expect(
      open(other.pair.privateKey, other.raw, sealed),
    ).rejects.toThrow();
    expect(await seal(server.public, "SMTP_PASSWORD=hunter2")).not.toBe(sealed);
  });

  it("refuses a key that is not a server key", async () => {
    await expect(seal("short", "x")).rejects.toThrow();
  });
});
