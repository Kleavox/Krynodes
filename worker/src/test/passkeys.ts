import { toB64url } from "../lib/b64url";

const encoder = new TextEncoder();

const sha256 = async (data: Uint8Array | string) =>
  new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      typeof data === "string" ? encoder.encode(data) : data,
    ),
  );

const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

function der(p1363: Uint8Array): Uint8Array {
  const integer = (bytes: Uint8Array) => {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start += 1;
    let value = bytes.slice(start);
    if ((value[0] ?? 0) & 0x80) value = concat(new Uint8Array([0]), value);
    return concat(new Uint8Array([0x02, value.length]), value);
  };
  const body = concat(integer(p1363.slice(0, 32)), integer(p1363.slice(32)));
  return concat(new Uint8Array([0x30, body.length]), body);
}

export interface TestPasskey {
  id: string;
  name: string;
  alg: -7;
  publicKey: string;
  sign: (options: {
    challenge: Uint8Array;
    origin: string;
    rpId: string;
    verified?: boolean;
    synced?: boolean;
  }) => Promise<{
    credentialId: string;
    authenticatorData: string;
    clientDataJSON: string;
    signature: string;
  }>;
}

export async function testPasskey(id: string, name = id): Promise<TestPasskey> {
  const pair = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const spki = new Uint8Array(
    (await crypto.subtle.exportKey("spki", pair.publicKey)) as ArrayBuffer,
  );
  return {
    id,
    name,
    alg: -7,
    publicKey: toB64url(spki),
    async sign({ challenge, origin, rpId, verified = true, synced = false }) {
      const authData = concat(
        await sha256(rpId),
        new Uint8Array([
          (verified ? 0x05 : 0x01) | (synced ? 0x18 : 0),
          0,
          0,
          0,
          1,
        ]),
      );
      const clientData = encoder.encode(
        JSON.stringify({
          type: "webauthn.get",
          challenge: toB64url(challenge),
          origin,
          crossOrigin: false,
        }),
      );
      const p1363 = new Uint8Array(
        await crypto.subtle.sign(
          { name: "ECDSA", hash: "SHA-256" },
          pair.privateKey,
          concat(authData, await sha256(clientData)),
        ),
      );
      return {
        credentialId: id,
        authenticatorData: toB64url(authData),
        clientDataJSON: toB64url(clientData),
        signature: toB64url(der(p1363)),
      };
    },
  };
}

export async function testPassphrase() {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const raw = new Uint8Array(
    (await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer,
  );
  return {
    key: {
      salt: toB64url(new Uint8Array(16)),
      iterations: 600000,
      publicKey: toB64url(raw),
    },
  };
}
