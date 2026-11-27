import { joinFingerprint } from "@krynodes/protocol";

import { b64url, fromB64url } from "./passkeys";
import { memoryStore, remember } from "./pins";
import { network } from "./rules-test-utils";
import type { SealDeps } from "./stacks";

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

export async function sealFromNode(
  node: Recipient,
  to: string,
  text: string,
): Promise<string> {
  const toRaw = fromB64url(to);
  const target = await crypto.subtle.importKey("raw", toRaw, CURVE, false, []);
  const ephemeral = (await crypto.subtle.generateKey(CURVE, true, [
    "deriveBits",
  ])) as CryptoKeyPair;
  const epk = new Uint8Array(
    await crypto.subtle.exportKey("raw", ephemeral.publicKey),
  );
  const toEphemeral = await crypto.subtle.deriveBits(
    { name: "ECDH", public: target },
    ephemeral.privateKey,
    256,
  );
  const toNode = await crypto.subtle.deriveBits(
    { name: "ECDH", public: target },
    node.privateKey,
    256,
  );
  const base = await crypto.subtle.importKey(
    "raw",
    new Uint8Array([...new Uint8Array(toEphemeral), ...new Uint8Array(toNode)]),
    "HKDF",
    false,
    ["deriveKey"],
  );
  const key = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array([...epk, ...node.raw, ...toRaw]),
      info: new TextEncoder().encode("krynodes-seal-from-node-v1"),
    },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(text),
  );
  return b64url(
    new TextEncoder().encode(
      JSON.stringify({
        v: 2,
        epk: b64url(epk),
        iv: b64url(iv),
        ct: b64url(ct),
      }),
    ),
  );
}

export async function pinnedNode() {
  const key = await recipient();
  const document = network([]);
  const member = document.members[0]!;
  member.sealKey = key.public;
  const store = memoryStore();
  remember(store, [
    {
      node: member.node,
      fingerprint: await joinFingerprint(
        member.key,
        member.signer,
        member.sealKey,
      ),
    },
  ]);
  const deps: SealDeps = {
    current: async () => ({ document, hash: "q".repeat(43) }),
    store,
  };
  return { key, deps };
}
