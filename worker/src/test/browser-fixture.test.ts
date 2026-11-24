import { readFileSync } from "node:fs";

import { describe, it } from "vitest";

import { toB64url } from "../lib/b64url";
import { importKeyPair, signDocument, testPasskey } from "./passkeys";

const ORIGIN = "https://kry.example.org";
const RP_ID = "kry.example.org";
const NODE = "11111111-1111-4111-8111-111111111111";
const CHANGE_ID = "6c1f5a52-30de-4c1e-9d1b-0d7c3f6f2a01";
const COMMAND_ID = "6c1f5a52-30de-4c1e-9d1b-0d7c3f6f2a02";
const SIGNED_AT = Date.parse("2026-11-22T10:00:00.000Z");
const AGENT_NOW = SIGNED_AT + 30_000;
const CHANGE_MS = 10 * 60_000;
const SESSION_MS = 5 * 60_000;
const COMMAND_GRACE_MS = 60 * 60_000;

const KEYS = {
  laptop: {
    kty: "EC",
    crv: "P-256",
    x: "-PtWtv5mJmKoB5xyNWMR7Y35X3nExwYY-JikK-JBEoM",
    y: "IvmHFcLtSmQHndioKfG8-XIQSKEUfsBgkJZyAlU3Kd8",
    d: "rl7AUi1cha7o77hA-k5r8FGhvOa0hb149Bnu0K9oA84",
  },
  phone: {
    kty: "EC",
    crv: "P-256",
    x: "_i7_REYw50izDE07_mLn46V1i5rM1owZBqEdIm8xZPQ",
    y: "nTc_MEBVn6LS8hyHnmh0wAFmOBI-9XqbIL-RAGUxCBA",
    d: "LjzuGi69dCLsz4_jY7JYNEMltkXjj2JstdxP9yazlBA",
  },
  session: {
    kty: "EC",
    crv: "P-256",
    x: "DVZSEmcJUxDJBVfBeiANpsQMoJMtjkEkbl44wZLDQ64",
    y: "lAf9CvLnRVLig3zXFVyxTSqD1oiqtp_6kYe8qmVjspI",
    d: "LchKaeR5PpH67qEluAbGkG9mYE2EPWdFAq_0PYRumJs",
  },
};

const encoder = new TextEncoder();
const iso = (ms: number) => new Date(ms).toISOString();
const sha256 = async (bytes: Uint8Array) =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

async function build(touchOnly: boolean) {
  const laptop = await testPasskey(
    "AAECAwQFBgcICQoLDA0ODw",
    "Laptop",
    await importKeyPair(KEYS.laptop),
  );
  const phone = await testPasskey(
    "EBESExQVFhcYGRobHB0eHw",
    "Phone",
    await importKeyPair(KEYS.phone),
  );
  const session = await importKeyPair(KEYS.session);
  const verified = !touchOnly;
  const granting = touchOnly ? laptop : phone;

  const changeBytes = encoder.encode(
    JSON.stringify({
      v: 1,
      origin: ORIGIN,
      rpId: RP_ID,
      version: 2,
      issuedAt: iso(SIGNED_AT),
      expiresAt: iso(SIGNED_AT + CHANGE_MS),
      core: [laptop, phone].map(({ id, name, alg, publicKey }) => ({
        id,
        name,
        alg,
        publicKey,
      })),
      requireUv: true,
      access: { [NODE]: [laptop.id, phone.id] },
    }),
  );
  const approval = await laptop.sign({
    challenge: await sha256(changeBytes),
    origin: ORIGIN,
    rpId: RP_ID,
    verified,
  });
  const change = {
    change: toB64url(changeBytes),
    approvals: [approval],
  };

  const grantBytes = encoder.encode(
    JSON.stringify({
      v: 1,
      rpId: RP_ID,
      sessionKey: toB64url(
        new Uint8Array(
          (await crypto.subtle.exportKey(
            "spki",
            session.publicKey,
          )) as ArrayBuffer,
        ),
      ),
      issuedAt: iso(SIGNED_AT),
      expiresAt: iso(SIGNED_AT + SESSION_MS),
      nonce: "Zml4dHVyZS1ub25jZQ",
    }),
  );
  const grant = await granting.sign({
    challenge: await sha256(grantBytes),
    origin: ORIGIN,
    rpId: RP_ID,
    verified,
  });
  const commandBytes = encoder.encode(
    JSON.stringify({
      v: 1,
      id: COMMAND_ID,
      nodeId: NODE,
      kind: "host",
      name: "server-1",
      action: "restart",
      issuedAt: iso(SIGNED_AT + 10_000),
      expiresAt: iso(SIGNED_AT + SESSION_MS + COMMAND_GRACE_MS),
    }),
  );
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    session.privateKey,
    commandBytes,
  );
  const signedGrant = { grant: toB64url(grantBytes), ...grant };
  const command = {
    grant: signedGrant,
    command: toB64url(commandBytes),
    signature: toB64url(new Uint8Array(signature)),
  };
  const network: { valid: { document: { version: number } }[] } = JSON.parse(
    readFileSync(new URL("network-allow.json", fixtures), "utf8"),
  );
  const document = network.valid[0]!.document;
  const signedDocument = await signDocument(
    { key: session.privateKey, grant: signedGrant },
    encoder.encode(JSON.stringify(document)),
  );

  return {
    origin: ORIGIN,
    rpId: RP_ID,
    nodeId: NODE,
    now: iso(AGENT_NOW),
    tokens: [`${laptop.id}.${laptop.alg}.${laptop.publicKey}`],
    change: {
      type: "command",
      id: CHANGE_ID,
      kind: "trust",
      name: "server-1",
      action: "apply",
      signed: JSON.stringify(change),
    },
    command: {
      type: "command",
      id: COMMAND_ID,
      kind: "host",
      name: "server-1",
      action: "restart",
      signed: JSON.stringify(command),
    },
    document: {
      type: "document",
      version: document.version,
      signed: signedDocument,
    },
  };
}

const unsigned = (key: string, value: unknown): unknown =>
  key === "signature"
    ? "-"
    : key === "signed" && typeof value === "string"
      ? JSON.stringify(JSON.parse(value), unsigned)
      : value;

const fixtures = new URL(
  "../../../packages/protocol/src/fixtures/",
  import.meta.url,
);

describe("the browser fixtures", () => {
  it.each([
    ["browser-signed.json", false],
    ["browser-uv.json", true],
  ] as const)("%s is what the browser signs", async (name, touchOnly) => {
    const built = await build(touchOnly);
    const committed: unknown = JSON.parse(
      readFileSync(new URL(name, fixtures), "utf8"),
    );
    if (
      JSON.stringify(committed, unsigned) !== JSON.stringify(built, unsigned)
    ) {
      throw new Error(
        `${name} differs from what the browser signs; replace it with:\n${JSON.stringify(built, null, 2)}\n`,
      );
    }
  });
});
