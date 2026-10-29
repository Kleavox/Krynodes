import { describe, expect, it } from "vitest";

import { app } from "../app";
import type { Env } from "../env";
import { toB64url } from "../lib/b64url";
import { fingerprint } from "../lib/webauthn";
import { LAPTOP, PHONE } from "../test/keys";
import { testPasskey, type TestPasskey } from "../test/passkeys";
import { seedCheck, seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";

const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const CHECK = "33333333-3333-4333-8333-333333333333";
const ORIGIN = "https://kry.example.test";
const RP = "kry.example.test";

const encoder = new TextEncoder();
const json = (value: unknown) =>
  new Uint8Array(encoder.encode(JSON.stringify(value)));
const sha256 = async (bytes: Uint8Array<ArrayBuffer>) =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

async function proof(
  passkey: TestPasskey,
  op: string,
  target: string,
  options: { verified?: boolean; at?: number } = {},
) {
  const now = Date.now();
  const pair = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const spki = new Uint8Array(
    (await crypto.subtle.exportKey("spki", pair.publicKey)) as ArrayBuffer,
  );
  const grant = json({
    v: 1,
    rpId: RP,
    sessionKey: toB64url(spki),
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 15 * 60_000).toISOString(),
    nonce: "n",
  });
  const intent = json({
    v: 1,
    op,
    target,
    at: new Date(options.at ?? now).toISOString(),
    origin: ORIGIN,
  });
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      pair.privateKey,
      intent,
    ),
  );
  return toB64url(
    json({
      grant: {
        grant: toB64url(grant),
        ...(await passkey.sign({
          challenge: await sha256(grant),
          origin: ORIGIN,
          rpId: RP,
          verified: options.verified ?? true,
        })),
      },
      command: toB64url(intent),
      signature: toB64url(signature),
    }),
  );
}

async function setup(core = true, requireUv = false, more: string[] = []) {
  const { db, sqlite } = createTestDb();
  seedNode(sqlite, { id: A });
  seedNode(sqlite, { id: B });
  seedCheck(sqlite, { id: CHECK, nodeId: A });
  const env = {
    DB: db,
    PUBLIC_ORIGIN: ORIGIN,
    ASSETS: {
      fetch: async () => new Response('#!/bin/sh\nmain "$@"\n'),
    },
  } as unknown as Env;
  const call = (
    method: string,
    path: string,
    body?: unknown,
    confirm?: string,
  ) =>
    app.request(
      `${ORIGIN}${path}`,
      {
        method,
        headers: {
          "content-type": "application/json",
          ...(confirm ? { "x-kry-proof": confirm } : {}),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      },
      env,
    );
  const phone = await testPasskey("phone");
  const others = await Promise.all(more.map((name) => testPasskey(name)));
  for (const device of [phone, ...others]) {
    await call("POST", "/api/devices", {
      id: device.id,
      name: device.name,
      alg: device.alg,
      publicKey: device.publicKey,
      verifies: true,
    });
  }
  if (core) {
    const prints = await Promise.all(
      [phone, ...others].map((device) => fingerprint(device.publicKey)),
    );
    sqlite.prepare("UPDATE nodes SET trust_report = ?").run(
      JSON.stringify({
        version: 1,
        core: prints,
        access: prints,
        passphrase: false,
        requireUv,
      }),
    );
  }
  const code = async (response: Response) =>
    ((await response.clone().json()) as { code?: string }).code;
  const installer = async (response: Response) => {
    const { enrollmentToken } = (await response.json()) as {
      enrollmentToken: string;
    };
    return (await call("GET", `/i/${enrollmentToken}`)).text();
  };
  return { call, phone, others, code, installer, sqlite };
}

describe("dashboard actions that destroy or hide", () => {
  it("need no fingerprint while the owner has no core devices", async () => {
    const t = await setup(false);
    const enroll = await t.call("POST", "/api/enrollments");
    expect(await t.installer(enroll)).not.toContain("--trust");
    expect((await t.call("DELETE", `/api/nodes/${A}`)).status).toBe(204);
  });

  it("refuse to delete a server without a fingerprint, or with one for another server", async () => {
    const t = await setup();
    const bare = await t.call("DELETE", `/api/nodes/${A}`);
    expect(bare.status).toBe(403);
    expect(await bare.json()).toMatchObject({
      code: "PROOF_NEEDED",
      op: "node.delete",
      target: A,
      core: ["phone"],
    });
    const other = await t.call(
      "DELETE",
      `/api/nodes/${A}`,
      undefined,
      await proof(t.phone, "node.delete", B),
    );
    expect(other.status).toBe(400);
    expect(await t.code(other)).toBe("BAD_PROOF");
    const stale = await t.call(
      "DELETE",
      `/api/nodes/${A}`,
      undefined,
      await proof(t.phone, "node.delete", A, { at: Date.now() - 180_000 }),
    );
    expect(stale.status).toBe(400);
    const good = await t.call(
      "DELETE",
      `/api/nodes/${A}`,
      undefined,
      await proof(t.phone, "node.delete", A),
    );
    expect(good.status).toBe(204);
  });

  it("refuse a passkey that skipped the fingerprint when servers require one", async () => {
    const t = await setup(true, true);
    const response = await t.call(
      "DELETE",
      `/api/nodes/${A}`,
      undefined,
      await proof(t.phone, "node.delete", A, { verified: false }),
    );
    expect(response.status).toBe(400);
    expect(await t.code(response)).toBe("FINGERPRINT_NEEDED");
  });

  it("guard pausing, retargeting and deleting a check and new enrollments, not renames", async () => {
    const t = await setup();
    expect(
      (await t.call("PATCH", `/api/checks/${CHECK}`, { name: "Web" })).status,
    ).toBe(200);
    expect(
      (await t.call("PATCH", `/api/checks/${CHECK}`, { enabled: false }))
        .status,
    ).toBe(403);
    expect(
      (await t.call("PATCH", `/api/checks/${CHECK}`, { nodeId: B })).status,
    ).toBe(403);
    expect(
      (
        await t.call(
          "PATCH",
          `/api/checks/${CHECK}`,
          { enabled: false },
          await proof(t.phone, "check.change", CHECK),
        )
      ).status,
    ).toBe(200);
    expect((await t.call("DELETE", `/api/checks/${CHECK}`)).status).toBe(403);
    expect((await t.call("POST", "/api/enrollments")).status).toBe(403);
    const enroll = await t.call(
      "POST",
      "/api/enrollments",
      undefined,
      await proof(t.phone, "enrollment.create", "new"),
    );
    expect(enroll.status).toBe(201);
    expect(await t.installer(enroll)).toContain(
      ` --trust ${ORIGIN} --grant -- phone.-7.${t.phone.publicKey}'`,
    );
  });

  it("refuse a device that belongs to another account, and leave it out of what to confirm with", async () => {
    const t = await setup(true, false, ["laptop"]);
    t.sqlite
      .prepare("UPDATE devices SET account = ? WHERE id = 'laptop'")
      .run("friend@example.test");
    const bare = await t.call("DELETE", `/api/nodes/${A}`);
    expect(await bare.json()).toMatchObject({
      code: "PROOF_NEEDED",
      core: ["phone"],
    });
    const laptop = t.others[0]!;
    const refused = await t.call(
      "DELETE",
      `/api/nodes/${A}`,
      undefined,
      await proof(laptop, "node.delete", A),
    );
    expect(refused.status).toBe(403);
    expect(await refused.json()).toMatchObject({
      code: "NOT_YOUR_DEVICE",
      message: "laptop belongs to friend. Use one of your own devices.",
    });
  });

  it("give an unclaimed device to the account that first confirms with it", async () => {
    const t = await setup();
    const owner = () =>
      (
        t.sqlite
          .prepare("SELECT account FROM devices WHERE id = 'phone'")
          .get() as { account: string | null }
      ).account;
    t.sqlite.prepare("UPDATE devices SET account = NULL").run();
    expect(owner()).toBeNull();
    const good = await t.call(
      "DELETE",
      `/api/nodes/${A}`,
      undefined,
      await proof(t.phone, "node.delete", A),
    );
    expect(good.status).toBe(204);
    expect(owner()).toBe("standalone@localhost");
  });

  it("let the device that made the install command reach the new server", async () => {
    const t = await setup(true, false, ["laptop"]);
    const enroll = await t.call(
      "POST",
      "/api/enrollments",
      undefined,
      await proof(t.phone, "enrollment.create", "new"),
    );
    expect(enroll.status).toBe(201);
    const laptop = t.others[0]!;
    const script = await t.installer(enroll);
    expect(script).toContain(` --trust ${ORIGIN} --access phone -- `);
    expect(script).toContain(`phone.-7.${t.phone.publicKey}`);
    expect(script).toContain(`laptop.-7.${laptop.publicKey}`);
    expect(script).not.toContain("--grant");
  });
});

describe("the SSH keys in enroll defaults", () => {
  const defaults = { recommended: true, docker: true, hour: 3, network: false };
  const digest = async (keys: string[]) =>
    Array.from(
      await sha256(new Uint8Array(encoder.encode(keys.join("\n")))),
      (byte) => byte.toString(16).padStart(2, "0"),
    ).join("");

  it("asks for the fingerprint only when the keys change", async () => {
    const t = await setup();
    const keys = [LAPTOP];
    expect(
      (
        await t.call("PUT", "/api/settings/enroll-defaults", {
          ...defaults,
          hour: 5,
        })
      ).status,
    ).toBe(200);
    const bare = await t.call("PUT", "/api/settings/enroll-defaults", {
      ...defaults,
      keys,
    });
    expect(bare.status).toBe(403);
    expect(await bare.json()).toMatchObject({
      code: "PROOF_NEEDED",
      op: "enroll.admin",
      target: await digest([LAPTOP]),
    });
    const other = await t.call(
      "PUT",
      "/api/settings/enroll-defaults",
      { ...defaults, keys },
      await proof(t.phone, "enroll.admin", await digest([PHONE])),
    );
    expect(other.status).toBe(400);
    const good = await t.call(
      "PUT",
      "/api/settings/enroll-defaults",
      { ...defaults, keys },
      await proof(t.phone, "enroll.admin", await digest([LAPTOP])),
    );
    expect(good.status).toBe(200);
    expect(
      (
        await t.call("PUT", "/api/settings/enroll-defaults", {
          ...defaults,
          hour: 6,
          keys,
        })
      ).status,
    ).toBe(200);
    const removing = await t.call("PUT", "/api/settings/enroll-defaults", {
      ...defaults,
      keys: [],
    });
    expect(await removing.json()).toMatchObject({
      code: "PROOF_NEEDED",
      target:
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    });
  });
});
