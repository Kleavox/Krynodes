import { describe, expect, it } from "vitest";

import { fromB64url } from "../lib/b64url";
import { addDevice, addNode, ORIGIN, testEnv } from "../test/env";
import { testPasskey, type TestPasskey } from "../test/passkeys";

const RP = "kry.example.test";

async function register(
  harness: ReturnType<typeof testEnv>,
  passkey: TestPasskey,
  options: {
    name?: string;
    verified?: boolean;
    synced?: boolean;
    origin?: string;
    challenge?: string;
  } = {},
) {
  const issued = (await (
    await harness.send("POST", "/api/devices/register/options")
  ).json()) as { challenge: string };
  const challenge = options.challenge ?? issued.challenge;
  const assertion = await passkey.sign({
    challenge: fromB64url(challenge),
    origin: options.origin ?? ORIGIN,
    rpId: RP,
    verified: options.verified,
    synced: options.synced,
  });
  return harness.send("POST", "/api/devices/register", {
    id: passkey.id,
    name: options.name ?? "Laptop",
    alg: passkey.alg,
    publicKey: passkey.publicKey,
    challenge,
    assertion,
  });
}

describe("register/options", () => {
  it("issues a challenge for the dashboard's own host and lists the passkeys to exclude", async () => {
    const harness = testEnv();
    await addDevice(harness.db, "d1");
    const response = await harness.send(
      "POST",
      "/api/devices/register/options",
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body).toEqual({
      challenge: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/u),
      rpId: RP,
      user: { id: "standalone", name: "standalone@localhost" },
      exclude: ["d1"],
      expiresAt: expect.any(String),
    });
    expect(
      await harness.db
        .prepare("SELECT value FROM settings WHERE key = ?")
        .bind(`challenge:${body.challenge}`)
        .first(),
    ).toEqual({ value: body.expiresAt });
  });

  it("forgets challenges that have expired", async () => {
    const harness = testEnv();
    await harness.db
      .prepare(
        "INSERT INTO settings (key, value) VALUES ('challenge:old', '2026-11-22T00:00:00.000Z')",
      )
      .run();
    await harness.send("POST", "/api/devices/register/options");
    expect(
      await harness.db
        .prepare("SELECT key FROM settings WHERE key = 'challenge:old'")
        .first(),
    ).toBeNull();
  });
});

describe("register", () => {
  it("stores a passkey that proves it holds its key, once per challenge", async () => {
    const harness = testEnv();
    const passkey = await testPasskey("cred-1");
    const response = await register(harness, passkey, { synced: true });
    expect(response.status).toBe(201);
    expect(await response.json()).toEqual({ id: "cred-1" });
    expect(
      await harness.db
        .prepare("SELECT id, name, alg, public_key, synced FROM devices")
        .first(),
    ).toEqual({
      id: "cred-1",
      name: "Laptop",
      alg: "-7",
      public_key: passkey.publicKey,
      synced: 1,
    });
    expect(
      await harness.db.prepare("SELECT key FROM settings").first(),
    ).toBeNull();
  });

  it("a challenge works once", async () => {
    const harness = testEnv();
    const first = await testPasskey("cred-1");
    const second = await testPasskey("cred-2");
    const issued = (await (
      await harness.send("POST", "/api/devices/register/options")
    ).json()) as { challenge: string };
    const attempt = async (passkey: TestPasskey) =>
      (
        await harness.send("POST", "/api/devices/register", {
          id: passkey.id,
          name: "Key",
          alg: passkey.alg,
          publicKey: passkey.publicKey,
          challenge: issued.challenge,
          assertion: await passkey.sign({
            challenge: fromB64url(issued.challenge),
            origin: ORIGIN,
            rpId: RP,
          }),
        })
      ).status;
    expect(await attempt(first)).toBe(201);
    expect(await attempt(second)).toBe(400);
  });

  it("refuses an unknown or expired challenge", async () => {
    const harness = testEnv();
    const passkey = await testPasskey("cred-1");
    expect(
      (await register(harness, passkey, { challenge: "A".repeat(43) })).status,
    ).toBe(400);
    await harness.db
      .prepare(
        "INSERT INTO settings (key, value) VALUES (?, '2026-11-22T00:00:00.000Z')",
      )
      .bind(`challenge:${"B".repeat(43)}`)
      .run();
    expect(
      (await register(harness, passkey, { challenge: "B".repeat(43) })).status,
    ).toBe(400);
    expect(
      await harness.db.prepare("SELECT id FROM devices").first(),
    ).toBeNull();
  });

  it("refuses a proof from another origin or for another credential", async () => {
    const harness = testEnv();
    const passkey = await testPasskey("cred-1");
    const wrong = await register(harness, passkey, {
      origin: "https://evil.example",
    });
    expect(wrong.status).toBe(400);
    expect(await wrong.json()).toMatchObject({ code: "INVALID_PROOF" });
    const other = await testPasskey("cred-2");
    const issued = (await (
      await harness.send("POST", "/api/devices/register/options")
    ).json()) as { challenge: string };
    const mismatch = await harness.send("POST", "/api/devices/register", {
      id: "cred-1",
      name: "Key",
      alg: -7,
      publicKey: passkey.publicKey,
      challenge: issued.challenge,
      assertion: await other.sign({
        challenge: fromB64url(issued.challenge),
        origin: ORIGIN,
        rpId: RP,
      }),
    });
    expect(mismatch.status).toBe(400);
    expect(
      await harness.db.prepare("SELECT id FROM devices").first(),
    ).toBeNull();
  });

  it("refuses a passkey that does not ask for a fingerprint, face or PIN", async () => {
    const harness = testEnv();
    const response = await register(harness, await testPasskey("cred-1"), {
      verified: false,
    });
    expect(response.status).toBe(422);
    expect(await response.json()).toMatchObject({ code: "CANNOT_VERIFY" });
  });

  it("refuses a passkey it already has", async () => {
    const harness = testEnv();
    const passkey = await testPasskey("cred-1");
    expect((await register(harness, passkey)).status).toBe(201);
    const again = await register(harness, passkey);
    expect(again.status).toBe(409);
    expect(await again.json()).toMatchObject({ code: "DEVICE_EXISTS" });
  });
});

describe("listing, renaming and deleting", () => {
  async function trusted() {
    const harness = testEnv();
    await addNode(harness.db, "n1");
    await addDevice(harness.db, "core", "pk-core", "Laptop");
    await addDevice(harness.db, "access", "pk-access", "Phone");
    await addDevice(harness.db, "free", "pk-free", "Spare");
    await harness.db
      .prepare(
        "INSERT INTO node_trust (node_id, version, core, access, reported_at) VALUES ('n1', 1, '[\"core\"]', '[\"core\",\"access\"]', '2026-11-22T00:00:00.000Z')",
      )
      .run();
    return harness;
  }

  it("lists passkeys and which a server trusts", async () => {
    const { call } = await trusted();
    const list = (await (await call("/api/devices")).json()) as Record<
      string,
      unknown
    >[];
    expect(list.map((device) => [device.id, device.trusted])).toEqual([
      ["access", true],
      ["core", true],
      ["free", false],
    ]);
    expect(list[1]).toEqual({
      id: "core",
      name: "Laptop",
      alg: -7,
      publicKey: "pk-core",
      synced: false,
      createdAt: "2026-11-22T00:00:00.000Z",
      trusted: true,
    });
  });

  it("renames, refusing an empty name and an unknown passkey", async () => {
    const { db, send } = await trusted();
    expect(
      (await send("PATCH", "/api/devices/free", { name: " Desk " })).status,
    ).toBe(200);
    expect(
      await db.prepare("SELECT name FROM devices WHERE id = 'free'").first(),
    ).toEqual({ name: "Desk" });
    expect(
      (await send("PATCH", "/api/devices/free", { name: "" })).status,
    ).toBe(400);
    expect(
      (await send("PATCH", "/api/devices/ghost", { name: "x" })).status,
    ).toBe(404);
  });

  it("a trusted passkey cannot be deleted", async () => {
    const { db, send } = await trusted();
    for (const id of ["core", "access"]) {
      const response = await send("DELETE", `/api/devices/${id}`);
      expect(response.status).toBe(409);
      expect(await response.json()).toMatchObject({ code: "STILL_TRUSTED" });
    }
    expect(
      (
        await db
          .prepare("SELECT COUNT(*) AS n FROM devices")
          .first<{ n: number }>()
      )?.n,
    ).toBe(3);
  });

  it("an untrusted passkey can, and an unknown one is 404", async () => {
    const { db, send } = await trusted();
    expect((await send("DELETE", "/api/devices/free")).status).toBe(200);
    expect(
      await db.prepare("SELECT id FROM devices WHERE id = 'free'").first(),
    ).toBeNull();
    expect((await send("DELETE", "/api/devices/free")).status).toBe(404);
  });
});
