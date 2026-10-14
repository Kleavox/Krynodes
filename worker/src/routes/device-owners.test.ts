import { describe, expect, it } from "vitest";

import { app } from "../app";
import type { Env } from "../env";
import { seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";

const NODE = "11111111-1111-4111-8111-111111111111";
const ACTION = "22222222-2222-4222-8222-222222222222";
const VERIFIED = Buffer.from(
  Uint8Array.from({ length: 37 }, (_, index) => (index === 32 ? 0x05 : 0)),
).toString("base64url");
const b64 = (value: unknown) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

function setup() {
  const { db, sqlite } = createTestDb();
  seedNode(sqlite, { id: NODE });
  sqlite
    .prepare(
      "UPDATE nodes SET agent_version = '0.6.10', docker = 'ready', last_seen_at = datetime('now') WHERE id = ?",
    )
    .run(NODE);
  const device = (id: string, account: string | null) =>
    sqlite
      .prepare(
        `INSERT INTO devices (id, owner_user_id, name, alg, public_key, created_at, verifies, account)
         VALUES (?, 'standalone', ?, -7, ?, '2026-10-01T00:00:00.000Z', 1, ?)`,
      )
      .run(id, id, Buffer.from(`key-${id}`).toString("base64url"), account);
  const env = { DB: db } as unknown as Env;
  const call = (method: string, path: string, body?: unknown) =>
    app.request(
      `https://kry.example.test${path}`,
      {
        method,
        headers: { "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      },
      env,
    );
  return { sqlite, device, call };
}

describe("devices that belong to an account", () => {
  it("say whose they are and which are yours", async () => {
    const t = setup();
    t.device("mine", "standalone@localhost");
    t.device("friends", "friend@example.test");
    t.device("loose", null);
    const listed = (
      (await (await t.call("GET", "/api/devices")).json()) as {
        devices: { id: string; owner: string | null; mine: boolean }[];
      }
    ).devices.map(({ id, owner, mine }) => ({ id, owner, mine }));
    expect(listed).toEqual([
      { id: "friends", owner: "friend@example.test", mine: false },
      { id: "loose", owner: null, mine: false },
      { id: "mine", owner: "standalone@localhost", mine: true },
    ]);
  });

  it("are renamed and forgotten only by their owner", async () => {
    const t = setup();
    t.device("friends", "friend@example.test");
    t.device("mine", "standalone@localhost");
    const rename = (id: string) =>
      t.call("PATCH", `/api/devices/${id}`, { name: "New name" });
    expect((await rename("friends")).status).toBe(403);
    expect((await rename("mine")).status).toBe(200);
    const forget = await t.call("DELETE", "/api/devices/friends");
    expect(forget.status).toBe(403);
    expect(await forget.json()).toMatchObject({ code: "NOT_YOUR_DEVICE" });
    expect((await t.call("DELETE", "/api/devices/mine")).status).toBe(200);
  });

  it("belong to whoever registers them", async () => {
    const t = setup();
    const response = await t.call("POST", "/api/devices", {
      id: "fresh",
      name: "Pixel",
      alg: -7,
      publicKey: "a2V5",
      verifies: true,
    });
    expect(response.status).toBe(201);
    expect(
      t.sqlite.prepare("SELECT account FROM devices WHERE id = 'fresh'").get(),
    ).toEqual({ account: "standalone@localhost" });
  });

  it("cannot sign an action for another account", async () => {
    const t = setup();
    t.device("ZnJpZW5kcw", "friend@example.test");
    const command = {
      v: 1,
      id: ACTION,
      nodeId: NODE,
      kind: "host",
      name: "server",
      action: "reboot",
    };
    const response = await t.call("POST", "/api/actions", {
      action: "reboot",
      targets: [
        {
          id: ACTION,
          nodeId: NODE,
          kind: "host",
          name: "server",
          signed: {
            grant: {
              grant: "Z3JhbnQ",
              credentialId: "ZnJpZW5kcw",
              authenticatorData: VERIFIED,
              clientDataJSON: "Y2xpZW50",
              signature: "c2ln",
            },
            command: b64(command),
            signature: "c2lnbmF0dXJl",
          },
        },
      ],
    });
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({
      code: "NOT_YOUR_DEVICE",
      message: "ZnJpZW5kcw belongs to friend. Use one of your own devices.",
    });
  });
});
