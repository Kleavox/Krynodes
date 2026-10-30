import { describe, expect, it } from "vitest";

import { app } from "../app";
import type { Env } from "../env";
import { fingerprint } from "../lib/webauthn";
import { seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";

const NODE = "11111111-1111-4111-8111-111111111111";
const ME = "standalone@localhost";

const keyOf = (id: string) => Buffer.from(`key-${id}`).toString("base64url");

async function setup(device: {
  account: string | null;
  removed?: boolean;
  inAccess?: boolean;
  report?: boolean;
}) {
  const { db, sqlite } = createTestDb();
  seedNode(sqlite, { id: NODE });
  sqlite
    .prepare(
      `INSERT INTO devices (id, owner_user_id, name, alg, public_key, created_at, verifies, account, removed_at)
       VALUES ('laptop', 'standalone', 'Laptop', -7, ?, '2026-10-01T00:00:00.000Z', 1, ?, ?)`,
    )
    .run(
      keyOf("laptop"),
      device.account,
      device.removed ? "2026-10-20T00:00:00.000Z" : null,
    );
  const print = await fingerprint(keyOf("laptop"));
  const access = device.inAccess === false ? [] : [print];
  sqlite
    .prepare(
      `UPDATE nodes SET name = 'server-1', ipv4 = '203.0.113.12', ipv4_at = ?,
         interfaces = '[{"name":"eth0","address":"192.168.1.5"}]', trust_report = ?
       WHERE id = ?`,
    )
    .run(
      new Date().toISOString(),
      device.report === false
        ? null
        : JSON.stringify({
            version: 1,
            core: [print],
            access,
            passphrase: false,
            requireUv: false,
          }),
      NODE,
    );
  const env = { DB: db } as unknown as Env;
  const call = (method: string, path: string, body?: unknown) =>
    app.request(
      `https://kry.example.test${path}`,
      {
        method,
        headers: { "content-type": "application/json" },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      },
      env,
    );
  const overview = async () =>
    (await (await call("GET", "/api/overview")).json()) as {
      nodes: { addresses: unknown }[];
    };
  const owner = () =>
    (
      sqlite.prepare("SELECT ipv4_owner FROM nodes WHERE id = ?").get(NODE) as {
        ipv4_owner: string | null;
      }
    ).ipv4_owner;
  return { call, overview, owner };
}

describe("who sees a server's addresses", () => {
  it("are sent to an account whose device the server trusts", async () => {
    const t = await setup({ account: ME });
    expect((await t.overview()).nodes[0]!.addresses).toEqual([
      {
        label: "IPv4",
        family: 4,
        address: "203.0.113.12",
        router: true,
        network: null,
        owner: null,
      },
    ]);
  });

  it.each([
    ["another account's device", { account: "friend@example.test" }],
    ["an unclaimed device", { account: null }],
    ["a removed device", { account: ME, removed: true }],
    ["a server with no trust report", { account: ME, report: false }],
    ["a device the server does not let in", { account: ME, inAccess: false }],
  ])(
    "are withheld from an account the server does not trust: %s",
    async (_, device) => {
      const t = await setup(device);
      const body = await t.overview();
      expect(body.nodes[0]!.addresses).toBeNull();
      expect(JSON.stringify(body)).not.toContain("203.0.113.12");
      expect(JSON.stringify(body)).not.toContain("192.168.1.5");
    },
  );

  it("let only a trusted account correct the tag", async () => {
    const t = await setup({ account: ME });
    const correct = (body: unknown) =>
      t.call("PATCH", `/api/nodes/${NODE}`, body);
    expect(
      (await correct({ addressOwner: { family: 4, owner: "own" } })).status,
    ).toBe(200);
    expect(t.owner()).toBe("own");
    expect((await t.overview()).nodes[0]!.addresses).toEqual([
      expect.objectContaining({ router: false, owner: "own" }),
    ]);
    expect(
      (await correct({ addressOwner: { family: 4, owner: null } })).status,
    ).toBe(200);
    expect(t.owner()).toBeNull();
    expect(
      (await correct({ addressOwner: { family: 5, owner: "own" } })).status,
    ).toBe(400);

    const stranger = await setup({ account: "friend@example.test" });
    const refused = await stranger.call("PATCH", `/api/nodes/${NODE}`, {
      addressOwner: { family: 4, owner: "own" },
    });
    expect(refused.status).toBe(403);
    expect(await refused.json()).toMatchObject({ code: "NOT_TRUSTED_HERE" });
    expect(stranger.owner()).toBeNull();
  });
});
