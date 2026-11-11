import { describe, expect, it, vi } from "vitest";

import { fingerprint } from "../lib/webauthn";
import { hubHarness } from "../test/hub";
import { seedFleet, V1, V2, V3 } from "../test/fleet";
import { OWNER } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";
import { loadFleet } from "./fleet";
import { confirmed } from "./intent";

const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const KEY_A = b64url(
  Uint8Array.from({ length: 65 }, (_, i) => (i === 0 ? 4 : 1)),
);
const KEY_B = b64url(
  Uint8Array.from({ length: 65 }, (_, i) => (i === 0 ? 4 : 2)),
);
const HASH_1 = "1".repeat(64);
const HASH_2 = "2".repeat(64);
const SEAL_REAL = "A".repeat(87);

async function world() {
  const { db, sqlite } = createTestDb();
  seedFleet(sqlite);
  const fpA = await fingerprint(KEY_A);
  const fpB = await fingerprint(KEY_B);
  for (const [id, key] of [
    ["dev-A", KEY_A],
    ["dev-B", KEY_B],
  ] as const) {
    sqlite
      .prepare(
        `INSERT INTO devices (id, owner_user_id, name, alg, public_key, created_at)
         VALUES (?, ?, ?, -7, ?, '2026-09-01 00:00:00')`,
      )
      .run(id, OWNER, id, key);
  }
  const harness = hubHarness({ DB: db, EMAIL: { send: vi.fn() } } as never);
  const trust = (core: string[]) => ({
    version: 1,
    core,
    access: [],
    passphrase: false,
  });
  const report = async (node: string, inventory: Record<string, unknown>) => {
    const ws = await harness.connect(node);
    return harness.request(ws, "actions", {
      report: { nodeId: node, inventory: { services: [], ...inventory } },
    });
  };
  const quarantineNode = (node: string) =>
    sqlite
      .prepare(
        `INSERT INTO quarantines (id, node_id, why, at, timeline) VALUES (?, ?, 'test', 'now', '[]')`,
      )
      .run(`q-${node}`, node);
  return { db, sqlite, fpA, fpB, report, trust, quarantineNode };
}

const SEAL_OTHER = "B".repeat(87);

const ask = (db: D1Database) =>
  confirmed(
    {
      get: () => ({ id: OWNER, email: "op@example.test" }),
      env: { DB: db, PUBLIC_ORIGIN: "https://kry.example.test" },
      req: { header: () => undefined },
      json: (body: unknown, status: number) =>
        new Response(JSON.stringify(body), { status }),
    } as never,
    "node.delete",
    V3,
  );

describe("the trusted passkeys the Worker reads from server reports", () => {
  it("ignore a quarantined server's report and never name a removed passkey", async () => {
    const t = await world();
    await t.report(V1, { hash: HASH_1, trust: t.trust([t.fpA]) });
    expect((await loadFleet(t.db, OWNER)).core).toEqual(["dev-A"]);
    t.quarantineNode(V2);
    await t.report(V2, { hash: HASH_1, trust: t.trust([t.fpA, t.fpB]) });
    expect((await loadFleet(t.db, OWNER)).core).toEqual(["dev-A"]);
    t.sqlite.exec(
      "UPDATE devices SET removed_at = '2026-09-02' WHERE id = 'dev-B'",
    );
    await t.report(V3, { hash: HASH_1, trust: t.trust([t.fpA, t.fpB]) });
    expect((await loadFleet(t.db, OWNER)).core).toEqual(["dev-A"]);
  });

  it("still ask for a passkey that was used before when every report turns empty", async () => {
    const t = await world();
    t.sqlite.exec(
      "UPDATE devices SET verifies = 1, last_used_at = '2026-09-03' WHERE id = 'dev-A'",
    );
    await t.report(V1, { hash: HASH_1, trust: t.trust([t.fpA]) });
    expect((await ask(t.db))?.status).toBe(403);
    await t.report(V1, { hash: HASH_2, trust: t.trust([]) });
    const fleet = await loadFleet(t.db, OWNER);
    expect(fleet.core).toEqual([]);
    expect(fleet.proof).toEqual(["dev-A"]);
    expect((await ask(t.db))?.status).toBe(403);
  });
});

describe("a server's seal key", () => {
  it("is not replaced by a report from a quarantined server", async () => {
    const t = await world();
    await t.report(V1, { hash: HASH_1, sealKey: SEAL_REAL });
    const read = () =>
      (
        t.sqlite.prepare("SELECT seal_key FROM nodes WHERE id = ?").get(V1) as {
          seal_key: string;
        }
      ).seal_key;
    t.quarantineNode(V1);
    await t.report(V1, { hash: HASH_2, sealKey: SEAL_OTHER });
    expect(read()).toBe(SEAL_REAL);
  });
});
