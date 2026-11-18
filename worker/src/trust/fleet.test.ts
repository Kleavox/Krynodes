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

describe("a laptop's report", () => {
  it("writes its trust report alone and mails nothing", async () => {
    const t = await world();
    const mail: unknown[] = [];
    const harness = hubHarness({
      DB: t.db,
      ALERT_EMAIL: "user1@example.com",
      FROM_EMAIL: "kry@example.test",
      EMAIL: { send: async (message: unknown) => mail.push(message) },
    } as never);
    t.sqlite
      .prepare("UPDATE nodes SET kind = 'laptop', seal_key = ? WHERE id = ?")
      .run(SEAL_REAL, V3);
    const now = "2026-11-16T10:00:00.000Z";
    const inventory = (hash: string) => ({
      hash,
      docker: "ready",
      sealKey: SEAL_OTHER,
      leftovers: ["old"],
      removed: [{ project: "web", directory: "/srv/web", removedAt: now }],
      services: [
        {
          kind: "systemd",
          name: "nginx.service",
          state: "running",
          since: null,
          system: true,
        },
      ],
      packages: { apt: false, system: "Windows 11" },
      security: {
        checkedAt: now,
        findings: [{ id: "ssh-password", severity: "serious", detail: "d" }],
        recipes: [],
        lockdown: false,
        rebootHour: null,
      },
      trust: t.trust([t.fpA]),
    });
    const laptop = await harness.connect(V3, OWNER, 60, true);
    const setup = await harness.request(laptop, "setup", {
      setup: { phase: "admin", step: 1, of: 3 },
    });
    expect(setup).toMatchObject({ type: "error", code: "INVALID_MESSAGE" });
    const answer = await harness.request(laptop, "actions", {
      report: { nodeId: V3, inventory: inventory(HASH_1) },
    });
    expect(answer).toMatchObject({
      type: "actions",
      response: { ok: true, inventoryHash: HASH_1 },
    });
    const row = (id: string) =>
      t.sqlite
        .prepare(
          `SELECT setup, seal_key, security, docker, inventory_hash, trust_report,
             (SELECT COUNT(*) FROM services WHERE node_id = nodes.id) AS services,
             (SELECT COUNT(*) FROM removed_stacks WHERE node_id = nodes.id) AS removed,
             (SELECT COUNT(*) FROM packages WHERE node_id = nodes.id) AS packages
           FROM nodes WHERE id = ?`,
        )
        .get(id) as Record<string, unknown>;
    expect(row(V3)).toEqual({
      setup: null,
      seal_key: SEAL_REAL,
      security: null,
      docker: null,
      inventory_hash: null,
      trust_report: JSON.stringify(t.trust([t.fpA])),
      services: 0,
      removed: 0,
      packages: 0,
    });
    expect(mail).toEqual([]);
    expect((await loadFleet(t.db, OWNER)).core).toEqual([]);
    const server = await harness.connect(V1, OWNER);
    await harness.request(server, "actions", {
      report: { nodeId: V1, inventory: inventory(HASH_2) },
    });
    expect(row(V1)).toMatchObject({ services: 1, packages: 1 });
    expect(mail).toHaveLength(1);
  });
});

describe("a laptop in the fleet", () => {
  it("is a target of passkey changes only while it is a member that has not left", async () => {
    const t = await world();
    t.sqlite.prepare("UPDATE nodes SET kind = 'laptop' WHERE id = ?").run(V3);
    const listed = async () =>
      (await loadFleet(t.db, OWNER)).nodes.map((node) => node.id);
    expect(await listed()).toEqual(expect.arrayContaining([V1, V2, V3]));
    for (const state of ["waiting", "leaving"]) {
      t.sqlite
        .prepare("UPDATE network_members SET state = ? WHERE node_id = ?")
        .run(state, V3);
      const nodes = await listed();
      expect(nodes, state).toEqual(expect.arrayContaining([V1, V2]));
      expect(nodes, state).not.toContain(V3);
    }
    t.sqlite
      .prepare("UPDATE network_members SET state = 'in' WHERE node_id = ?")
      .run(V3);
    expect(await listed()).toContain(V3);
    t.sqlite.prepare("DELETE FROM network_members WHERE node_id = ?").run(V3);
    expect(await listed()).not.toContain(V3);
  });
});

describe("a retired laptop", () => {
  it("is closed out of its open connection at its next message", async () => {
    const t = await world();
    t.sqlite.prepare("UPDATE nodes SET kind = 'laptop' WHERE id = ?").run(V3);
    const harness = hubHarness({
      DB: t.db,
      EMAIL: { send: vi.fn() },
    } as never);
    const ws = await harness.connect(V3, OWNER, 60, true);
    t.sqlite
      .prepare(
        "UPDATE nodes SET disabled_at = datetime('now'), agent_token_hash = 'retired-' || id WHERE id = ?",
      )
      .run(V3);
    await harness.request(ws, "actions", {
      report: { nodeId: V3, inventory: { hash: HASH_1, services: [] } },
    });
    expect(ws.closed).toEqual({
      code: 4401,
      reason: "Unknown or disabled server",
    });
  });
});
