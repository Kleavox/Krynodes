import type { DatabaseSync } from "node:sqlite";
import type { ServiceEntry } from "@krynodes/protocol";
import { describe, expect, it } from "vitest";

import { seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";
import {
  applyInventory,
  requestRefresh,
  type InventoryNode,
} from "./inventory";

const NODE = "11111111-1111-4111-8111-111111111111";
const NOW = Date.parse("2026-09-29T10:00:00.000Z");
const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const SEEN = "2026-09-29 09:59:30";

const entry = (
  name: string,
  state: ServiceEntry["state"] = "running",
  kind: ServiceEntry["kind"] = "docker",
): ServiceEntry => ({ kind, name, state, since: null, system: false });

function setup() {
  const { db, sqlite } = createTestDb();
  seedNode(sqlite, { id: NODE });
  sqlite
    .prepare(
      "UPDATE nodes SET agent_version = '0.6.0', last_seen_at = ? WHERE id = ?",
    )
    .run(SEEN, NODE);
  const node = () =>
    sqlite
      .prepare(
        "SELECT id, inventory_hash, refresh_requested_at, inventory_at FROM nodes WHERE id = ?",
      )
      .get(NODE) as unknown as InventoryNode & { inventory_at: string | null };
  const rows = () =>
    sqlite
      .prepare(
        "SELECT kind, name, state, updated_at FROM services WHERE node_id = ? ORDER BY name",
      )
      .all(NODE);
  return { db, sqlite, node, rows };
}

function recordStatements(sqlite: DatabaseSync): string[] {
  const statements: string[] = [];
  const prepare = sqlite.prepare.bind(sqlite);
  sqlite.prepare = ((sql: string) => {
    statements.push(sql);
    return prepare(sql);
  }) as typeof sqlite.prepare;
  return statements;
}

describe("applyInventory", () => {
  it("stores a new inventory and acknowledges its hash", async () => {
    const { db, node, rows } = setup();
    const stored = await applyInventory(
      db,
      node(),
      { hash: HASH_A, services: [entry("adguard"), entry("web", "stopped")] },
      NOW,
    );
    expect(stored).toBe(HASH_A);
    expect(node()).toMatchObject({
      inventory_hash: HASH_A,
      inventory_at: new Date(NOW).toISOString(),
    });
    expect(rows()).toEqual([
      expect.objectContaining({ name: "adguard", state: "running" }),
      expect.objectContaining({ name: "web", state: "stopped" }),
    ]);
  });

  it("writes only the rows that changed and deletes the ones that disappeared", async () => {
    const { db, node, rows } = setup();
    await applyInventory(
      db,
      node(),
      {
        hash: HASH_A,
        services: [entry("adguard"), entry("web"), entry("old")],
      },
      NOW,
    );
    const later = NOW + 60_000;
    await applyInventory(
      db,
      node(),
      { hash: HASH_B, services: [entry("adguard"), entry("web", "failed")] },
      later,
    );
    expect(rows()).toEqual([
      {
        kind: "docker",
        name: "adguard",
        state: "running",
        updated_at: new Date(NOW).toISOString(),
      },
      {
        kind: "docker",
        name: "web",
        state: "failed",
        updated_at: new Date(later).toISOString(),
      },
    ]);
  });

  it("writes nothing when the hash is unchanged", async () => {
    const { db, sqlite, node } = setup();
    await applyInventory(
      db,
      node(),
      { hash: HASH_A, services: [entry("adguard")] },
      NOW,
    );
    const statements = recordStatements(sqlite);
    const stored = await applyInventory(
      db,
      node(),
      { hash: HASH_A, services: [entry("adguard")] },
      NOW + 60_000,
    );
    expect(stored).toBe(HASH_A);
    expect(
      statements.filter((sql) => /^\s*(INSERT|UPDATE|DELETE)/iu.test(sql)),
    ).toEqual([]);
  });

  it("ends a refresh even when nothing changed", async () => {
    const { db, sqlite, node } = setup();
    await applyInventory(
      db,
      node(),
      { hash: HASH_A, services: [entry("adguard")] },
      NOW,
    );
    sqlite
      .prepare("UPDATE nodes SET refresh_requested_at = ? WHERE id = ?")
      .run(new Date(NOW + 1_000).toISOString(), NODE);
    await applyInventory(db, node(), { hash: HASH_A }, NOW + 5_000);
    expect(node()).toMatchObject({
      refresh_requested_at: null,
      inventory_at: new Date(NOW + 5_000).toISOString(),
    });
  });

  it("never stores a protected target an agent reports", async () => {
    const { db, node, rows } = setup();
    await applyInventory(
      db,
      node(),
      {
        hash: HASH_A,
        services: [
          entry("ssh.service", "running", "systemd"),
          entry("nginx.service", "running", "systemd"),
        ],
      },
      NOW,
    );
    expect(rows()).toEqual([
      expect.objectContaining({ name: "nginx.service" }),
    ]);
  });

  it("writes a large inventory in a handful of statements", async () => {
    const { db, sqlite, node, rows } = setup();
    const statements = recordStatements(sqlite);
    const many = Array.from({ length: 120 }, (_, index) => entry(`c${index}`));
    await applyInventory(db, node(), { hash: HASH_A, services: many }, NOW);
    await applyInventory(
      db,
      node(),
      { hash: HASH_B, services: many.slice(60) },
      NOW + 60_000,
    );
    expect(rows()).toHaveLength(60);
    expect(
      statements.filter((sql) => /^\s*(INSERT|UPDATE|DELETE)/iu.test(sql))
        .length,
    ).toBeLessThanOrEqual(6);
  });

  it("keeps the stored inventory when a new hash arrives without its services", async () => {
    const { db, node, rows } = setup();
    await applyInventory(
      db,
      node(),
      { hash: HASH_A, services: [entry("adguard")] },
      NOW,
    );
    expect(await applyInventory(db, node(), { hash: HASH_B }, NOW)).toBe(
      HASH_A,
    );
    expect(rows()).toHaveLength(1);
  });
});

describe("refresh and eligibility", () => {
  it("asks only the owner's reporting agents for a fresh inventory", async () => {
    const { db, sqlite } = setup();
    const OTHER = "22222222-2222-4222-8222-222222222222";
    const FOREIGN = "33333333-3333-4333-8333-333333333333";
    seedNode(sqlite, { id: OTHER });
    seedNode(sqlite, { id: FOREIGN, owner: "someone-else" });
    sqlite
      .prepare(
        "UPDATE nodes SET agent_version = '0.1.0', last_seen_at = ? WHERE id = ?",
      )
      .run(SEEN, OTHER);
    sqlite
      .prepare(
        "UPDATE nodes SET agent_version = '0.6.0', last_seen_at = ? WHERE id = ?",
      )
      .run(SEEN, FOREIGN);
    expect(await requestRefresh(db, "standalone", undefined, NOW)).toEqual(
      [NODE, OTHER].sort(),
    );
    const flagged = sqlite
      .prepare(
        "SELECT id FROM nodes WHERE refresh_requested_at IS NOT NULL ORDER BY id",
      )
      .all()
      .map((row) => (row as { id: string }).id);
    expect(flagged).toEqual([NODE, OTHER].sort());
    expect(await requestRefresh(db, "standalone", [OTHER], NOW)).toEqual([
      OTHER,
    ]);
  });

  it("asks a fleet of 60 servers in one statement", async () => {
    const { db, sqlite } = setup();
    for (let index = 0; index < 60; index++) {
      const id = `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`;
      seedNode(sqlite, { id });
      sqlite
        .prepare(
          "UPDATE nodes SET agent_version = '0.6.0', last_seen_at = ? WHERE id = ?",
        )
        .run(SEEN, id);
    }
    let statements = 0;
    const prepare = db.prepare.bind(db);
    db.prepare = ((sql: string) => {
      statements += 1;
      return prepare(sql);
    }) as typeof db.prepare;
    expect(await requestRefresh(db, "standalone", undefined, NOW)).toHaveLength(
      61,
    );
    expect(statements).toBeLessThanOrEqual(2);
    expect(
      sqlite
        .prepare(
          "SELECT COUNT(*) AS n FROM nodes WHERE refresh_requested_at IS NULL",
        )
        .get(),
    ).toEqual({ n: 0 });
  });

  it("still asks a server whose row is a few minutes old", async () => {
    const { db, sqlite } = setup();
    sqlite
      .prepare("UPDATE nodes SET last_seen_at = ? WHERE id = ?")
      .run("2026-09-29 09:56:00", NODE);
    expect(await requestRefresh(db, "standalone", undefined, NOW)).toEqual([
      NODE,
    ]);
  });

  it("does not ask a server that has stopped reporting", async () => {
    const { db, sqlite } = setup();
    sqlite
      .prepare("UPDATE nodes SET last_seen_at = ? WHERE id = ?")
      .run("2026-09-29 09:50:00", NODE);
    expect(await requestRefresh(db, "standalone", undefined, NOW)).toEqual([]);
    sqlite
      .prepare("UPDATE nodes SET last_seen_at = NULL WHERE id = ?")
      .run(NODE);
    expect(await requestRefresh(db, "standalone", undefined, NOW)).toEqual([]);
  });
});

describe("stacks and trust", () => {
  const stack = (project: string, running = 2) => ({
    project,
    directory: `/opt/${project}`,
    running,
    total: 2,
    compose: true,
    rollback: project === "listmonk",
  });
  const stacks = (sqlite: DatabaseSync) =>
    sqlite
      .prepare(
        "SELECT project, directory, running, total, compose, rollback FROM stacks WHERE node_id = ? ORDER BY project",
      )
      .all(NODE);

  it("stores stacks and removes the ones that left", async () => {
    const { db, sqlite, node } = setup();
    await applyInventory(
      db,
      node(),
      {
        hash: HASH_A,
        services: [],
        stacks: [stack("listmonk"), stack("shop")],
      },
      NOW,
    );
    expect(stacks(sqlite)).toEqual([
      {
        project: "listmonk",
        directory: "/opt/listmonk",
        running: 2,
        total: 2,
        compose: 1,
        rollback: 1,
      },
      {
        project: "shop",
        directory: "/opt/shop",
        running: 2,
        total: 2,
        compose: 1,
        rollback: 0,
      },
    ]);
    await applyInventory(
      db,
      node(),
      { hash: HASH_B, services: [], stacks: [stack("listmonk", 1)] },
      NOW + 1_000,
    );
    expect(stacks(sqlite)).toEqual([
      {
        project: "listmonk",
        directory: "/opt/listmonk",
        running: 1,
        total: 2,
        compose: 1,
        rollback: 1,
      },
    ]);
  });

  it("stores the trust report as the agent sends it", async () => {
    const { db, sqlite, node } = setup();
    const stored = () =>
      JSON.parse(
        (
          sqlite
            .prepare("SELECT trust_report FROM nodes WHERE id = ?")
            .get(NODE) as { trust_report: string }
        ).trust_report,
      ) as unknown;
    await applyInventory(
      db,
      node(),
      {
        hash: HASH_B,
        services: [],
        trust: {
          version: 3,
          core: ["0123456789abcdef"],
          access: [],
          passphrase: true,
        },
      },
      NOW,
    );
    expect(stored()).toEqual({
      version: 3,
      core: ["0123456789abcdef"],
      access: [],
      passphrase: true,
    });
  });

  it("leaves stacks and trust alone when the inventory omits them", async () => {
    const { db, sqlite, node } = setup();
    await applyInventory(
      db,
      node(),
      {
        hash: HASH_A,
        services: [],
        stacks: [stack("listmonk")],
        trust: {
          version: 1,
          core: ["0123456789abcdef"],
          access: ["0123456789abcdef"],
          passphrase: false,
        },
      },
      NOW,
    );
    await applyInventory(
      db,
      node(),
      { hash: HASH_B, services: [entry("adguard")] },
      NOW + 1_000,
    );
    expect(stacks(sqlite)).toHaveLength(1);
    expect(
      sqlite.prepare("SELECT trust_report FROM nodes WHERE id = ?").get(NODE),
    ).toEqual({
      trust_report: JSON.stringify({
        version: 1,
        core: ["0123456789abcdef"],
        access: ["0123456789abcdef"],
        passphrase: false,
      }),
    });
  });
});
