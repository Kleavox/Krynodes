import { describe, expect, it } from "vitest";

import { freshDb } from "./test/db";

async function addNode(db: D1Database, id: string, name: string) {
  await db
    .prepare(
      "INSERT INTO nodes (id, name, agent_token_hash, enrolled_at) VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(id, name, `hash-${id}`, "2026-11-22T00:00:00.000Z")
    .run();
}

async function addAction(
  db: D1Database,
  id: string,
  nodeId: string,
  status = "sent",
) {
  await db
    .prepare(
      "INSERT INTO actions (id, node_id, kind, name, action, title, status, created_at) VALUES (?1, ?2, 'service', 'nginx', 'restart', 'Restart nginx', ?3, ?4)",
    )
    .bind(id, nodeId, status, "2026-11-22T00:00:00.000Z")
    .run();
}

async function count(db: D1Database, table: string, nodeId: string) {
  const row = await db
    .prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE node_id = ?1`)
    .bind(nodeId)
    .first<{ n: number }>();
  return row?.n;
}

describe("0001_init", () => {
  it("applies to a fresh database and creates every table and the actions index", async () => {
    const db = freshDb();
    const names = await db
      .prepare(
        "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
      )
      .all<{ name: string }>();
    expect(names.results.map((row) => row.name)).toEqual([
      "actions",
      "actions_node_created",
      "agent_release",
      "check_transitions",
      "check_transitions_check_at",
      "checks",
      "devices",
      "enrollments",
      "network",
      "network_addresses",
      "network_blocked",
      "network_changes",
      "network_changes_at",
      "network_documents",
      "network_links",
      "network_members",
      "node_inventory",
      "node_trust",
      "nodes",
      "settings",
    ]);
  });

  it("0002_seen adds a nullable seen_ip to nodes", async () => {
    const db = freshDb();
    await addNode(db, "n1", "server-1");
    expect(
      await db
        .prepare("SELECT seen_ip FROM nodes WHERE id = 'n1'")
        .first("seen_ip"),
    ).toBeNull();
    await db.prepare("UPDATE nodes SET seen_ip = '203.0.113.9'").run();
    expect(await db.prepare("SELECT seen_ip FROM nodes").first("seen_ip")).toBe(
      "203.0.113.9",
    );
  });

  it("deleting a node removes its trust and its actions", async () => {
    const db = freshDb();
    await addNode(db, "n1", "server-1");
    await addNode(db, "n2", "server-2");
    for (const id of ["n1", "n2"]) {
      await db
        .prepare(
          "INSERT INTO node_trust (node_id, version, core, access, reported_at) VALUES (?1, 1, '[]', '[]', ?2)",
        )
        .bind(id, "2026-11-22T00:00:00.000Z")
        .run();
      await addAction(db, `a-${id}`, id);
    }
    await db.prepare("DELETE FROM nodes WHERE id = ?1").bind("n1").run();
    expect(await count(db, "node_trust", "n1")).toBe(0);
    expect(await count(db, "actions", "n1")).toBe(0);
    expect(await count(db, "node_trust", "n2")).toBe(1);
    expect(await count(db, "actions", "n2")).toBe(1);
  });

  it("deleting a node removes its member, link and address rows", async () => {
    const db = freshDb();
    await addNode(db, "n1", "server-1");
    await addNode(db, "n2", "server-2");
    const at = "2026-11-22T00:00:00.000Z";
    for (const [id, address] of [
      ["n1", "10.88.37.1"],
      ["n2", "10.88.37.2"],
    ] as const) {
      await db
        .prepare(
          "INSERT INTO network_members (node_id, state, key, signer, since) VALUES (?1, 'in', ?2, ?2, ?3)",
        )
        .bind(id, `key-${id}`, at)
        .run();
      await db
        .prepare(
          "INSERT INTO network_addresses (address, node_id) VALUES (?1, ?2)",
        )
        .bind(address, id)
        .run();
    }
    await db
      .prepare(
        "INSERT INTO network_links (a, b, answering, ms, since) VALUES ('n1', 'n2', 1, 4.5, ?1)",
      )
      .bind(at)
      .run();
    await db
      .prepare(
        "INSERT INTO network_blocked (key, node_id, at) VALUES ('key-old', 'n1', ?1)",
      )
      .bind(at)
      .run();
    await db.prepare("DELETE FROM nodes WHERE id = ?1").bind("n1").run();
    expect(await count(db, "network_members", "n1")).toBe(0);
    expect(await count(db, "network_addresses", "n1")).toBe(0);
    expect(await count(db, "network_members", "n2")).toBe(1);
    expect(await count(db, "network_addresses", "n2")).toBe(1);
    expect(
      await db.prepare("SELECT COUNT(*) AS n FROM network_links").first("n"),
    ).toBe(0);
    expect(
      await db.prepare("SELECT key, node_id FROM network_blocked").first(),
    ).toEqual({ key: "key-old", node_id: null });
  });

  it("refuses a second node with the same name", async () => {
    const db = freshDb();
    await addNode(db, "n1", "server-1");
    await expect(addNode(db, "n2", "server-1")).rejects.toThrow(/UNIQUE/u);
  });

  it("refuses an action for a node that does not exist", async () => {
    const db = freshDb();
    await expect(addAction(db, "a1", "ghost")).rejects.toThrow(/FOREIGN KEY/u);
  });

  it("refuses an unknown action status", async () => {
    const db = freshDb();
    await addNode(db, "n1", "server-1");
    await addAction(db, "a1", "n1", "failed");
    await expect(addAction(db, "a2", "n1", "queued")).rejects.toThrow(/CHECK/u);
  });

  it("refuses invalid JSON in an enrollment's trust", async () => {
    const db = freshDb();
    await expect(
      db
        .prepare(
          "INSERT INTO enrollments (id, token_hash, name, trust, created_at, expires_at) VALUES ('e1', 'h1', 'server-1', 'not json', ?1, ?1)",
        )
        .bind("2026-11-22T00:00:00.000Z")
        .run(),
    ).rejects.toThrow(/CHECK/u);
  });

  it("keeps agent_release to its one row", async () => {
    const db = freshDb();
    await db
      .prepare(
        "INSERT INTO agent_release (id, version, checked_at) VALUES (1, '0.7.90', ?1)",
      )
      .bind("2026-11-22T00:00:00.000Z")
      .run();
    await expect(
      db
        .prepare(
          "INSERT INTO agent_release (id, version, checked_at) VALUES (2, '0.7.91', ?1)",
        )
        .bind("2026-11-22T00:00:00.000Z")
        .run(),
    ).rejects.toThrow(/CHECK/u);
  });
});
