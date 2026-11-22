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
      "devices",
      "enrollments",
      "node_trust",
      "nodes",
      "settings",
    ]);
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
