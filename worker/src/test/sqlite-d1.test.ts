import { describe, expect, it } from "vitest";

import { createTestDb } from "./sqlite-d1";

describe("SQLite D1 stand-in", () => {
  it("starts with no tables", async () => {
    const { db } = createTestDb();
    const tables = await db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
      .all<{ name: string }>();
    expect(tables.results).toEqual([]);
  });

  it("binds numbered parameters the way D1 does, reused or not", async () => {
    const { db } = createTestDb();
    const row = await db
      .prepare("SELECT ?1 AS a, ?2 AS b, ?1 * 2 AS c")
      .bind(3, "x")
      .first<{ a: number; b: string; c: number }>();
    expect(row).toEqual({ a: 3, b: "x", c: 6 });
  });

  it("rolls a batch back when one statement fails, like D1", async () => {
    const { db, sqlite } = createTestDb();
    sqlite.exec("CREATE TABLE nodes (id TEXT PRIMARY KEY)");
    sqlite.exec("INSERT INTO nodes VALUES ('n1')");
    await expect(
      db.batch([
        db.prepare("DELETE FROM nodes WHERE id = ?").bind("n1"),
        db.prepare("INSERT INTO nowhere VALUES (1)"),
      ]),
    ).rejects.toThrow();
    expect(sqlite.prepare("SELECT COUNT(*) AS n FROM nodes").get()).toEqual({
      n: 1,
    });
  });
});
