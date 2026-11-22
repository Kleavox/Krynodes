import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { createTestDb } from "./sqlite-d1";

const INIT = fileURLToPath(
  new URL("../../migrations/0001_init.sql", import.meta.url),
);

export function freshDb(): D1Database {
  const { db, sqlite } = createTestDb();
  sqlite.exec(readFileSync(INIT, "utf8"));
  return db;
}
