import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { createTestDb } from "./sqlite-d1";

const MIGRATIONS = fileURLToPath(new URL("../../migrations/", import.meta.url));

export function freshDb(): D1Database {
  const { db, sqlite } = createTestDb();
  for (const file of readdirSync(MIGRATIONS).sort()) {
    sqlite.exec(readFileSync(`${MIGRATIONS}${file}`, "utf8"));
  }
  return db;
}
