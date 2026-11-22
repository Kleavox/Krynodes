import { DatabaseSync, type SQLInputValue } from "node:sqlite";

interface TestDb {
  db: D1Database;
  sqlite: DatabaseSync;
}

function positional(
  sql: string,
  params: SQLInputValue[],
): [string, SQLInputValue[]] {
  const ordered: SQLInputValue[] = [];
  const text = sql.replace(/\?(\d+)/gu, (_, index: string) => {
    ordered.push(params[Number(index) - 1] ?? null);
    return "?";
  });
  return ordered.length > 0 ? [text, ordered] : [sql, params];
}

export function createTestDb(): TestDb {
  const sqlite = new DatabaseSync(":memory:");
  sqlite.exec("PRAGMA foreign_keys = ON");

  const size = () => {
    const pages = sqlite.prepare("PRAGMA page_count").get() as {
      page_count: number;
    };
    const page = sqlite.prepare("PRAGMA page_size").get() as {
      page_size: number;
    };
    return pages.page_count * page.page_size;
  };

  const statement = (source: string, values: SQLInputValue[] = []) => {
    const [sql, params] = positional(source, values);
    return {
      bind: (...next: SQLInputValue[]) => statement(source, next),
      all: async () => ({
        results: sqlite.prepare(sql).all(...params),
        success: true,
        meta: { size_after: size() },
      }),
      first: async (column?: string) => {
        const row = sqlite.prepare(sql).get(...params) as
          Record<string, unknown> | undefined;
        if (!row) return null;
        return column ? row[column] : row;
      },
      run: async () => {
        const result = sqlite.prepare(sql).run(...params);
        return { success: true, meta: { changes: Number(result.changes) } };
      },
    };
  };

  let pending: Promise<unknown> = Promise.resolve();
  const db = {
    prepare: (sql: string) => statement(sql),
    batch: (statements: { run: () => Promise<unknown> }[]) => {
      const next = pending.then(async () => {
        const results: unknown[] = [];
        sqlite.exec("BEGIN");
        try {
          for (const item of statements) results.push(await item.run());
        } catch (error) {
          sqlite.exec("ROLLBACK");
          throw error;
        }
        sqlite.exec("COMMIT");
        return results;
      });
      pending = next.catch(() => undefined);
      return next;
    },
  };

  return { db: db as unknown as D1Database, sqlite };
}
