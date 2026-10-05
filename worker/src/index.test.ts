import { describe, expect, it, vi } from "vitest";

import worker, { runRetention } from "./index";
import type { Env } from "./env";
import { createTestDb } from "./test/sqlite-d1";

function retentionEnv() {
  const statements: string[] = [];
  const run = vi.fn(async () => ({ success: true }));
  const env = {
    DB: {
      prepare(sql: string) {
        statements.push(sql);
        return { run, bind: () => ({ run }) };
      },
    },
  } as unknown as Env;
  return { env, statements, run };
}

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

describe("Krynodes retention", () => {
  it("deletes expired history, incident and action records", async () => {
    const { env, statements, run } = retentionEnv();
    await runRetention(env);

    expect(run).toHaveBeenCalledTimes(7);
    expect(statements[0]).toContain("DELETE FROM node_windows");
    expect(statements.join("\n")).toContain("incidents");
    expect(statements[3]).toContain("FROM actions");
    expect(statements[3]).toContain("-90 days");
  });

  it("drops history windows older than eight days, by the primary key", async () => {
    const { db, sqlite } = createTestDb();
    sqlite.exec(
      "INSERT INTO nodes (id, owner_user_id, name, agent_token_hash) VALUES ('n1', 'standalone', 'pivox', 'h1')",
    );
    const day = 86_400_000;
    for (const age of [9 * day, 7 * day, 60_000]) {
      sqlite
        .prepare(
          "INSERT INTO node_windows (node_id, window_start) VALUES ('n1', ?)",
        )
        .run(new Date(Date.now() - age).toISOString());
    }
    await runRetention({ DB: db } as unknown as Env);
    expect(
      sqlite.prepare("SELECT COUNT(*) AS n FROM node_windows").get(),
    ).toEqual({ n: 2 });
  });

  it("forgets enrollment tokens a day after they expire", async () => {
    const { db, sqlite } = createTestDb();
    const insert = sqlite.prepare(
      `INSERT INTO enrollment_tokens (id, owner_user_id, token_hash, expires_at)
       VALUES (?, 'standalone', ?, ?)`,
    );
    insert.run(
      "stale",
      "hash-stale",
      new Date(Date.now() - 2 * 86_400_000).toISOString(),
    );
    insert.run(
      "fresh",
      "hash-fresh",
      new Date(Date.now() + 60_000).toISOString(),
    );

    await runRetention({ DB: db } as unknown as Env);

    expect(sqlite.prepare("SELECT id FROM enrollment_tokens").all()).toEqual([
      { id: "fresh" },
    ]);
  });

  it("erases log text a day after it arrives and keeps the row", async () => {
    const { db, sqlite } = createTestDb();
    sqlite.exec(
      "INSERT INTO nodes (id, owner_user_id, name, agent_token_hash) VALUES ('n1', 'standalone', 'pivox', 'h1')",
    );
    const at = (age: number) => new Date(Date.now() - age).toISOString();
    const insert = sqlite.prepare(
      `INSERT INTO actions (id, batch_id, position, mode, node_id, kind, name, action,
         status, requested_by, requested_at, finished_at, output)
       VALUES (?, ?, 0, 'parallel', 'n1', 'docker', 'adguard', ?, ?, 'owner', ?, ?, 'text')`,
    );
    insert.run("old-logs", "b1", "logs", "done", at(2 * DAY), at(2 * DAY));
    insert.run("new-logs", "b2", "logs", "done", at(HOUR), at(HOUR));
    insert.run("waiting-logs", "b3", "logs", "sent", at(2 * DAY), null);
    insert.run(
      "old-restart",
      "b4",
      "restart",
      "done",
      at(2 * DAY),
      at(2 * DAY),
    );

    await runRetention({ DB: db } as unknown as Env);

    expect(
      sqlite.prepare("SELECT id, output FROM actions ORDER BY id").all(),
    ).toEqual([
      { id: "new-logs", output: "text" },
      { id: "old-logs", output: null },
      { id: "old-restart", output: "text" },
      { id: "waiting-logs", output: "text" },
    ]);
  });

  it("forgets closed trust changes and removed devices after a year", async () => {
    const { db, sqlite } = createTestDb();
    const at = (age: number) => new Date(Date.now() - age).toISOString();
    const proposal = sqlite.prepare(
      `INSERT INTO proposals (id, owner_user_id, change, title, version, approvals, status, opened_by, opened_at, expires_at, closed_at)
       VALUES (?, 'standalone', 'e30', 'Admit Phone', 2, '[]', ?, 'd1', ?, ?, ?)`,
    );
    proposal.run("old", "applied", at(400 * DAY), at(400 * DAY), at(400 * DAY));
    proposal.run(
      "recent",
      "expired",
      at(100 * DAY),
      at(100 * DAY),
      at(100 * DAY),
    );
    proposal.run("open", "open", at(400 * DAY), at(-DAY), null);
    const device = sqlite.prepare(
      `INSERT INTO devices (id, owner_user_id, name, alg, public_key, created_at, removed_at)
       VALUES (?, 'standalone', ?, -7, ?, ?, ?)`,
    );
    device.run("gone", "Old phone", "k1", at(500 * DAY), at(400 * DAY));
    device.run("left", "Tablet", "k2", at(50 * DAY), at(10 * DAY));
    device.run("here", "Laptop", "k3", at(500 * DAY), null);

    await runRetention({ DB: db } as unknown as Env);

    expect(
      sqlite.prepare("SELECT id FROM proposals ORDER BY id").all(),
    ).toEqual([{ id: "open" }, { id: "recent" }]);
    expect(sqlite.prepare("SELECT id FROM devices ORDER BY id").all()).toEqual([
      { id: "here" },
      { id: "left" },
    ]);
  });

  it("runs retention, the agent release check and the token reminder from the cron", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("down", { status: 503 })),
    );
    const { db } = createTestDb();
    const pending: Promise<unknown>[] = [];
    worker.scheduled(
      {} as ScheduledController,
      { DB: db } as unknown as Env,
      {
        waitUntil: (promise: Promise<unknown>) => pending.push(promise),
      } as unknown as ExecutionContext,
    );
    expect(pending).toHaveLength(3);
    await Promise.all(pending);
    vi.unstubAllGlobals();
  });
});
