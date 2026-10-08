import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const MIGRATIONS = fileURLToPath(new URL("../migrations", import.meta.url));
const FILES = readdirSync(MIGRATIONS)
  .filter((name) => name.endsWith(".sql"))
  .sort();

function apply(sqlite: DatabaseSync, pick: (name: string) => boolean) {
  for (const name of FILES.filter(pick)) {
    sqlite.exec(readFileSync(join(MIGRATIONS, name), "utf8"));
  }
}

const action = (
  id: string,
  kind: string,
  name: string,
  verb: string,
  status: string,
  signed: string | null = null,
) =>
  `INSERT INTO actions (id, batch_id, position, mode, node_id, kind, name, action,
     status, requested_by, requested_at, deliverable_at${signed === null ? "" : ", signed"})
   VALUES ('${id}', 'b-${id}', 0, 'rolling', 'n1', '${kind}', '${name}', '${verb}',
     '${status}', 'owner', '2026-09-29T10:00:00.000Z', '2026-09-29T10:00:00.000Z'${signed === null ? "" : `, '${signed}'`})`;

function before0014() {
  const sqlite = new DatabaseSync(":memory:");
  sqlite.exec("PRAGMA foreign_keys = ON");
  apply(sqlite, (name) => name < "0014");
  sqlite.exec(
    "INSERT INTO nodes (id, owner_user_id, name, agent_token_hash) VALUES ('n1', 'standalone', 'pivox', 'h1')",
  );
  sqlite.exec(action("a1", "docker", "adguard", "restart", "done"));
  sqlite.exec(action("a2", "systemd", "nginx.service", "stop", "queued"));
  return sqlite;
}

describe("migration 0014", () => {
  it("keeps 4a actions and every index", () => {
    const sqlite = before0014();
    apply(sqlite, (name) => name.startsWith("0014"));
    expect(
      sqlite
        .prepare(
          "SELECT id, kind, action, status, signed FROM actions ORDER BY id",
        )
        .all(),
    ).toEqual([
      {
        id: "a1",
        kind: "docker",
        action: "restart",
        status: "done",
        signed: null,
      },
      {
        id: "a2",
        kind: "systemd",
        action: "stop",
        status: "queued",
        signed: null,
      },
    ]);
    expect(
      sqlite
        .prepare(
          "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'actions' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .all()
        .map((row) => (row as { name: string }).name),
    ).toEqual([
      "idx_actions_batch",
      "idx_actions_node_requested",
      "idx_actions_one_pending",
      "idx_actions_status_node",
    ]);
    expect(() =>
      sqlite.exec(action("a3", "systemd", "nginx.service", "start", "queued")),
    ).toThrow(/UNIQUE/u);
  });

  it("accepts compose deploys, rollbacks and trust changes, and nothing else", () => {
    const sqlite = before0014();
    apply(sqlite, (name) => name.startsWith("0014"));
    sqlite.exec(action("c1", "compose", "listmonk", "deploy", "done", "{}"));
    sqlite.exec(
      action("c2", "compose", "listmonk", "rollback", "queued", "{}"),
    );
    sqlite.exec(action("t1", "trust", "devices", "trust", "queued", "{}"));
    expect(() =>
      sqlite.exec(action("x1", "kubernetes", "web", "deploy", "queued")),
    ).toThrow(/CHECK/u);
    expect(() =>
      sqlite.exec(action("x2", "compose", "shop", "exec", "queued")),
    ).toThrow(/CHECK/u);
  });

  it("adds devices, stacks and the node's trust", () => {
    const sqlite = before0014();
    apply(sqlite, (name) => name.startsWith("0014"));
    sqlite.exec(
      "INSERT INTO devices (id, owner_user_id, name, alg, public_key, created_at) VALUES ('d1', 'standalone', 'Laptop', -7, 'MFkw', '2026-09-29T10:00:00.000Z')",
    );
    expect(() =>
      sqlite.exec(
        "INSERT INTO devices (id, owner_user_id, name, alg, public_key, created_at) VALUES ('d2', 'standalone', 'Old', -8, 'MFkw', '2026-09-29T10:00:00.000Z')",
      ),
    ).toThrow(/CHECK/u);
    sqlite.exec(
      "INSERT INTO stacks (node_id, project, directory, running, total, compose, rollback, updated_at) VALUES ('n1', 'listmonk', '/opt/listmonk', 5, 5, 1, 0, '2026-09-29T10:00:00.000Z')",
    );
    sqlite.exec(
      "UPDATE nodes SET trust_version = 1, trust_keys = '[\"0123456789abcdef\"]' WHERE id = 'n1'",
    );
    sqlite.exec("DELETE FROM nodes WHERE id = 'n1'");
    expect(sqlite.prepare("SELECT COUNT(*) AS n FROM stacks").get()).toEqual({
      n: 0,
    });
  });
});

describe("migration 0015", () => {
  it("keeps every action and index and accepts a server restart", () => {
    const sqlite = before0014();
    apply(sqlite, (name) => name >= "0014" && name < "0015");
    sqlite.exec(action("c1", "compose", "listmonk", "deploy", "done", "{}"));
    apply(sqlite, (name) => name.startsWith("0015"));
    expect(
      sqlite.prepare("SELECT id, kind, signed FROM actions ORDER BY id").all(),
    ).toEqual([
      { id: "a1", kind: "docker", signed: null },
      { id: "a2", kind: "systemd", signed: null },
      { id: "c1", kind: "compose", signed: "{}" },
    ]);
    sqlite.exec(action("h1", "host", "server", "reboot", "queued", "{}"));
    expect(() =>
      sqlite.exec(action("h2", "host", "server", "exec", "queued", "{}")),
    ).toThrow();
    expect(
      sqlite
        .prepare(
          "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'actions' AND name LIKE 'idx_%' ORDER BY name",
        )
        .all()
        .map((row) => (row as { name: string }).name),
    ).toEqual([
      "idx_actions_batch",
      "idx_actions_node_requested",
      "idx_actions_one_pending",
      "idx_actions_status_node",
    ]);
  });
});

describe("migration 0016", () => {
  it("moves each node's trust into one report and adds proposals and the passphrase", () => {
    const sqlite = before0014();
    apply(sqlite, (name) => name >= "0014" && name < "0016");
    sqlite.exec(
      "UPDATE nodes SET trust_version = 3, trust_keys = '[\"0123456789abcdef\"]' WHERE id = 'n1'",
    );
    apply(sqlite, (name) => name.startsWith("0016"));
    expect(
      JSON.parse(
        (
          sqlite
            .prepare("SELECT trust_report FROM nodes WHERE id = 'n1'")
            .get() as {
            trust_report: string;
          }
        ).trust_report,
      ),
    ).toEqual({
      version: 3,
      core: ["0123456789abcdef"],
      access: ["0123456789abcdef"],
      passphrase: false,
    });
    sqlite.exec(
      "INSERT INTO devices (id, owner_user_id, name, alg, public_key, created_at, verifies) VALUES ('d1', 'standalone', 'Laptop', -7, 'MFkw', '2026-09-30T10:00:00.000Z', 0)",
    );
    sqlite.exec(
      "INSERT INTO proposals (id, owner_user_id, change, version, approvals, status, opened_by, opened_at, expires_at) VALUES ('p1', 'standalone', 'Y2hhbmdl', 4, '[]', 'open', 'd1', '2026-09-30T10:00:00.000Z', '2026-10-01T10:00:00.000Z')",
    );
    expect(() =>
      sqlite.exec(
        "INSERT INTO proposals (id, owner_user_id, change, version, approvals, status, opened_by, opened_at, expires_at) VALUES ('p2', 'standalone', 'Y2hhbmdl', 4, '[]', 'maybe', 'd1', '2026-09-30T10:00:00.000Z', '2026-10-01T10:00:00.000Z')",
      ),
    ).toThrow(/CHECK/u);
    sqlite.exec(
      "INSERT INTO passphrase (owner_user_id, salt, iterations, public_key, set_at) VALUES ('standalone', 'c2FsdA', 600000, 'cHVi', '2026-09-30T10:00:00.000Z')",
    );
    sqlite.exec(action("a3", "docker", "adguard", "restart", "queued", "{}"));
    sqlite.exec("UPDATE actions SET device_id = 'd1' WHERE id = 'a3'");
    const columns = sqlite
      .prepare("SELECT name FROM pragma_table_info('nodes')")
      .all()
      .map((row) => (row as { name: string }).name);
    expect(columns).not.toContain("trust_version");
    expect(columns).not.toContain("trust_keys");
  });
});

describe("migration 0017", () => {
  it("folds metrics and check results into one row per server per five minutes", () => {
    const sqlite = before0014();
    apply(sqlite, (name) => name >= "0014" && name < "0017");
    sqlite.exec(
      "INSERT INTO checks (id, node_id, name, kind, target) VALUES ('c1', 'n1', 'Web', 'HTTP', 'https://example.com'), ('c2', 'n1', 'DB', 'TCP', 'db:5432')",
    );
    sqlite.exec(
      `INSERT INTO node_metrics (node_id, cpu_percent, memory_used_bytes, memory_total_bytes, disk_used_bytes, disk_total_bytes, load_1, load_5, load_15, uptime_seconds, recorded_at) VALUES
       ('n1', 10, 4, 8, 1, 2, 0.1, 0.2, 0.3, 100, '2026-10-01 08:00:10'),
       ('n1', 30, 6, 8, 1, 2, 0.3, 0.2, 0.3, 160, '2026-10-01 08:01:10'),
       ('n1', 50, 4, 8, 1, 2, 0.5, 0.2, 0.3, 400, '2026-10-01 08:05:10')`,
    );
    sqlite.exec(
      `INSERT INTO check_results (check_id, status, latency_ms, message, checked_at) VALUES
       ('c1', 'UP', 40, NULL, '2026-10-01T08:00:10.000Z'),
       ('c2', 'DOWN', NULL, 'refused', '2026-10-01T08:00:10.000Z'),
       ('c1', 'UP', 42, NULL, '2026-10-01T08:10:10.000Z')`,
    );
    apply(sqlite, (name) => name.startsWith("0017"));
    const rows = sqlite
      .prepare(
        "SELECT node_id, window_start, samples, cpu_percent, uptime_seconds, checks FROM node_windows ORDER BY window_start",
      )
      .all() as {
      window_start: string;
      samples: number;
      cpu_percent: number | null;
      uptime_seconds: number | null;
      checks: string;
    }[];
    expect(rows.map((row) => row.window_start)).toEqual([
      "2026-10-01T08:00:00.000Z",
      "2026-10-01T08:05:00.000Z",
      "2026-10-01T08:10:00.000Z",
    ]);
    expect(rows[0]).toMatchObject({
      samples: 2,
      cpu_percent: 20,
      uptime_seconds: 160,
    });
    expect(JSON.parse(rows[0]!.checks)).toEqual({
      c1: ["UP", 40],
      c2: ["DOWN", null, "refused"],
    });
    expect(rows[1]).toMatchObject({ samples: 1, checks: "{}" });
    expect(rows[2]).toMatchObject({ samples: 0, cpu_percent: null });
    expect(JSON.parse(rows[2]!.checks)).toEqual({ c1: ["UP", 42] });
    const tables = sqlite
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
      .all()
      .map((row) => (row as { name: string }).name);
    expect(tables).not.toContain("node_metrics");
    expect(tables).not.toContain("check_results");
    expect(
      sqlite.prepare("SELECT transport FROM nodes WHERE id = 'n1'").get(),
    ).toEqual({ transport: "http" });
    expect(
      sqlite
        .prepare(
          "SELECT COUNT(*) AS n FROM sqlite_master WHERE type = 'index' AND tbl_name = 'node_windows'",
        )
        .get(),
    ).toEqual({ n: 0 });
  });
});

describe("migration 0019", () => {
  it("drops the old agent path switch and leaves transport for the next deploy", () => {
    const sqlite = new DatabaseSync(":memory:");
    apply(sqlite, (name) => name < "0019");
    sqlite.exec(
      "INSERT INTO settings (key, value, updated_at) VALUES ('agent_http', 'off', '2026-10-01T00:00:00.000Z'), ('agent_release', '0.3.1', '2026-10-01T00:00:00.000Z')",
    );
    apply(sqlite, (name) => name.startsWith("0019"));
    expect(
      sqlite.prepare("SELECT key FROM settings ORDER BY key").all(),
    ).toEqual([{ key: "agent_release" }]);
    const columns = sqlite
      .prepare("SELECT name FROM pragma_table_info('nodes')")
      .all()
      .map((row) => (row as { name: string }).name);
    expect(columns).toContain("transport");
  });
});

describe("migrations 0020 and 0021", () => {
  function current() {
    const sqlite = new DatabaseSync(":memory:");
    sqlite.exec("PRAGMA foreign_keys = ON");
    apply(sqlite, (name) => name < "0020");
    sqlite.exec(
      "INSERT INTO nodes (id, owner_user_id, name, agent_token_hash) VALUES ('n1', 'standalone', 'pivox', 'h1')",
    );
    sqlite.exec(action("a1", "docker", "adguard", "restart", "done"));
    apply(sqlite, (name) => name >= "0020");
    return sqlite;
  }

  it("drops the transport column and keeps every action", () => {
    const sqlite = current();
    const columns = sqlite
      .prepare("SELECT name FROM pragma_table_info('nodes')")
      .all()
      .map((row) => (row as { name: string }).name);
    expect(columns).not.toContain("transport");
    expect(sqlite.prepare("SELECT id, status FROM actions").all()).toEqual([
      { id: "a1", status: "done" },
    ]);
  });

  it("allows logs requests beside a pending action, but one pending action per target", () => {
    const sqlite = current();
    sqlite.exec(action("r1", "docker", "adguard", "restart", "queued"));
    sqlite.exec(action("l1", "docker", "adguard", "logs", "queued"));
    sqlite.exec(action("l2", "docker", "adguard", "logs", "sent"));
    expect(() =>
      sqlite.exec(action("r2", "docker", "adguard", "stop", "queued")),
    ).toThrow(/UNIQUE/u);
    expect(
      (
        sqlite.prepare("SELECT COUNT(*) AS n FROM actions").get() as {
          n: number;
        }
      ).n,
    ).toBe(4);
  });
});

describe("migration 0022", () => {
  it("drops the passphrase table nothing reads any more", () => {
    const sqlite = new DatabaseSync(":memory:");
    apply(sqlite, () => true);
    expect(
      sqlite
        .prepare(
          "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'passphrase'",
        )
        .all(),
    ).toEqual([]);
  });
});

describe("migration 0026", () => {
  it("keeps every action and accepts removing Krynodes from a server", () => {
    const sqlite = new DatabaseSync(":memory:");
    sqlite.exec("PRAGMA foreign_keys = ON");
    apply(sqlite, (name) => name < "0026");
    sqlite.exec(
      "INSERT INTO nodes (id, owner_user_id, name, agent_token_hash) VALUES ('n1', 'standalone', 'pivox', 'h1')",
    );
    sqlite.exec(action("a1", "host", "docker", "install", "done", "{}"));
    expect(() =>
      sqlite.exec(action("a2", "host", "server", "uninstall", "queued", "{}")),
    ).toThrow();
    apply(sqlite, (name) => name.startsWith("0026"));
    sqlite.exec(action("a2", "host", "server", "uninstall", "queued", "{}"));
    const rows = sqlite
      .prepare("SELECT id, action FROM actions ORDER BY id")
      .all();
    expect(rows).toEqual([
      { id: "a1", action: "install" },
      { id: "a2", action: "uninstall" },
    ]);
    expect(() =>
      sqlite.exec(action("a3", "host", "server", "explode", "queued", "{}")),
    ).toThrow();
  });
});
