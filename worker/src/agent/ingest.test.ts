import type { AgentHeartbeat, CheckResult } from "@krynodes/protocol";
import { describe, expect, it, vi } from "vitest";

import { app } from "../app";
import type { Env } from "../env";
import type { IncidentNotice } from "../incident/notify";
import { sha256 } from "../lib/crypto";
import { hubHarness } from "../test/hub";
import { seedCheck, seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";
import {
  acceptResults,
  CHECK_LIMIT,
  commit,
  heartbeatStatements,
  loadAgentConfig,
  resultStatements,
} from "./ingest";

const NODE = {
  id: "11111111-1111-4111-8111-111111111111",
  interval_seconds: 60,
};
const CHECK = "22222222-2222-4222-8222-222222222222";
const WINDOW = 300_000;
const BASE = Math.floor(Date.parse("2026-09-27T08:00:00Z") / WINDOW) * WINDOW;
const STARTED = "2026-09-27T07:59:00Z";

function heartbeat(results?: CheckResult[]): AgentHeartbeat {
  return {
    nodeId: NODE.id,
    hostname: "server-1",
    operatingSystem: "linux",
    architecture: "arm64",
    agentVersion: "0.3.1",
    metrics: {
      cpuPercent: 12,
      memoryUsedBytes: 4,
      memoryTotalBytes: 8,
      diskUsedBytes: 1,
      diskTotalBytes: 2,
      load1: 0.1,
      load5: 0.1,
      load15: 0.1,
      uptimeSeconds: 100,
    },
    results,
  };
}

const result = (status: "UP" | "DOWN"): CheckResult => ({
  checkId: CHECK,
  status,
  latencyMs: status === "UP" ? 40 : null,
  message: status === "DOWN" ? "timeout" : null,
});

function setup() {
  const { db, sqlite } = createTestDb();
  seedNode(sqlite, { id: NODE.id });
  seedCheck(sqlite, { id: CHECK, nodeId: NODE.id });
  const notices: IncidentNotice[] = [];
  const env = { DB: db } as unknown as Env;
  const beat = async (now: number, results?: CheckResult[]) => {
    const agent = await loadAgentConfig(db, NODE);
    const accepted = acceptResults(agent.checks, results ?? []);
    notices.push(
      ...(await commit(
        env,
        NODE.id,
        heartbeatStatements(db, NODE, heartbeat(results), now),
        resultStatements(db, agent.checks, accepted, now),
      )),
    );
  };
  const changes = () =>
    (sqlite.prepare("SELECT total_changes() AS n").get() as { n: number }).n;
  const count = (table: string) =>
    (
      sqlite.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get() as {
        n: number;
      }
    ).n;
  return { db, sqlite, notices, beat, changes, count };
}

describe("agent ingestion budget", () => {
  it("opens an incident at the second failure, then stays quiet until it resolves", async () => {
    const { beat, changes, count, notices, sqlite } = setup();
    await beat(BASE + 10_000, [result("DOWN")]);
    expect(count("incidents")).toBe(0);

    await beat(BASE + 70_000, [result("DOWN")]);
    expect(count("incidents")).toBe(1);
    expect(notices).toHaveLength(1);
    expect(notices.at(-1)).toEqual(
      expect.objectContaining({
        kind: "opened",
        summary: `${CHECK} is down: timeout`,
      }),
    );

    const before = changes();
    await beat(BASE + 130_000, [result("DOWN")]);
    expect(changes() - before).toBe(1);

    await beat(BASE + 190_000, [result("UP")]);
    expect(notices).toHaveLength(2);
    expect(notices.at(-1)).toEqual(
      expect.objectContaining({ kind: "resolved" }),
    );
    expect(sqlite.prepare("SELECT status FROM incidents").get()).toEqual({
      status: "RESOLVED",
    });
  });

  it("ignores results for checks the node does not run", () => {
    expect(
      acceptResults(
        [{ id: CHECK }],
        [
          {
            ...result("DOWN"),
            checkId: "33333333-3333-4333-8333-333333333333",
          },
        ],
      ),
    ).toEqual([]);
  });

  it("changes the config version only when the agent config changes", async () => {
    const { db, sqlite } = setup();
    const first = await loadAgentConfig(db, NODE);
    expect(first.configVersion).toMatch(/^[0-9a-f]{16}$/u);

    sqlite
      .prepare("UPDATE checks SET status = 'DOWN', consecutive_failures = 2")
      .run();
    expect((await loadAgentConfig(db, NODE)).configVersion).toBe(
      first.configVersion,
    );

    sqlite
      .prepare("UPDATE checks SET target = 'https://example.com/other'")
      .run();
    expect((await loadAgentConfig(db, NODE)).configVersion).not.toBe(
      first.configVersion,
    );
  });

  it("orders checks that share a creation time by id", async () => {
    const { db, sqlite } = createTestDb();
    seedNode(sqlite, { id: NODE.id });
    for (const id of ["c-b", "c-a"]) seedCheck(sqlite, { id, nodeId: NODE.id });
    sqlite
      .prepare("UPDATE checks SET created_at = '2026-09-01 00:00:00'")
      .run();
    const { config } = await loadAgentConfig(db, NODE);
    expect(config.checks.map((check) => check.id)).toEqual(["c-a", "c-b"]);
  });

  it("stores when a container started", async () => {
    const { beat, sqlite } = setup();
    await beat(BASE + 10_000, [{ ...result("UP"), since: STARTED }]);
    expect(
      sqlite.prepare("SELECT since FROM checks WHERE id = ?").get(CHECK),
    ).toEqual({ since: STARTED });
  });

  it("writes a restart between two checks once", async () => {
    const { beat, db } = setup();
    await beat(BASE + 10_000, [{ ...result("UP"), since: STARTED }]);
    const { checks } = await loadAgentConfig(db, NODE);
    const restarted = "2026-09-27T08:01:30Z";
    expect(
      resultStatements(
        db,
        checks,
        [{ ...result("UP"), since: restarted }],
        BASE + 70_000,
      ).statements,
    ).toHaveLength(1);
    expect(
      resultStatements(
        db,
        checks,
        [{ ...result("UP"), since: STARTED }],
        BASE + 70_000,
      ).statements,
    ).toHaveLength(0);
  });

  it("clears since when a result comes without it", async () => {
    const { beat, sqlite } = setup();
    await beat(BASE + 10_000, [{ ...result("UP"), since: STARTED }]);
    await beat(BASE + 70_000, [result("UP")]);
    expect(
      sqlite.prepare("SELECT since FROM checks WHERE id = ?").get(CHECK),
    ).toEqual({ since: null });
  });

  it("drops the unused last_seen_at index", () => {
    const { sqlite } = setup();
    expect(
      sqlite
        .prepare(
          "SELECT name FROM sqlite_master WHERE name = 'idx_nodes_last_seen_at'",
        )
        .get(),
    ).toBeUndefined();
  });
});

describe("agent routes", () => {
  async function agentSetup() {
    const { db, sqlite } = createTestDb();
    seedNode(sqlite, { id: NODE.id });
    sqlite
      .prepare("UPDATE nodes SET agent_token_hash = ? WHERE id = ?")
      .run(await sha256("agent-token"), NODE.id);
    seedCheck(sqlite, { id: CHECK, nodeId: NODE.id });
    const call = (path: string, init: RequestInit = {}) =>
      app.request(
        `https://kry.example.test${path}`,
        {
          ...init,
          headers: {
            authorization: "Bearer agent-token",
            "content-type": "application/json",
          },
        },
        { DB: db } as unknown as Env,
      );
    return { db, sqlite, call };
  }

  it("ingests results carried by the heartbeat and returns the config version", async () => {
    const { db, sqlite } = await agentSetup();
    const hub = hubHarness({ DB: db });
    const reply = await hub.request(await hub.connect(NODE.id), "heartbeat", {
      heartbeat: heartbeat([result("UP")]),
    });
    const body = reply?.response as {
      ok: boolean;
      intervalSeconds: number;
      configVersion: string;
    };
    expect(body).toMatchObject({ ok: true, intervalSeconds: 60 });
    expect(body.configVersion).toBe(
      (await loadAgentConfig(db, NODE)).configVersion,
    );
    expect(
      sqlite.prepare("SELECT status FROM checks WHERE id = ?").get(CHECK),
    ).toEqual({ status: "UP" });
  });

  it("has no separate results endpoint; results ride the heartbeat", async () => {
    const { sqlite, call } = await agentSetup();
    const response = await call("/api/agent/results", {
      method: "POST",
      body: JSON.stringify({ nodeId: NODE.id, results: [result("UP")] }),
    });
    expect(response.status).toBe(404);
    expect(
      sqlite.prepare("SELECT COUNT(*) AS n FROM node_windows").get(),
    ).toEqual({ n: 0 });
  });
});

describe("POST /api/checks", () => {
  it(`rejects a check beyond ${CHECK_LIMIT} per node`, async () => {
    const { db, sqlite } = createTestDb();
    seedNode(sqlite, { id: NODE.id });
    for (let index = 0; index < CHECK_LIMIT; index += 1) {
      seedCheck(sqlite, { id: crypto.randomUUID(), nodeId: NODE.id });
    }
    const response = await app.request(
      "https://kry.example.test/api/checks",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          nodeId: NODE.id,
          name: "one too many",
          kind: "HTTP",
          target: "https://example.com/health",
        }),
      },
      { DB: db } as unknown as Env,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ code: "CHECK_LIMIT" });
  });
});
