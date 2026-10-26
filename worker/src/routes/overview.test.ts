import { describe, expect, it, vi } from "vitest";

import { app } from "../app";
import type { Env } from "../env";
import { seedCheck, seedIncident, seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";

const NODE_KEYS = [
  "id",
  "name",
  "hostname",
  "architecture",
  "operating_system",
  "agent_version",
  "last_seen_at",
  "enrolled_at",
  "disabled_at",
  "interval_seconds",
  "cpu_percent",
  "memory_used_bytes",
  "memory_total_bytes",
  "disk_used_bytes",
  "disk_total_bytes",
  "load_1",
  "uptime_seconds",
  "created_at",
  "update_requested_version",
  "update_requested_at",
  "update_attempts",
  "update_error",
  "auto_update",
  "deleting",
  "addresses",
];
const CHECK_KEYS = [
  "id",
  "node_id",
  "name",
  "kind",
  "target",
  "enabled",
  "status",
  "timeout_seconds",
  "latency_ms",
  "last_checked_at",
  "consecutive_failures",
  "last_message",
  "public",
  "public_note",
  "auto_restart",
  "created_at",
  "since",
];
const INCIDENT_KEYS = [
  "id",
  "check_id",
  "status",
  "started_at",
  "resolved_at",
  "summary",
  "check_name",
  "node_name",
  "node_id",
  "update_status",
];

describe("GET /api/overview contract", () => {
  it("keeps every field the dashboard reads and adds node_id to incidents", async () => {
    const { db, sqlite } = createTestDb();
    seedNode(sqlite, { id: "n1" });
    seedCheck(sqlite, { id: "c1", nodeId: "n1" });
    sqlite
      .prepare(
        "UPDATE checks SET since = '2026-10-24T09:24:39Z' WHERE id = 'c1'",
      )
      .run();
    seedIncident(sqlite, {
      id: "i1",
      checkId: "c1",
      status: "OPEN",
      startedAt: new Date().toISOString(),
    });

    const response = await app.request(
      "https://kry.example.test/api/overview",
      {},
      {
        DB: db,
      } as unknown as Env,
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<
      string,
      Record<string, unknown>[]
    >;

    expect(Object.keys(body).sort()).toEqual([
      "agentRelease",
      "checks",
      "incidents",
      "mail",
      "nodes",
    ]);
    expect(Object.keys(body.nodes![0]!).sort()).toEqual([...NODE_KEYS].sort());
    expect(Object.keys(body.checks![0]!).sort()).toEqual(
      [...CHECK_KEYS].sort(),
    );
    expect(Object.keys(body.incidents![0]!).sort()).toEqual(
      [...INCIDENT_KEYS].sort(),
    );
    expect(body.incidents![0]!.node_id).toBe("n1");
    expect(body.checks![0]!.since).toBe("2026-10-24T09:24:39Z");
    expect(body.nodes![0]!.addresses).toBeNull();
  });

  it("keeps an open incident that 50 newer ones would push out", async () => {
    const { db, sqlite } = createTestDb();
    seedNode(sqlite, { id: "n1" });
    seedCheck(sqlite, { id: "c1", nodeId: "n1" });
    const start = Date.parse("2026-10-01T00:00:00Z");
    seedIncident(sqlite, {
      id: "open",
      checkId: "c1",
      status: "OPEN",
      startedAt: new Date(start).toISOString(),
    });
    for (let index = 1; index <= 55; index += 1) {
      seedIncident(sqlite, {
        id: `r${index}`,
        checkId: "c1",
        status: "RESOLVED",
        startedAt: new Date(start + index * 60_000).toISOString(),
      });
    }
    const response = await app.request(
      "https://kry.example.test/api/overview",
      {},
      { DB: db } as unknown as Env,
    );
    const ids = (
      (await response.json()) as { incidents: { id: string }[] }
    ).incidents.map((incident) => incident.id);
    expect(ids).toHaveLength(51);
    expect(ids[0]).toBe("r55");
    expect(ids.at(-1)).toBe("open");
    expect(ids).not.toContain("r5");
  });
});

describe("a node being deleted", () => {
  it("reads running while its batch has work left and stopped once a step did not finish", async () => {
    const { db, sqlite } = createTestDb();
    for (const id of ["n1", "n2", "n3"]) seedNode(sqlite, { id });
    const step = (batch: string, node: string, status: string, at: number) =>
      sqlite
        .prepare(
          `INSERT INTO actions (id, batch_id, position, mode, node_id, kind, name, action,
             status, requested_by, requested_at)
           VALUES (?, ?, ?, 'rolling', ?, 'host', 'server', 'uninstall', ?, 'o', '2026-10-13')`,
        )
        .run(`${batch}-${at}`, batch, at, node, status);
    step("b1", "n1", "queued", 0);
    step("b2", "n2", "done", 0);
    step("b2", "n2", "failed", 1);
    sqlite
      .prepare("UPDATE nodes SET deleting_batch = 'b1' WHERE id = 'n1'")
      .run();
    sqlite
      .prepare("UPDATE nodes SET deleting_batch = 'b2' WHERE id = 'n2'")
      .run();
    const response = await app.request(
      "https://kry.example.test/api/overview",
      {},
      { DB: db } as unknown as Env,
    );
    const body = (await response.json()) as {
      nodes: { id: string; deleting: string | null }[];
    };
    expect(
      Object.fromEntries(body.nodes.map((node) => [node.id, node.deleting])),
    ).toEqual({ n1: "running", n2: "stopped", n3: null });
  });
});

describe("unknown API paths", () => {
  it("answer 404 JSON instead of the app shell", async () => {
    const assets = vi.fn(async () => new Response("<!doctype html>"));
    const response = await app.request(
      "https://kry.example.test/api/unknown",
      {},
      {
        ASSETS: { fetch: assets },
      } as unknown as Env,
    );
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({
      code: "NOT_FOUND",
      message: "No such endpoint.",
    });
    expect(assets).not.toHaveBeenCalled();
  });
});
