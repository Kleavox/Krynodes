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
];

describe("GET /api/overview contract", () => {
  it("keeps every field the dashboard reads and adds node_id to incidents", async () => {
    const { db, sqlite } = createTestDb();
    seedNode(sqlite, { id: "n1" });
    seedCheck(sqlite, { id: "c1", nodeId: "n1" });
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
