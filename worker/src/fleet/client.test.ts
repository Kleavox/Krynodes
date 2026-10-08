import { describe, expect, it, vi } from "vitest";

import { app } from "../app";
import type { Env } from "../env";
import { sha256 } from "../lib/crypto";
import { seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";

const NODE = "11111111-1111-4111-8111-111111111111";
const OTHER = "33333333-3333-4333-8333-333333333333";
const TOKEN = "agent-token";

const live = (nodes: object) => JSON.stringify({ nodes, mail: null });

function fleet(handler: (request: Request) => Response | Promise<Response>) {
  const calls: { name: string; request: Request }[] = [];
  return {
    calls,
    binding: {
      idFromName: (name: string) => ({ name }),
      get: (id: { name: string }) => ({
        fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
          const request = new Request(input, init);
          calls.push({ name: id.name, request });
          return handler(request);
        },
      }),
    },
  };
}

async function setup(env: Partial<Env> = {}) {
  const { db, sqlite } = createTestDb();
  seedNode(sqlite, { id: NODE });
  seedNode(sqlite, { id: OTHER });
  sqlite
    .prepare("UPDATE nodes SET agent_token_hash = ? WHERE id = ?")
    .run(await sha256(TOKEN), NODE);
  const full = { DB: db, ...env } as unknown as Env;
  const call = (path: string, headers: Record<string, string> = {}) =>
    app.request(`https://kry.example.test${path}`, { headers }, full);
  return { sqlite, call };
}

const upgrade = {
  upgrade: "websocket",
  authorization: `Bearer ${TOKEN}`,
};

describe("agent stream route", () => {
  it("answers 404 when the hub is not bound", async () => {
    const unbound = await setup();
    expect((await unbound.call("/api/agent/stream", upgrade)).status).toBe(404);
  });

  it("wants a WebSocket upgrade and a valid agent token", async () => {
    const hub = fleet(() => new Response("hub"));
    const t = await setup({
      FLEET: hub.binding as unknown as DurableObjectNamespace,
    });
    expect(
      (
        await t.call("/api/agent/stream", {
          authorization: `Bearer ${TOKEN}`,
        })
      ).status,
    ).toBe(426);
    expect(
      (
        await t.call("/api/agent/stream", {
          upgrade: "websocket",
          authorization: "Bearer wrong",
        })
      ).status,
    ).toBe(401);
    expect(hub.calls).toHaveLength(0);
  });

  it("hands the upgrade to the owner's hub with the node it proved to be", async () => {
    const hub = fleet(() => new Response("from hub"));
    const t = await setup({
      FLEET: hub.binding as unknown as DurableObjectNamespace,
    });
    const response = await t.call("/api/agent/stream", {
      ...upgrade,
      "x-kry-node": OTHER,
      "x-kry-owner": "intruder",
    });
    expect(await response.text()).toBe("from hub");
    const [{ name, request }] = hub.calls as [
      { name: string; request: Request },
    ];
    expect(name).toBe("standalone");
    expect(new URL(request.url).pathname).toBe("/connect");
    expect(request.headers.get("x-kry-node")).toBe(NODE);
    expect(request.headers.get("x-kry-owner")).toBe("standalone");
    expect(request.headers.get("x-kry-interval")).toBe("60");
    expect(request.headers.get("authorization")).toBeNull();
  });
});

describe("overview with live connections", () => {
  const LAST_SEEN = Date.parse("2026-10-01T08:04:30.000Z");

  it("takes live sightings and metrics from the hub for streaming servers", async () => {
    const hub = fleet(
      () =>
        new Response(
          live({
            [NODE]: {
              lastSeen: LAST_SEEN,
              connectedAt: LAST_SEEN - 600_000,
              agentVersion: "0.3.0",
              hostname: "pivox",
              metrics: {
                cpuPercent: 42,
                memoryUsedBytes: 5,
                memoryTotalBytes: 8,
                diskUsedBytes: 1,
                diskTotalBytes: 2,
                load1: 1,
                load5: 1,
                load15: 1,
                uptimeSeconds: 900,
              },
            },
          }),
        ),
    );
    const t = await setup({
      FLEET: hub.binding as unknown as DurableObjectNamespace,
    });
    const body = (await (await t.call("/api/overview")).json()) as {
      nodes: Record<string, unknown>[];
    };
    const node = body.nodes.find((entry) => entry.id === NODE)!;
    expect(node).toMatchObject({
      last_seen_at: "2026-10-01 08:04:30",
      connected_at: "2026-10-01T07:54:30.000Z",
      cpu_percent: 42,
      uptime_seconds: 900,
      agent_version: "0.3.0",
    });
    expect(node.grace_seconds).toBeUndefined();
    expect(
      body.nodes.find((entry) => entry.id === OTHER)?.grace_seconds,
    ).toBeUndefined();
  });

  it("still answers for a connection that opened before connectedAt existed", async () => {
    const hub = fleet(
      () =>
        new Response(
          live({
            [NODE]: {
              lastSeen: LAST_SEEN,
              agentVersion: "0.3.0",
              hostname: "pivox",
              metrics: {
                cpuPercent: 42,
                memoryUsedBytes: 5,
                memoryTotalBytes: 8,
                diskUsedBytes: 1,
                diskTotalBytes: 2,
                load1: 1,
                load5: 1,
                load15: 1,
                uptimeSeconds: 900,
              },
            },
          }),
        ),
    );
    const t = await setup({
      FLEET: hub.binding as unknown as DurableObjectNamespace,
    });
    const response = await t.call("/api/overview");
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      nodes: Record<string, unknown>[];
    };
    const node = body.nodes.find((entry) => entry.id === NODE)!;
    expect(node.last_seen_at).toBe("2026-10-01 08:04:30");
    expect(node).not.toHaveProperty("connected_at");
  });

  it("widens the offline grace of streaming servers when the hub cannot answer", async () => {
    const hub = fleet(() => {
      throw new Error("hub down");
    });
    const errors = vi
      .spyOn(console, "error")
      .mockImplementation(() => undefined);
    const t = await setup({
      FLEET: hub.binding as unknown as DurableObjectNamespace,
    });
    const body = (await (await t.call("/api/overview")).json()) as {
      nodes: Record<string, unknown>[];
    };
    expect(body.nodes.map((entry) => entry.grace_seconds)).toEqual([420, 420]);
    errors.mockRestore();
  });
});
