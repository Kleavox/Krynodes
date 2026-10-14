import { describe, expect, it } from "vitest";

import { app } from "../app";
import type { Env } from "../env";
import { sha256 } from "../lib/crypto";
import { seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";

const NODE = "11111111-1111-4111-8111-111111111111";

async function setup() {
  const { db, sqlite } = createTestDb();
  seedNode(sqlite, { id: NODE });
  sqlite
    .prepare("UPDATE nodes SET agent_version = '0.6.10' WHERE id = ?")
    .run(NODE);
  sqlite
    .prepare("UPDATE nodes SET agent_token_hash = ? WHERE id = ?")
    .run(await sha256("agent-token"), NODE);
  const hub: Request[] = [];
  const env = {
    DB: db,
    FLEET: {
      idFromName: (name: string) => ({ name }),
      get: () => ({
        fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
          hub.push(new Request(input, init));
          return new Response("from hub");
        },
      }),
    },
  } as unknown as Env;
  const call = (
    method: string,
    path: string,
    headers: Record<string, string> = {},
    body?: unknown,
  ) =>
    app.request(
      `https://kry.example.test${path}`,
      {
        method,
        headers: {
          "content-type": "application/json",
          authorization: "Bearer agent-token",
          ...headers,
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      },
      env,
    );
  const row = () =>
    sqlite
      .prepare("SELECT ipv4, ipv4_at, ipv6, ipv6_at FROM nodes WHERE id = ?")
      .get(NODE) as {
      ipv4: string | null;
      ipv4_at: string | null;
      ipv6: string | null;
      ipv6_at: string | null;
    };
  return { call, hub, row };
}

describe("the server's own addresses", () => {
  it("are what Cloudflare saw the agent come from, one per family", async () => {
    const t = await setup();
    const seen = async (ip: string) =>
      (
        await t.call("GET", "/api/agent/address", { "cf-connecting-ip": ip })
      ).json();
    expect(await seen("103.28.54.214")).toEqual({
      address: "103.28.54.214",
      family: 4,
    });
    expect(await seen("2001:db8:1:2::8f2a")).toEqual({
      address: "2001:db8:1:2::8f2a",
      family: 6,
    });
    const stored = t.row();
    expect(stored).toMatchObject({
      ipv4: "103.28.54.214",
      ipv6: "2001:db8:1:2::8f2a",
    });
    expect(stored.ipv4_at).not.toBeNull();
    expect(stored.ipv6_at).not.toBeNull();
  });

  it("ignore what is not an address and refuse a stranger", async () => {
    const t = await setup();
    expect(
      await (
        await t.call("GET", "/api/agent/address", {
          "cf-connecting-ip": "999.1.1.1",
        })
      ).json(),
    ).toEqual({ address: null });
    expect(await (await t.call("GET", "/api/agent/address")).json()).toEqual({
      address: null,
    });
    expect(t.row()).toMatchObject({ ipv4: null, ipv6: null });
    expect(
      (
        await t.call("GET", "/api/agent/address", {
          authorization: "Bearer wrong",
          "cf-connecting-ip": "103.28.54.214",
        })
      ).status,
    ).toBe(401);
  });
});

describe("older agents", () => {
  it("get 410 on the HTTP report routes, which no longer exist", async () => {
    const t = await setup();
    for (const [method, path] of [
      ["POST", "/api/agent/heartbeat"],
      ["GET", "/api/agent/config"],
      ["POST", "/api/agent/actions"],
    ] as const) {
      const response = await t.call(
        method,
        path,
        {},
        method === "POST" ? {} : undefined,
      );
      expect(response.status).toBe(410);
      expect(await response.json()).toMatchObject({
        code: "AGENT_UPDATE_REQUIRED",
      });
    }
  });

  it("are refused at the live connection by the version they announce", async () => {
    const t = await setup();
    const open = (agent: string) =>
      t.call("GET", "/api/agent/stream", {
        upgrade: "websocket",
        "user-agent": agent,
      });
    const old = await open("kry-agent/0.4.1");
    expect(old.status).toBe(426);
    expect(await old.json()).toMatchObject({ code: "AGENT_UPDATE_REQUIRED" });
    expect(t.hub).toHaveLength(0);
    expect(await (await open("kry-agent/0.5.1")).text()).toBe("from hub");
    expect(await (await open("kry-agent/0.6.0")).text()).toBe("from hub");
    expect(await (await open("kry-agent/dev")).text()).toBe("from hub");
  });

  it("leave no switch behind on the dashboard", async () => {
    const t = await setup();
    const overview = (await (
      await t.call("GET", "/api/overview")
    ).json()) as Record<string, unknown>;
    expect(overview).not.toHaveProperty("agentHttp");
    expect(
      (await t.call("PUT", "/api/agent-http", {}, { enabled: true })).status,
    ).toBe(404);
  });
});
