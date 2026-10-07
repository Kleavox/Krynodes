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
  return { call, hub };
}

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
