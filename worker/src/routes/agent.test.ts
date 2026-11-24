import { describe, expect, it } from "vitest";

import { app } from "../app";
import type { Env } from "../env";
import { sha256 } from "../lib/crypto";
import { freshDb } from "../test/db";
import { addEnrollment, addNode, testEnv } from "../test/env";

async function setup() {
  const db = freshDb();
  await db
    .prepare(
      "INSERT INTO nodes (id, name, agent_token_hash, enrolled_at) VALUES ('n1', 'server-1', ?1, '2026-11-22T00:00:00.000Z')",
    )
    .bind(await sha256("agent-token"))
    .run();
  const hub: Request[] = [];
  const names: string[] = [];
  const env = {
    DB: db,
    ENVIRONMENT: "development",
    PUBLIC_ORIGIN: "https://kry.example.test",
    ASSETS: { fetch: async () => new Response("from assets") },
    FLEET: {
      idFromName: (name: string) => {
        names.push(name);
        return { name };
      },
      get: () => ({
        fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
          hub.push(new Request(input, init));
          return new Response("from hub");
        },
      }),
    },
  } as unknown as Env;
  const call = (
    path: string,
    headers: Record<string, string> = {},
    init: RequestInit = {},
  ) =>
    app.request(`https://kry.example.test${path}`, { ...init, headers }, env);
  return { hub, names, call };
}

const agent = {
  upgrade: "websocket",
  authorization: "Bearer agent-token",
  "user-agent": "kry-agent/0.7.92",
};

describe("agent stream", () => {
  it("upgrades into the one hub with the node and its version", async () => {
    const { hub, names, call } = await setup();
    const response = await call("/api/agent/stream", {
      ...agent,
      "x-kry-node": "spoofed",
      origin: "https://elsewhere.example",
      "sec-fetch-site": "cross-site",
    });
    expect(await response.text()).toBe("from hub");
    expect(names).toEqual(["fleet"]);
    expect(hub).toHaveLength(1);
    const forwarded = hub[0]!;
    expect(new URL(forwarded.url).pathname).toBe("/connect");
    expect(forwarded.headers.get("x-kry-node")).toBe("n1");
    expect(forwarded.headers.get("x-kry-version")).toBe("0.7.92");
    expect(forwarded.headers.get("authorization")).toBeNull();
    expect(forwarded.headers.get("upgrade")).toBe("websocket");
  });

  it("passes an old or missing version on for the hub to close", async () => {
    const { hub, call } = await setup();
    await call("/api/agent/stream", {
      ...agent,
      "user-agent": "kry-agent/0.7.25",
    });
    await call("/api/agent/stream", { ...agent, "user-agent": "curl/8" });
    expect(hub.map((request) => request.headers.get("x-kry-version"))).toEqual([
      "0.7.25",
      "",
    ]);
  });

  it("refuses an unknown token", async () => {
    const { hub, call } = await setup();
    const response = await call("/api/agent/stream", {
      ...agent,
      authorization: "Bearer nope",
    });
    expect(response.status).toBe(401);
    expect(hub).toEqual([]);
  });

  it("wants an upgrade", async () => {
    const { call } = await setup();
    const response = await call("/api/agent/stream", {
      authorization: agent.authorization,
    });
    expect(response.status).toBe(426);
  });
});

describe("live", () => {
  it("upgrades a dashboard into the hub's watch", async () => {
    const { hub, call } = await setup();
    const response = await call("/api/live", {
      upgrade: "websocket",
      cookie: "CF_Authorization=x",
      origin: "https://kry.example.test",
    });
    expect(await response.text()).toBe("from hub");
    expect(new URL(hub[0]!.url).pathname).toBe("/watch");
    expect(hub[0]!.headers.get("cookie")).toBeNull();
  });

  it("refuses another site", async () => {
    const { hub, call } = await setup();
    const response = await call("/api/live", {
      upgrade: "websocket",
      origin: "https://elsewhere.example",
    });
    expect(response.status).toBe(403);
    expect(hub).toEqual([]);
  });
});

describe("app", () => {
  it("answers health", async () => {
    const { call } = await setup();
    expect(await (await call("/health")).json()).toEqual({
      service: "kry",
      status: "ok",
    });
  });

  it("refuses a body over 2 MiB", async () => {
    const { call } = await setup();
    const response = await call(
      "/api/anything",
      { origin: "https://kry.example.test" },
      { method: "POST", body: "x".repeat(2 * 1024 * 1024 + 1) },
    );
    expect(response.status).toBe(413);
  });

  it("refuses a cross-site change", async () => {
    const { call } = await setup();
    const response = await call(
      "/api/anything",
      { "sec-fetch-site": "cross-site" },
      { method: "POST", body: "{}" },
    );
    expect(response.status).toBe(403);
  });
});

const host = {
  hostname: "vps-1",
  os: "linux",
  arch: "amd64",
  kernel: "6.8.0-45-generic",
  version: "0.7.92",
};

const enroll = (
  send: ReturnType<typeof testEnv>["call"],
  body: unknown,
  token = "enroll-token",
) =>
  send("/api/agent/enroll", {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      "sec-fetch-site": "none",
    },
    body: JSON.stringify(body),
  });

describe("enroll", () => {
  it("creates the node named as the enrollment and spends the token", async () => {
    const { db, call, hub } = testEnv();
    await addEnrollment(db, "enroll-token", { name: "server-1" });
    const response = await enroll(call, host);
    expect(response.status).toBe(200);
    const { nodeId, token } = (await response.json()) as {
      nodeId: string;
      token: string;
    };
    expect(
      await db
        .prepare(
          "SELECT name, hostname, os, arch, kernel, version, agent_token_hash FROM nodes WHERE id = ?",
        )
        .bind(nodeId)
        .first(),
    ).toEqual({
      name: "server-1",
      hostname: "vps-1",
      os: "linux",
      arch: "amd64",
      kernel: "6.8.0-45-generic",
      version: "0.7.92",
      agent_token_hash: await sha256(token),
    });
    expect(
      await db
        .prepare("SELECT used_at IS NOT NULL AS used, node_id FROM enrollments")
        .first(),
    ).toEqual({ used: 1, node_id: nodeId });
    expect(hub.calls.map((entry) => entry.path)).toEqual(["/announce"]);
    expect((await enroll(call, host)).status).toBe(401);
  });

  it("enroll below MIN_AGENT is 426", async () => {
    const { db, call } = testEnv();
    await addEnrollment(db, "enroll-token");
    const response = await enroll(call, { ...host, version: "0.7.25" });
    expect(response.status).toBe(426);
    expect(await response.json()).toMatchObject({
      code: "AGENT_UPDATE_REQUIRED",
    });
    expect(await db.prepare("SELECT used_at FROM enrollments").first()).toEqual(
      { used_at: null },
    );
  });

  it("an expired, used or unknown token is refused", async () => {
    const { db, call } = testEnv();
    await addEnrollment(db, "old", {
      id: "e1",
      expiresAt: "2026-11-22T00:00:01.000Z",
    });
    await addEnrollment(db, "spent", {
      id: "e2",
      usedAt: "2026-11-22T00:00:00.000Z",
    });
    for (const token of ["old", "spent", "nope"]) {
      expect((await enroll(call, host, token)).status).toBe(401);
    }
    expect(await db.prepare("SELECT id FROM nodes").first()).toBeNull();
  });

  it("refuses a body that is not a host report", async () => {
    const { db, call } = testEnv();
    await addEnrollment(db, "enroll-token");
    expect((await enroll(call, { hostname: "vps-1" })).status).toBe(400);
    expect((await enroll(call, { ...host, extra: 1 })).status).toBe(400);
    const bare = await call("/api/agent/enroll", { method: "POST" });
    expect(bare.status).toBe(400);
  });

  it("a name already taken leaves the token unspent", async () => {
    const { db, call } = testEnv();
    await addNode(db, "n1", "server-1");
    await addEnrollment(db, "enroll-token", { name: "server-1" });
    const response = await enroll(call, host);
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({ code: "NAME_TAKEN" });
    expect(await db.prepare("SELECT used_at FROM enrollments").first()).toEqual(
      { used_at: null },
    );
  });

  it("a network name another machine took meanwhile leaves the token unspent", async () => {
    const { db, call } = testEnv();
    await addNode(db, "n1", "Server 1");
    await addEnrollment(db, "enroll-token", { name: "server-1" });
    const response = await enroll(call, host);
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({
      code: "NAME_TAKEN",
      message:
        "server-1 would have the same network name as Server 1 (server-1.kry). Create a new install command with another name.",
    });
    expect(await db.prepare("SELECT used_at FROM enrollments").first()).toEqual(
      { used_at: null },
    );
  });

  it("the token it returns opens the stream", async () => {
    const { db, call, hub } = testEnv();
    await addEnrollment(db, "enroll-token");
    const { nodeId, token } = (await (await enroll(call, host)).json()) as {
      nodeId: string;
      token: string;
    };
    await call("/api/agent/stream", {
      headers: {
        upgrade: "websocket",
        authorization: `Bearer ${token}`,
        "user-agent": "kry-agent/0.7.92",
      },
    });
    const connect = hub.calls.find((entry) => entry.path === "/connect");
    expect(connect).toBeDefined();
    expect(nodeId).toMatch(/^[0-9a-f-]{36}$/u);
  });
});

describe("agent rate limit", () => {
  it("answers 429 on /api/agent/* and /i/* when the limit is spent, keyed by IP", async () => {
    const keys: string[] = [];
    const { call } = testEnv({
      AGENT_RATE_LIMIT: {
        limit: async ({ key }: { key: string }) => {
          keys.push(key);
          return { success: false };
        },
      },
    });
    const stream = await call("/api/agent/stream", {
      headers: { "cf-connecting-ip": "203.0.113.7" },
    });
    expect(stream.status).toBe(429);
    expect(await stream.json()).toEqual({
      code: "RATE_LIMITED",
      message: "Too many agent requests.",
    });
    const installer = await call("/i/anything", {
      headers: { "cf-connecting-ip": "203.0.113.7" },
    });
    expect(installer.status).toBe(429);
    expect(keys).toEqual(["203.0.113.7", "203.0.113.7"]);
  });

  it("lets a request through while the limit holds", async () => {
    const { call } = testEnv({
      AGENT_RATE_LIMIT: { limit: async () => ({ success: true }) },
    });
    const response = await call("/api/agent/stream", {
      headers: { authorization: "Bearer nope", upgrade: "websocket" },
    });
    expect(response.status).toBe(401);
  });
});
