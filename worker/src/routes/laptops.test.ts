import { afterEach, describe, expect, it, vi } from "vitest";

import { sha256 } from "../lib/crypto";
import {
  addDevice,
  addEnrollment,
  addNode,
  AGENT,
  ORIGIN,
  testEnv,
} from "../test/env";

const wgKey = (n: number) => Buffer.alloc(32, n).toString("base64");
const SEAL = Buffer.alloc(65, 9).toString("base64url");

const host = {
  hostname: "laptop-1",
  os: "windows",
  arch: "amd64",
  kernel: "10.0.26100",
  version: "0.7.92",
};

const keys = {
  kind: "laptop",
  key: wgKey(1),
  signer: wgKey(2),
  port: 51820,
  sealKey: SEAL,
};

async function ready() {
  const harness = testEnv();
  await addDevice(harness.db, "d1", "pk1");
  await harness.db
    .prepare(
      "INSERT INTO agent_release (id, version, checked_at) VALUES (1, '0.7.92', '2026-11-22T00:00:00.000Z')",
    )
    .run();
  const enroll = (token: string, body: unknown) =>
    harness.call("/api/agent/enroll", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(body),
    });
  const code = async () => {
    const response = await harness.send("POST", "/api/laptops", {
      name: "laptop-1",
      trust: ["d1"],
    });
    expect(response.status).toBe(201);
    return (await response.json()) as Record<string, string>;
  };
  return { ...harness, enroll, code };
}

afterEach(() => vi.useRealTimers());

describe("POST /api/laptops", () => {
  it("makes a code for 10 minutes with the pinned download", async () => {
    const { db, code } = await ready();
    const before = Date.now();
    const body = await code();
    expect(body).toEqual({
      code: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/u),
      expiresAt: expect.any(String),
      origin: ORIGIN,
      endpoint: AGENT,
      download:
        "https://github.com/Kleavox/Krynodes/releases/download/agent-v0.7.92/krynodes-windows-amd64.exe",
    });
    expect(Date.parse(body.expiresAt!) - before).toBeGreaterThan(599_000);
    expect(Date.parse(body.expiresAt!) - before).toBeLessThan(601_000);
    expect(
      await db
        .prepare("SELECT token_hash, name, trust, kind FROM enrollments")
        .first(),
    ).toEqual({
      token_hash: await sha256(body.code!),
      name: "laptop-1",
      trust: '["d1"]',
      kind: "laptop",
    });
  });

  it("refuses while no agent release is known", async () => {
    const { db, send } = await ready();
    await db.prepare("DELETE FROM agent_release").run();
    const response = await send("POST", "/api/laptops", {
      name: "laptop-1",
      trust: ["d1"],
    });
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({ code: "NO_RELEASE" });
    expect(await db.prepare("SELECT id FROM enrollments").first()).toBeNull();
  });

  it("the code works once and enrolls a laptop that asks to join", async () => {
    const { db, enroll, code, hub } = await ready();
    const { code: token } = await code();
    const response = await enroll(token!, { ...host, ...keys });
    expect(response.status).toBe(200);
    const answer = (await response.json()) as {
      nodeId: string;
      name: string;
      token: string;
      trust: string[];
    };
    expect(answer.trust).toEqual(["d1.-7.pk1"]);
    expect(answer.name).toBe("laptop-1");
    expect(
      await db
        .prepare(
          "SELECT name, kind, seal_key, hostname FROM nodes WHERE id = ?",
        )
        .bind(answer.nodeId)
        .first(),
    ).toEqual({
      name: "laptop-1",
      kind: "laptop",
      seal_key: SEAL,
      hostname: "laptop-1",
    });
    expect(
      await db
        .prepare(
          "SELECT state, key, signer, port, ready FROM network_members WHERE node_id = ?",
        )
        .bind(answer.nodeId)
        .first(),
    ).toEqual({
      state: "requested",
      key: wgKey(1),
      signer: wgKey(2),
      port: 51820,
      ready: 1,
    });
    expect(hub.calls.at(-1)).toEqual({
      path: "/announce",
      body: { topics: ["fleet", "network"] },
    });
    expect((await enroll(token!, { ...host, ...keys })).status).toBe(401);
  });

  it("the code is refused after 10 minutes", async () => {
    const { enroll, code, db } = await ready();
    const { code: token } = await code();
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 10 * 60_000 + 1000);
    expect((await enroll(token!, { ...host, ...keys })).status).toBe(401);
    expect(await db.prepare("SELECT id FROM nodes").first()).toBeNull();
  });

  it("a laptop code enrolls no server and a server token no laptop", async () => {
    const { db, enroll, code, call } = await ready();
    const { code: token } = await code();
    expect((await enroll(token!, host)).status).toBe(400);
    const script = await (await call(`/i/${token}`)).text();
    expect(script).toContain("already used or has expired");
    await addEnrollment(db, "server-token-0123456789", { name: "server-1" });
    expect(
      (await enroll("server-token-0123456789", { ...host, ...keys })).status,
    ).toBe(400);
    expect(await db.prepare("SELECT id FROM nodes").first()).toBeNull();
  });
});

describe("a laptop name", () => {
  it("taken by another machine is named so, never a server", async () => {
    const { db, send, enroll, code } = await ready();
    await addNode(db, "n1", "laptop-2");
    const taken = await send("POST", "/api/laptops", {
      name: "laptop-2",
      trust: ["d1"],
    });
    expect(await taken.json()).toEqual({
      code: "NAME_TAKEN",
      message: "laptop-2 is taken by another machine. Choose another name.",
    });
    const { code: token } = await code();
    await addNode(db, "n2", "laptop-1");
    const late = await enroll(token!, { ...host, ...keys });
    expect(late.status).toBe(409);
    expect(await late.json()).toEqual({
      code: "NAME_TAKEN",
      message:
        "laptop-1 is taken by another machine. Make a new code with another name.",
    });
  });
});

describe("DELETE /api/laptops/:id", () => {
  async function laptop(state: string | null) {
    const harness = await ready();
    await addNode(harness.db, "l1", "laptop-1");
    await harness.db
      .prepare("UPDATE nodes SET kind = 'laptop' WHERE id = 'l1'")
      .run();
    if (state) {
      await harness.db
        .prepare(
          "INSERT INTO network_members (node_id, state, since) VALUES ('l1', ?, '2026-11-22T00:00:00.000Z')",
        )
        .bind(state)
        .run();
    }
    return harness;
  }

  it("refuses a laptop that is a member", async () => {
    const { send, db, hub } = await laptop("in");
    const response = await send("DELETE", "/api/laptops/l1");
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({
      code: "NETWORK_MEMBER",
      message: "Remove laptop-1 from the private network first.",
    });
    expect(await db.prepare("SELECT id FROM nodes").first()).toEqual({
      id: "l1",
    });
    expect(hub.calls).toEqual([]);
  });

  it("removes a laptop that is not a member", async () => {
    const { send, db, hub } = await laptop("requested");
    expect((await send("DELETE", "/api/laptops/l1")).status).toBe(200);
    expect(await db.prepare("SELECT id FROM nodes").first()).toBeNull();
    expect(hub.calls.map((call) => call.path)).toEqual(["/drop", "/announce"]);
  });

  it("answers 404 for a server or an unknown laptop", async () => {
    const { send, db } = await laptop(null);
    await addNode(db, "n1", "server-1");
    expect((await send("DELETE", "/api/laptops/n1")).status).toBe(404);
    expect((await send("DELETE", "/api/laptops/ghost")).status).toBe(404);
  });
});
