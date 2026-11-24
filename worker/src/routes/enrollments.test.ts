import { describe, expect, it } from "vitest";

import { sha256 } from "../lib/crypto";
import {
  addDevice,
  addEnrollment,
  addNode,
  AGENT,
  ORIGIN,
  testEnv,
} from "../test/env";

const PIN =
  "https://github.com/Kleavox/Krynodes/releases/download/agent-v0.7.90";

async function release(db: D1Database, version = "0.7.90") {
  await db
    .prepare(
      "INSERT INTO agent_release (id, version, checked_at) VALUES (1, ?, '2026-11-22T00:00:00.000Z')",
    )
    .bind(version)
    .run();
}

async function ready() {
  const harness = testEnv();
  await addDevice(harness.db, "d1", "pk1");
  await addDevice(harness.db, "d2", "pk2");
  await release(harness.db);
  return harness;
}

describe("creating an enrollment", () => {
  it("makes a one-hour token and the install command", async () => {
    const { db, send } = await ready();
    const before = Date.now();
    const response = await send("POST", "/api/enrollments", {
      name: "server-1",
      trust: ["d1", "d2"],
    });
    expect(response.status).toBe(201);
    const body = (await response.json()) as {
      id: string;
      command: string;
      expiresAt: string;
    };
    const token = /^curl -fsSL (\S+)\/i\/(\S+) \| sudo sh$/u.exec(body.command);
    expect(token?.[1]).toBe(AGENT);
    expect(token?.[2]).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(Date.parse(body.expiresAt) - before).toBeGreaterThan(3_599_000);
    expect(Date.parse(body.expiresAt) - before).toBeLessThan(3_601_000);
    expect(
      await db
        .prepare("SELECT id, token_hash, name, trust, used_at FROM enrollments")
        .first(),
    ).toEqual({
      id: body.id,
      token_hash: await sha256(token![2]!),
      name: "server-1",
      trust: '["d1","d2"]',
      used_at: null,
    });
  });

  it("refuses what it cannot install", async () => {
    const { db, send } = await ready();
    await addNode(db, "n1", "taken");
    const refused = async (body: unknown) =>
      (await send("POST", "/api/enrollments", body)).status;
    expect(await refused({ name: "", trust: ["d1"] })).toBe(400);
    expect(await refused({ name: "server-1", trust: [] })).toBe(400);
    expect(await refused({ name: "server-1" })).toBe(400);
    expect(await refused({ name: "server-1", trust: ["d1", "d1"] })).toBe(400);
    expect(await refused({ name: "server-1", trust: ["ghost"] })).toBe(422);
    expect(await refused({ name: "taken", trust: ["d1"] })).toBe(409);
    expect(await db.prepare("SELECT id FROM enrollments").first()).toBeNull();
  });
});

describe("a name in the private network", () => {
  it("refuses a name whose network name another machine already has", async () => {
    const { db, send } = await ready();
    await addNode(db, "n1", "Server 1");
    const response = await send("POST", "/api/enrollments", {
      name: "server-1",
      trust: ["d1"],
    });
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({
      code: "NAME_TAKEN",
      message:
        "server-1 would have the same network name as Server 1 (server-1.kry). Choose another name.",
    });
    expect(await db.prepare("SELECT id FROM enrollments").first()).toBeNull();
    expect(
      (
        await send("POST", "/api/enrollments", {
          name: "server-10",
          trust: ["d1"],
        })
      ).status,
    ).toBe(201);
  });
});

describe("waiting for the server", () => {
  it("answers no node until the agent enrolls, then its id", async () => {
    const { db, call } = await ready();
    await addEnrollment(db, "tok", { id: "e1" });
    const waiting = await call("/api/enrollments/e1");
    expect(await waiting.json()).toEqual({ nodeId: null });
    await addNode(db, "n1");
    await db.prepare("UPDATE enrollments SET node_id = 'n1'").run();
    expect(await (await call("/api/enrollments/e1")).json()).toEqual({
      nodeId: "n1",
    });
    expect((await call("/api/enrollments/ghost")).status).toBe(404);
  });
});

describe("the installer", () => {
  const script = async (token: string, harness = testEnv()) => {
    const response = await harness.call(`/i/${token}`);
    return { response, text: await response.text() };
  };

  it("is the real installer with its arguments filled in", async () => {
    const harness = await ready();
    await addEnrollment(harness.db, "tok-".padEnd(43, "x"), {
      trust: ["d1", "d2"],
    });
    const { response, text } = await script("tok-".padEnd(43, "x"), harness);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/plain");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(text.startsWith("#!/bin/sh\nset -eu\n")).toBe(true);
    expect(text).not.toContain('main "$@"');
    const tail = text.slice(text.lastIndexOf("\nKRY_DOWNLOAD_BASE="));
    const [pin, run] = tail.trim().split("\n");
    expect(pin).toBe(`KRY_DOWNLOAD_BASE='${PIN}'`);
    expect(run).toBe(
      `main --endpoint ${AGENT} --token ${"tok-".padEnd(43, "x")} --origin ${ORIGIN} --trust d1.-7.pk1,d2.-7.pk2`,
    );
    for (const argument of run!.split(" ").slice(1)) {
      expect(argument).toMatch(/^(--[a-z]+|[A-Za-z0-9:/._,-]+)$/u);
    }
  });

  it("an expired or used token gets the refusing script", async () => {
    const harness = await ready();
    const old = "o".repeat(43);
    const spent = "s".repeat(43);
    await addEnrollment(harness.db, old, {
      id: "e1",
      expiresAt: "2026-11-22T00:00:01.000Z",
    });
    await addEnrollment(harness.db, spent, {
      id: "e2",
      usedAt: "2026-11-22T00:00:00.000Z",
    });
    for (const token of [old, spent, "z".repeat(43), "short", "bad token!"]) {
      const { response, text } = await script(token, harness);
      expect(response.status).toBe(200);
      expect(text).toBe(
        '#!/bin/sh\necho "This install command was already used or has expired. Create a new one in Krynodes." >&2\nexit 1\n',
      );
    }
  });

  it("refuses with a clear message while no release is known", async () => {
    const harness = testEnv();
    await addDevice(harness.db, "d1", "pk1");
    await addEnrollment(harness.db, "t".repeat(43));
    const { response, text } = await script("t".repeat(43), harness);
    expect(response.status).toBe(200);
    expect(text).toContain("has not found an agent release yet");
    expect(text).toContain("exit 1");
    expect(text).not.toContain("main --endpoint");
  });

  it("refuses when every passkey it trusted is gone", async () => {
    const harness = await ready();
    await addEnrollment(harness.db, "t".repeat(43), { trust: ["ghost"] });
    const { text } = await script("t".repeat(43), harness);
    expect(text).toContain("exit 1");
    expect(text).not.toContain("main --endpoint");
  });

  it("is not served when an argument could break the shell", async () => {
    const harness = await ready();
    await addDevice(harness.db, "d3", "pk'; rm -rf /; '");
    await addEnrollment(harness.db, "t".repeat(43), { trust: ["d3"] });
    const { response, text } = await script("t".repeat(43), harness);
    expect(response.status).toBe(503);
    expect(text).toContain("cannot serve the installer");
  });

  it("is not served when the installer lost its tail", async () => {
    const harness = await ready();
    harness.env.ASSETS = {
      fetch: async () => new Response("#!/bin/sh\nmain\n"),
    } as unknown as Fetcher;
    await addEnrollment(harness.db, "t".repeat(43));
    const { response } = await script("t".repeat(43), harness);
    expect(response.status).toBe(503);
  });
});
