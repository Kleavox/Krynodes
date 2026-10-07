import { describe, expect, it } from "vitest";

import { app } from "../app";
import type { Env } from "../env";
import { createTestDb } from "../test/sqlite-d1";

function fleet(extra: Partial<Env> = {}) {
  const { db, sqlite } = createTestDb();
  const env = {
    DB: db,
    PUBLIC_ORIGIN: "https://kry.example.test",
    ...extra,
  } as unknown as Env;
  const request = (
    method: string,
    path: string,
    body?: unknown,
    token?: string,
  ) =>
    app.request(
      `https://kry.example.test${path}`,
      {
        method,
        headers: {
          "content-type": "application/json",
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      },
      env,
    );
  const create = async () => {
    const response = await request("POST", "/api/enrollments", {});
    expect(response.status).toBe(201);
    const body = (await response.json()) as { id: string; command: string };
    return {
      id: body.id,
      command: body.command,
      token: body.command.split(" ").at(-1)!,
    };
  };
  const enroll = (token: string, hostname: string) =>
    request(
      "POST",
      "/api/agent/enroll",
      {
        hostname,
        operatingSystem: "linux",
        architecture: "amd64",
        agentVersion: "0.6.0",
      },
      token,
    );
  const status = async (id: string) =>
    (await request("GET", `/api/enrollments/${id}`)).json();
  const nodes = () =>
    sqlite
      .prepare(
        "SELECT id, name, interval_seconds, owner_user_id, enrolled_at FROM nodes",
      )
      .all() as {
      id: string;
      name: string;
      interval_seconds: number;
      owner_user_id: string;
      enrolled_at: string | null;
    }[];
  return { sqlite, request, create, enroll, status, nodes };
}

describe("enrollment tokens", () => {
  it("creates no node until an agent enrolls, only an install command", async () => {
    const { create, nodes, status } = fleet();
    const { id, command } = await create();
    expect(command).toMatch(
      /^curl -fsSL https:\/\/kry\.example\.test\/install\.sh \| sudo sh -s -- https:\/\/kry\.example\.test [A-Za-z0-9_-]{43}$/u,
    );
    expect(nodes()).toEqual([]);
    expect(await status(id)).toEqual({ status: "pending" });
  });

  it("points the command at AGENT_ORIGIN when it is set", async () => {
    const { create } = fleet({
      AGENT_ORIGIN: "https://kry.example.workers.dev",
    });
    const { command } = await create();
    expect(command).toMatch(
      /^curl -fsSL https:\/\/kry\.example\.workers\.dev\/install\.sh \| sudo sh -s -- https:\/\/kry\.example\.workers\.dev \S+$/u,
    );
  });

  it("creates the node from the hostname when the agent enrolls", async () => {
    const { create, enroll, nodes, status } = fleet();
    const { id, token } = await create();

    const response = await enroll(token, "web-01");
    expect(response.status).toBe(200);
    const body = (await response.json()) as { nodeId: string; token: string };

    const [node] = nodes();
    expect(node).toMatchObject({
      id: body.nodeId,
      name: "web-01",
      interval_seconds: 60,
      owner_user_id: "standalone",
    });
    expect(node!.enrolled_at).not.toBeNull();
    expect(await status(id)).toEqual({
      status: "used",
      node: { id: body.nodeId, name: "web-01" },
    });
  });

  it("lets a token enroll exactly one server", async () => {
    const { create, enroll, nodes } = fleet();
    const { token } = await create();
    expect((await enroll(token, "web-01")).status).toBe(200);
    expect((await enroll(token, "intruder")).status).toBe(401);
    expect(nodes().map((node) => node.name)).toEqual(["web-01"]);
  });

  it("cuts a long hostname to the 100-character name limit", async () => {
    const { create, enroll, nodes } = fleet();
    const { token } = await create();
    await enroll(token, "h".repeat(180));
    expect(nodes()[0]!.name).toBe("h".repeat(100));
  });

  it("refuses an expired token and reports it as expired", async () => {
    const { sqlite, create, enroll, nodes, status } = fleet();
    const { id, token } = await create();
    sqlite
      .prepare("UPDATE enrollment_tokens SET expires_at = ? WHERE id = ?")
      .run(new Date(Date.now() - 60_000).toISOString(), id);
    expect((await enroll(token, "web-01")).status).toBe(401);
    expect(nodes()).toEqual([]);
    expect(await status(id)).toEqual({ status: "expired" });
  });

  it("does not show another owner's enrollment", async () => {
    const { sqlite, request } = fleet();
    sqlite
      .prepare(
        `INSERT INTO enrollment_tokens (id, owner_user_id, token_hash, expires_at)
         VALUES ('other', 'someone-else', 'hash', ?)`,
      )
      .run(new Date(Date.now() + 60_000).toISOString());
    expect((await request("GET", "/api/enrollments/other")).status).toBe(404);
  });

  it("no longer creates nodes directly", async () => {
    const { request } = fleet();
    expect((await request("POST", "/api/nodes", {})).status).toBe(404);
  });
});
