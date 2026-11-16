import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { app } from "../app";
import type { Env } from "../env";
import { sha256 } from "../lib/crypto";
import { fingerprint } from "../lib/webauthn";
import { testPasskey } from "../test/passkeys";
import { OWNER, seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";

const INSTALLER = readFileSync(
  new URL("../../../app/public/install.sh", import.meta.url),
  "utf8",
);

const A = "11111111-1111-4111-8111-111111111111";
const L = "44444444-4444-4444-8444-444444444444";
const ORIGIN = "https://kry.example.test";

const key = (n: number) => Buffer.alloc(32, n).toString("base64");
const SEAL = "s".repeat(87);
const KEYS = { key: key(7), signer: key(107), port: 51820, sealKey: SEAL };
const HOST = {
  hostname: "laptop-1",
  operatingSystem: "windows",
  architecture: "amd64",
  agentVersion: "0.7.24",
};

function setup(network = true, extra: Partial<Env> = {}) {
  const { db, sqlite } = createTestDb();
  seedNode(sqlite, { id: A });
  if (network) {
    sqlite
      .prepare(
        `INSERT INTO network (owner_user_id, cidr, port, mtu, version, document, stamp, created_at, created_by)
         VALUES (?, '10.88.0.0/24', 51820, 1420, 1, '{}', 's1', 'now', 'user1@example.com')`,
      )
      .run(OWNER);
  }
  const env = {
    ...extra,
    DB: db,
    PUBLIC_ORIGIN: ORIGIN,
    ASSETS: {
      fetch: async (request: Request) =>
        new URL(request.url).pathname === "/install.sh"
          ? new Response(INSTALLER)
          : new Response("not found", { status: 404 }),
    },
  } as unknown as Env;
  const call = (method: string, path: string, body?: unknown, token?: string) =>
    app.request(
      `${ORIGIN}${path}`,
      {
        method,
        headers: {
          "content-type": "application/json",
          "cf-connecting-ip": "203.0.113.9",
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      },
      env,
    );
  const code = async () => {
    const response = await call("POST", "/api/laptops");
    expect(response.status).toBe(201);
    return (await response.json()) as { code: string; expiresAt: string };
  };
  const serverCode = async () => {
    const token = "server-code-0123456789-abcdefghij";
    sqlite
      .prepare(
        `INSERT INTO enrollment_tokens (id, owner_user_id, token_hash, expires_at, setup)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(
        crypto.randomUUID(),
        OWNER,
        await sha256(token),
        new Date(Date.now() + 60_000).toISOString(),
        JSON.stringify({ docker: false, rebootHour: 3, network: false }),
      );
    return token;
  };
  const enroll = (token: string, laptop?: object) =>
    call(
      "POST",
      "/api/agent/enroll",
      laptop ? { ...HOST, laptop } : { ...HOST, operatingSystem: "linux" },
      token,
    );
  return { db, sqlite, call, code, serverCode, enroll };
}

describe("laptop codes", () => {
  it("a laptop code expires in 10 minutes and works once", async () => {
    const empty = setup(false);
    const refused = await empty.call("POST", "/api/laptops");
    expect(refused.status).toBe(409);
    expect(await refused.json()).toEqual({
      code: "NO_NETWORK",
      message: "Create the private network first.",
    });
    const { code, enroll, sqlite, call } = setup();
    const before = Date.now();
    const made = await code();
    expect(made.code).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    const expires = Date.parse(made.expiresAt) - before;
    expect(expires).toBeGreaterThan(10 * 60_000 - 5_000);
    expect(expires).toBeLessThanOrEqual(10 * 60_000 + 5_000);
    expect(
      sqlite.prepare("SELECT token_hash, setup FROM enrollment_tokens").all(),
    ).toEqual([
      { token_hash: await sha256(made.code), setup: '{"laptop":true}' },
    ]);
    expect(await (await call("GET", `/i/${made.code}`)).text()).toContain(
      "already used or has expired",
    );
    expect((await enroll(made.code, KEYS)).status).toBe(200);
    expect((await enroll(made.code, KEYS)).status).toBe(401);
    const late = await code();
    sqlite
      .prepare(
        "UPDATE enrollment_tokens SET expires_at = ? WHERE used_at IS NULL",
      )
      .run(new Date(Date.now() - 1_000).toISOString());
    expect((await enroll(late.code, KEYS)).status).toBe(401);
  });

  it("a laptop code comes with the origins the install command needs", async () => {
    const same = await setup().code();
    expect(same).toMatchObject({ origin: ORIGIN, endpoint: ORIGIN });
    const split = await setup(true, {
      AGENT_ORIGIN: "https://agent.example.test",
    }).code();
    expect(split).toMatchObject({
      origin: ORIGIN,
      endpoint: "https://agent.example.test",
    });
  });

  it("a laptop enroll answers the trust tokens and waits to join", async () => {
    const { code, enroll, sqlite, serverCode, call } = setup();
    const phone = await testPasskey("phone");
    const tablet = await testPasskey("tablet");
    for (const device of [phone, tablet]) {
      sqlite
        .prepare(
          `INSERT INTO devices (id, owner_user_id, name, alg, public_key, created_at, account)
           VALUES (?, ?, ?, -7, ?, '2026-09-01 00:00:00', 'user1@example.com')`,
        )
        .run(device.id, OWNER, device.name, device.publicKey);
    }
    const prints = [
      await fingerprint(phone.publicKey),
      await fingerprint(tablet.publicKey),
    ];
    sqlite.prepare("UPDATE nodes SET trust_report = ? WHERE id = ?").run(
      JSON.stringify({
        version: 3,
        core: prints,
        access: prints,
        accounts: ["user1@example.com", "user1@example.com"],
      }),
      A,
    );
    const response = await enroll((await code()).code, KEYS);
    expect(response.status).toBe(200);
    const answer = (await response.json()) as {
      nodeId: string;
      token: string;
      intervalSeconds: number;
      trust: string[];
    };
    const script = await (await call("GET", `/i/${await serverCode()}`)).text();
    const installed = / -- (.+?) --setup /u.exec(script)?.[1]?.split(" ");
    expect(answer.trust).toHaveLength(2);
    expect(answer.trust).toEqual(installed);
    expect(answer.trust[0]).toMatch(
      /^phone\.-7\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u,
    );
    expect(answer.intervalSeconds).toBe(60);
    expect(
      sqlite
        .prepare(
          "SELECT name, kind, seal_key, operating_system, agent_version FROM nodes WHERE id = ?",
        )
        .get(answer.nodeId),
    ).toEqual({
      name: "laptop-1",
      kind: "laptop",
      seal_key: SEAL,
      operating_system: "windows",
      agent_version: "0.7.24",
    });
    expect(
      sqlite
        .prepare(
          "SELECT state, address, port, key, signer, endpoint FROM network_members WHERE node_id = ?",
        )
        .get(answer.nodeId),
    ).toEqual({
      state: "waiting",
      address: null,
      port: 51820,
      key: key(7),
      signer: key(107),
      endpoint: null,
    });
  });

  it("a server code cannot enroll a laptop and the other way round", async () => {
    const { code, enroll, serverCode, sqlite } = setup();
    const server = await serverCode();
    const laptop = (await code()).code;
    const refused = await enroll(server, KEYS);
    expect(refused.status).toBe(400);
    expect(await refused.json()).toEqual({ code: "INVALID_ENROLLMENT" });
    expect((await enroll(laptop)).status).toBe(400);
    expect((await enroll(laptop, { ...KEYS, port: 80 })).status).toBe(400);
    expect(
      sqlite
        .prepare(
          "SELECT COUNT(*) AS n FROM enrollment_tokens WHERE used_at IS NULL",
        )
        .get(),
    ).toEqual({ n: 2 });
    expect(sqlite.prepare("SELECT COUNT(*) AS n FROM nodes").get()).toEqual({
      n: 1,
    });
    const answer = await enroll(server);
    expect(answer.status).toBe(200);
    expect(await answer.json()).not.toHaveProperty("trust");
  });
});

describe("what a laptop code and token cannot reach", () => {
  it("an install code's setup cannot be written over a laptop code", async () => {
    const { code, serverCode, sqlite, call } = setup();
    await code();
    await serverCode();
    const rows = sqlite
      .prepare("SELECT id, setup FROM enrollment_tokens ORDER BY setup")
      .all() as { id: string; setup: string }[];
    const laptop = rows.find((row) => row.setup === '{"laptop":true}')!;
    const server = rows.find((row) => row !== laptop)!;
    const body = { docker: true, rebootHour: 4, network: false };
    const refused = await call("PATCH", `/api/enrollments/${laptop.id}`, body);
    expect(refused.status).toBe(409);
    expect(await refused.json()).toMatchObject({ code: "ENROLLMENT_CLOSED" });
    expect(
      (await call("PATCH", `/api/enrollments/${server.id}`, body)).status,
    ).toBe(200);
    expect(
      sqlite
        .prepare("SELECT setup FROM enrollment_tokens WHERE id = ?")
        .get(laptop.id),
    ).toEqual({ setup: '{"laptop":true}' });
  });

  it("a laptop's token cannot report a public address", async () => {
    const { code, serverCode, enroll, sqlite, call } = setup();
    const laptop = (await (await enroll((await code()).code, KEYS)).json()) as {
      nodeId: string;
      token: string;
    };
    const server = (await (await enroll(await serverCode())).json()) as {
      nodeId: string;
      token: string;
    };
    for (const method of ["GET", "POST"]) {
      const refused = await call(
        method,
        "/api/agent/address",
        method === "POST" ? { interfaces: [] } : undefined,
        laptop.token,
      );
      expect(refused.status, method).toBe(401);
    }
    expect(
      (await call("GET", "/api/agent/address", undefined, server.token)).status,
    ).toBe(200);
    const ipv4 = (id: string) =>
      sqlite.prepare("SELECT ipv4 FROM nodes WHERE id = ?").get(id);
    expect(ipv4(laptop.nodeId)).toEqual({ ipv4: null });
    expect(ipv4(server.nodeId)).toEqual({ ipv4: "203.0.113.9" });
  });
});

describe("laptops among the servers", () => {
  it("a laptop appears in no server list", async () => {
    const { call, sqlite } = setup();
    seedNode(sqlite, { id: L });
    sqlite
      .prepare(
        "UPDATE nodes SET kind = 'laptop', name = 'laptop-1', last_seen_at = datetime('now') WHERE id = ?",
      )
      .run(L);
    sqlite
      .prepare(
        `INSERT INTO actions (id, batch_id, position, mode, node_id, kind, name, action,
           status, requested_by, requested_at, deliverable_at)
         VALUES ('t1', 'b1', 0, 'parallel', ?, 'trust', 'devices', 'trust', 'queued',
           'user1@example.com', ?, ?)`,
      )
      .run(L, new Date().toISOString(), new Date().toISOString());
    sqlite
      .prepare(
        "INSERT INTO packages (node_id, hash, report, updated_at) VALUES (?, 'h', ?, 'now')",
      )
      .run(L, JSON.stringify({ packages: [{ name: "curl" }] }));
    for (const path of [
      "/api/overview",
      "/api/services",
      "/api/checks/results",
      "/api/metrics/recent",
      "/api/packages",
      "/api/incidents/board",
    ]) {
      const response = await call("GET", path);
      expect(response.status, path).toBe(200);
      const text = await response.text();
      expect(text, path).not.toContain(L);
    }
    expect(
      (
        await call("POST", "/api/checks", {
          nodeId: L,
          name: "Web",
          kind: "HTTP",
          target: "https://example.com/",
        })
      ).status,
    ).toBe(404);
    expect((await call("POST", `/api/nodes/${L}/update`)).status).toBe(404);
    expect((await call("GET", `/api/nodes/${L}/metrics`)).status).toBe(404);
    const renamed = await call("PATCH", `/api/nodes/${L}`, {
      name: "laptop-2",
    });
    expect(renamed.status).toBe(200);
  });
});

describe("dismissing a laptop", () => {
  const enrolled = async (made: ReturnType<typeof setup>) =>
    (await (await made.enroll((await made.code()).code, KEYS)).json()) as {
      nodeId: string;
    };
  const count = (made: ReturnType<typeof setup>, table: string) =>
    made.sqlite.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get();

  it("takes a waiting laptop away with its member row", async () => {
    const made = setup();
    const { nodeId } = await enrolled(made);
    expect(count(made, "network_members")).toEqual({ n: 1 });
    const gone = await made.call("DELETE", `/api/laptops/${nodeId}`);
    expect(gone.status).toBe(204);
    expect(count(made, "network_members")).toEqual({ n: 0 });
    expect(made.sqlite.prepare("SELECT id FROM nodes").all()).toEqual([
      { id: A },
    ]);
  });

  it("refuses a laptop that is in the network, a server and a stranger", async () => {
    const made = setup();
    const { nodeId } = await enrolled(made);
    made.sqlite
      .prepare("UPDATE network_members SET state = 'in' WHERE node_id = ?")
      .run(nodeId);
    const member = await made.call("DELETE", `/api/laptops/${nodeId}`);
    expect(member.status).toBe(409);
    expect(await member.json()).toEqual({
      code: "NETWORK_MEMBER",
      message: "Remove laptop-1 from the private network first.",
    });
    expect((await made.call("DELETE", `/api/laptops/${A}`)).status).toBe(404);
    expect((await made.call("DELETE", `/api/laptops/${L}`)).status).toBe(404);
    expect(count(made, "nodes")).toEqual({ n: 2 });
    expect(count(made, "network_members")).toEqual({ n: 1 });
  });
});
