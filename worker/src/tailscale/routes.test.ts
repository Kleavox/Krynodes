import { describe, expect, it } from "vitest";

import { app } from "../app";
import type { Env } from "../env";
import { hubHarness, type FakeSocket } from "../test/hub";
import { seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";

const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const C = "33333333-3333-4333-8333-333333333333";
const SET = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a20";
const TS_SET = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a22";
const DEVICE = "ZGV2aWNlLTE";
const keyOf = (node: string) => `B${node.slice(0, 1).repeat(86)}`;

const b64 = (value: unknown) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");
const VERIFIED = Buffer.from(
  Uint8Array.from({ length: 37 }, (_, index) => (index === 32 ? 0x05 : 0)),
).toString("base64url");

interface Step {
  nodeId: string;
  kind: string;
  name: string;
  action: string;
  args?: Record<string, string>;
  attachFrom?: number;
  attachKey?: string;
}

function step({ args, ...target }: Step) {
  const id = crypto.randomUUID();
  const { attachFrom, attachKey, ...command } = target;
  return {
    id,
    ...command,
    ...(attachFrom === undefined ? {} : { attachFrom }),
    ...(attachKey === undefined ? {} : { attachKey }),
    signed: {
      grant: {
        grant: "Z3JhbnQ",
        credentialId: DEVICE,
        authenticatorData: VERIFIED,
        clientDataJSON: "Y2xpZW50",
        signature: "c2ln",
      },
      command: b64({ v: 1, id, ...command, ...(args ? { args } : {}) }),
      signature: "c2lnbmF0dXJl",
    },
  };
}

const RULES = JSON.stringify([
  { from: "devices", to: "rest" },
  { from: "devices", to: "servers", ports: ["22/tcp"] },
]);

const release = (from: string, to: string) =>
  step({
    nodeId: from,
    kind: "vault",
    name: "tailscale",
    action: "release",
    args: { set: TS_SET, to, key: keyOf(to) },
  });

const job = (action: string, args: Record<string, string> = {}, node = A) =>
  step({
    nodeId: node,
    kind: "vault",
    name: "tailscale",
    action,
    args: { client: "kQ1clientCNTRL", ...args },
    attachFrom: 0,
  });

const join = (node: string, attachFrom = 1) =>
  step({
    nodeId: node,
    kind: "host",
    name: "tailscale",
    action: "join",
    attachFrom,
  });

const store = (nodeId: string, name = "tailscale", holders = "2") =>
  step({
    nodeId,
    kind: "vault",
    name,
    action: "store",
    args: { set: TS_SET, holders },
  });

const CONNECT = {
  tailscale: {
    tailnet: "tail0000.ts.net",
    clientId: "kQ1clientCNTRL",
    webhookSecret: "tskey-webhook-s3cret",
  },
};

function routes(version = "0.7.0") {
  const { db, sqlite } = createTestDb();
  for (const id of [A, B, C]) {
    seedNode(sqlite, { id });
    sqlite
      .prepare(
        "UPDATE nodes SET agent_version = ?, seal_key = ?, vault = ?, tailscale_vault = ?, last_seen_at = datetime('now') WHERE id = ?",
      )
      .run(
        version,
        keyOf(id),
        JSON.stringify({ set: SET, holders: 3 }),
        id === C ? null : JSON.stringify({ set: TS_SET, holders: 2 }),
        id,
      );
  }
  const env = {
    DB: db,
    PUBLIC_ORIGIN: "https://kry.example.org",
    AGENT_ORIGIN: "https://kry.kleavox.workers.dev",
  } as unknown as Env;
  const call = (method: string, path: string, body?: unknown) =>
    app.request(
      `https://kry.example.org${path}`,
      {
        method,
        headers: { "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      },
      env,
    );
  const operate = (
    kind: string,
    steps: ReturnType<typeof step>[],
    extra = {},
  ) => call("POST", "/api/operations", { kind, steps, ...extra });
  return { db, sqlite, env, call, operate };
}

const answer = async (response: Response) =>
  (await response.json()) as { code?: string; message?: string };

describe("Tailscale operations", () => {
  it("accepts each job's shape and refuses each near miss", async () => {
    const t = routes();
    const ok = async (
      kind: string,
      steps: ReturnType<typeof step>[],
      extra = {},
    ) => {
      const response = await t.operate(kind, steps, extra);
      expect(
        response.status,
        JSON.stringify(await answer(response.clone())),
      ).toBe(201);
      t.sqlite.prepare("UPDATE actions SET status = 'done'").run();
    };
    const refused = async (
      kind: string,
      steps: ReturnType<typeof step>[],
      extra = {},
    ) => expect((await t.operate(kind, steps, extra)).status).toBe(400);
    await ok("tailnet", [release(B, A), job("policy")]);
    await ok("tailnet", [
      release(B, A),
      job("save", {
        rules: RULES,
        servers: "{}",
        expected: "",
        tag: "",
        label: "",
      }),
    ]);
    await ok("tailnet", [
      release(B, A),
      job("key", { to: C, key: keyOf(C) }),
      join(C),
    ]);
    await ok("tailnet", [
      release(B, A),
      job("remove", { device: "nC", node: C }),
    ]);
    await ok("split", [store(A), store(B)], CONNECT);
    await ok("disconnect", [
      step({ nodeId: A, kind: "vault", name: "tailscale", action: "forget" }),
      step({ nodeId: B, kind: "vault", name: "tailscale", action: "forget" }),
    ]);
    await refused("tailnet", [
      release(B, A),
      job("key", { to: C, key: keyOf(C) }),
    ]);
    await refused("tailnet", [
      release(B, A),
      job("key", { to: C, key: keyOf(C) }),
      join(B),
    ]);
    await refused("tailnet", [release(B, A), job("policy"), join(C)]);
    await refused("tailnet", [job("policy", {}, A), job("save", {}, B)]);
    await refused("split", [store(A), store(B, "cloudflare")], CONNECT);
    await refused("split", [store(A, "tailscale", "1")], CONNECT);
    await refused("split", [store(A), store(B)]);
    await refused("disconnect", [store(A), store(B)]);
    await refused("tailnet", [
      step({
        nodeId: B,
        kind: "vault",
        name: "cloudflare",
        action: "release",
        args: { set: SET, to: A, key: keyOf(A) },
      }),
      job("policy"),
    ]);
  });

  it("writes the tailnet's row when the split is accepted, and a second split is Change Credential", async () => {
    const t = routes();
    expect(
      (await t.operate("split", [store(A), store(B)], CONNECT)).status,
    ).toBe(201);
    expect(
      t.sqlite
        .prepare(
          "SELECT tailnet, client_id, webhook_secret, set_id, connected_by FROM tailscale",
        )
        .get(),
    ).toEqual({
      tailnet: "tail0000.ts.net",
      client_id: "kQ1clientCNTRL",
      webhook_secret: "tskey-webhook-s3cret",
      set_id: null,
      connected_by: DEVICE,
    });
    t.sqlite.prepare("UPDATE actions SET status = 'done'").run();
    t.sqlite
      .prepare(
        "INSERT INTO tailscale_alarms (id, owner_user_id, kind, detail, at, raised_at) VALUES ('p1', 'standalone', 'policy', '{}', 'now', 'now')",
      )
      .run();
    const again = {
      tailscale: { tailnet: "tail0000.ts.net", clientId: "kQ2clientCNTRL" },
    };
    expect((await t.operate("split", [store(A), store(B)], again)).status).toBe(
      201,
    );
    expect(
      t.sqlite.prepare("SELECT client_id, webhook_secret FROM tailscale").get(),
    ).toEqual({
      client_id: "kQ2clientCNTRL",
      webhook_secret: "tskey-webhook-s3cret",
    });
    expect(
      t.sqlite
        .prepare(
          "SELECT cleared_at IS NOT NULL AS cleared FROM tailscale_alarms",
        )
        .get(),
    ).toEqual({ cleared: 1 });
    t.sqlite.prepare("UPDATE actions SET status = 'done'").run();
    expect(
      (
        await t.operate("disconnect", [
          step({
            nodeId: A,
            kind: "vault",
            name: "tailscale",
            action: "forget",
          }),
        ])
      ).status,
    ).toBe(201);
    expect(
      t.sqlite.prepare("SELECT COUNT(*) AS n FROM tailscale").get(),
    ).toEqual({ n: 0 });
    expect(
      t.sqlite.prepare("SELECT COUNT(*) AS n FROM tailscale_alarms").get(),
    ).toEqual({ n: 0 });
  });

  it("never runs a Tailscale step on a quarantined server", async () => {
    const t = routes();
    t.sqlite
      .prepare(
        "INSERT INTO quarantines (id, node_id, why, at, timeline) VALUES ('q1', ?, 'why', 'now', '{}')",
      )
      .run(B);
    const response = await t.operate("tailnet", [release(B, A), job("policy")]);
    expect(response.status).toBe(409);
    expect((await answer(response)).code).toBe("QUARANTINED");
    t.sqlite
      .prepare("UPDATE nodes SET tailscale_vault = ? WHERE id = ?")
      .run(JSON.stringify({ set: TS_SET, holders: 2 }), C);
    expect(
      (
        await t.operate("tailnet", [
          release(C, A),
          job("remove", { device: "nB", node: B }),
        ])
      ).status,
    ).toBe(201);
  });

  it("says which vault is busy, and keeps the two vaults apart", async () => {
    const t = routes();
    const pending = (name: string, action: string) =>
      t.sqlite
        .prepare(
          `INSERT INTO actions (id, batch_id, position, mode, node_id, kind, name, action,
             status, requested_by, requested_at, deliverable_at)
           VALUES (?, ?, 0, 'rolling', ?, 'vault', ?, ?, 'queued', 'owner@example.test', ?, ?)`,
        )
        .run(
          crypto.randomUUID(),
          crypto.randomUUID(),
          C,
          name,
          action,
          new Date().toISOString(),
          new Date().toISOString(),
        );
    pending("tailscale", "store");
    const busy = await t.operate("tailnet", [release(B, A), job("policy")]);
    expect(busy.status).toBe(409);
    expect(await answer(busy)).toMatchObject({
      code: "TOKEN_BUSY",
      message:
        "The Tailscale credential is being changed. Try again when that finishes.",
    });
    t.sqlite.prepare("UPDATE actions SET status = 'done'").run();
    pending("cloudflare", "store");
    expect(
      (await t.operate("tailnet", [release(B, A), job("policy")])).status,
    ).toBe(201);
    const cloudflare = await t.operate(
      "split",
      [A, B].map((nodeId) => store(nodeId, "cloudflare")),
      { zone: "example.org" },
    );
    expect(await answer(cloudflare)).toMatchObject({
      code: "TOKEN_BUSY",
      message:
        "The Cloudflare token is being changed. Try again when that finishes.",
    });
  });

  it("says which vault a server holds no piece of", async () => {
    const t = routes();
    const response = await t.operate("tailnet", [release(C, A), job("policy")]);
    expect(response.status).toBe(422);
    expect(await answer(response)).toMatchObject({
      code: "NO_PIECE",
      message: `${C} holds no piece of the Tailscale credential. Change the credential to share it again.`,
    });
  });

  it("needs agent 0.7.0 for a Tailscale step", async () => {
    const t = routes("0.6.14");
    const response = await t.operate("tailnet", [release(B, A), job("policy")]);
    expect(response.status).toBe(422);
    expect((await answer(response)).code).toBe("AGENT_TOO_OLD");
  });
});

describe("GET /api/tailscale", () => {
  it("shows the webhook address on the agent origin and no tailnet before Connect", async () => {
    const t = routes();
    t.sqlite
      .prepare("UPDATE nodes SET tailscale = ? WHERE id = ?")
      .run(
        JSON.stringify({ state: "running", addresses: ["100.101.7.20"] }),
        A,
      );
    const listener = {
      address: "0.0.0.0",
      port: 53,
      protocol: "udp",
      process: "Resolver",
    };
    t.sqlite
      .prepare("UPDATE nodes SET security = ? WHERE id = ?")
      .run(JSON.stringify({ findings: [], listeners: [listener] }), A);
    const response = await t.call("GET", "/api/tailscale");
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      hook: string;
      connected: unknown;
      servers: {
        nodeId: string;
        report: unknown;
        vault: unknown;
        signedIn: boolean;
      }[];
      alarms: unknown[];
    };
    expect(body.hook).toBe("https://kry.kleavox.workers.dev/hooks/tailscale");
    expect(body.connected).toBeNull();
    expect(body.alarms).toEqual([]);
    expect(body.servers.find((server) => server.nodeId === A)).toMatchObject({
      report: { state: "running" },
      vault: { set: TS_SET, holders: 2 },
      signedIn: false,
      listeners: [listener],
    });
    expect(body.servers.find((server) => server.nodeId === C)).toMatchObject({
      report: null,
      vault: null,
      listeners: [],
    });
  });
});

async function hub() {
  const { db, sqlite } = createTestDb();
  for (const id of [A, B, C]) {
    seedNode(sqlite, { id });
    sqlite
      .prepare(
        "UPDATE nodes SET agent_version = '0.7.0', seal_key = ?, tailscale_vault = ? WHERE id = ?",
      )
      .run(keyOf(id), JSON.stringify({ set: TS_SET, holders: 2 }), id);
  }
  sqlite
    .prepare(
      `INSERT INTO tailscale (owner_user_id, tailnet, client_id, webhook_secret, connected_at)
       VALUES ('standalone', 'tail0000.ts.net', 'kQ1clientCNTRL', 's', datetime('now'))`,
    )
    .run();
  const harness = hubHarness({ DB: db });
  const sockets = new Map<string, FakeSocket>();
  const send = async (
    nodeId: string,
    type: string,
    fields: Record<string, unknown>,
  ) => {
    let socket = sockets.get(nodeId);
    if (!socket) {
      socket = await harness.connect(nodeId);
      sockets.set(nodeId, socket);
    }
    return (await harness.request(socket, type, fields)) ?? {};
  };
  const beat = async (nodeId: string) =>
    ((
      await send(nodeId, "heartbeat", {
        heartbeat: {
          nodeId,
          hostname: "web-01",
          operatingSystem: "Debian 12.10",
          architecture: "amd64",
          agentVersion: "0.7.0",
          metrics: {
            cpuPercent: 1,
            memoryUsedBytes: 1,
            memoryTotalBytes: 2,
            diskUsedBytes: 1,
            diskTotalBytes: 2,
            load1: 0,
            load5: 0,
            load15: 0,
            uptimeSeconds: 1,
          },
        },
      })
    ).response ?? {}) as { actions?: Record<string, unknown>[] };
  const finish = (nodeId: string, id: string, output: string, ok = true) =>
    send(nodeId, "actions", {
      report: {
        nodeId,
        results: [
          {
            id,
            ok,
            exitCode: ok ? 0 : 1,
            output,
            finishedAt: new Date().toISOString(),
          },
        ],
      },
    });
  const env = {
    DB: db,
    PUBLIC_ORIGIN: "https://kry.example.org",
  } as unknown as Env;
  const operate = async (
    kind: string,
    steps: ReturnType<typeof step>[],
    extra = {},
  ) => {
    const response = await app.request(
      "https://kry.example.org/api/operations",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ kind, steps, ...extra }),
      },
      env,
    );
    expect(response.status).toBe(201);
    return steps.map((made) => made.id);
  };
  const row = () =>
    sqlite
      .prepare(
        "SELECT set_id, rules, block, lines, etag, members, saved_at IS NOT NULL AS saved, saved_by FROM tailscale",
      )
      .get() as Record<string, unknown>;
  return { db, sqlite, beat, finish, operate, row };
}

describe("Tailscale results", () => {
  it("keeps the rules of the signed save, never the ones its output names", async () => {
    const t = await hub();
    const [releaseId, saveId] = await t.operate("tailnet", [
      release(B, A),
      job("save", {
        rules: RULES,
        servers: "{}",
        expected: "",
        tag: "",
        label: "",
      }),
    ]);
    await t.beat(B);
    await t.finish(B, releaseId!, "c2VhbGVk");
    await t.beat(A);
    await t.finish(
      A,
      saveId!,
      JSON.stringify({
        saved: true,
        at: "2026-10-27T14:21:00Z",
        etag: '"e1"',
        block: "b1",
        lines: ["{}"],
        members: ["100.101.7.33"],
        rules: [{ raw: "{}" }],
      }),
    );
    expect(t.row()).toEqual({
      set_id: null,
      rules: RULES,
      block: "b1",
      lines: '["{}"]',
      etag: '"e1"',
      members: '["100.101.7.33"]',
      saved: 1,
      saved_by: DEVICE,
    });
  });

  it("leaves the row alone when a save found a changed rule", async () => {
    const t = await hub();
    const [releaseId, saveId] = await t.operate("tailnet", [
      release(B, A),
      job("save", {
        rules: RULES,
        servers: "{}",
        expected: "x",
        tag: "",
        label: "",
      }),
    ]);
    await t.beat(B);
    await t.finish(B, releaseId!, "c2VhbGVk");
    await t.beat(A);
    await t.finish(
      A,
      saveId!,
      JSON.stringify({ saved: false, block: "b2", changed: { now: [] } }),
    );
    expect(t.row()).toMatchObject({ rules: "[]", saved: 0 });
  });

  it("hands the sealed key to the join, records the joined server and the shared credential", async () => {
    const t = await hub();
    const [releaseId, keyId, joinId] = await t.operate("tailnet", [
      release(B, A),
      job("key", { to: C, key: keyOf(C) }),
      join(C),
    ]);
    await t.beat(B);
    await t.finish(B, releaseId!, "c2VhbGVk");
    await t.beat(A);
    await t.finish(A, keyId!, "a2V5");
    expect(
      t.sqlite.prepare("SELECT output FROM actions WHERE id = ?").get(keyId!),
    ).toEqual({
      output: null,
    });
    expect((await t.beat(C)).actions?.[0]).toMatchObject({
      id: joinId,
      attachment: "a2V5",
    });
    await t.finish(
      C,
      joinId!,
      JSON.stringify({ id: "nC", addresses: ["100.101.7.50"], name: "vps-4" }),
    );
    expect(
      t.sqlite.prepare("SELECT node_id, device FROM tailscale_nodes").all(),
    ).toEqual([{ node_id: C, device: "nC" }]);
    const stores = await t.operate("split", [store(A), store(B)], {
      tailscale: { tailnet: "tail0000.ts.net", clientId: "kQ1clientCNTRL" },
    });
    await t.beat(A);
    await t.finish(A, stores[0]!, "stored");
    await t.beat(B);
    await t.finish(B, stores[1]!, "stored");
    expect(t.row()).toMatchObject({ set_id: TS_SET });
    expect(t.sqlite.prepare("SELECT set_id FROM cloudflare").all()).toEqual([]);
  });

  it("writes the removal into the suspect's quarantine and clears a gone device's alarm", async () => {
    const t = await hub();
    t.sqlite
      .prepare(
        `INSERT INTO quarantines (id, node_id, why, at, timeline) VALUES ('q1', ?, 'why', 'now', ?)`,
      )
      .run(
        C,
        JSON.stringify({ batches: [], tailnet: ["100.101.7.50"], dropped: [] }),
      );
    t.sqlite
      .prepare(
        "INSERT INTO tailscale_alarms (id, owner_user_id, kind, device, detail, at, raised_at) VALUES ('d1', 'standalone', 'device', 'nGone', '{}', 'now', 'now')",
      )
      .run();
    const [releaseId, removeId] = await t.operate("tailnet", [
      release(B, A),
      job("remove", { device: "nC", node: C }),
    ]);
    await t.beat(B);
    await t.finish(B, releaseId!, "c2VhbGVk");
    await t.beat(A);
    await t.finish(A, removeId!, JSON.stringify({ removed: "nC" }));
    const timeline = JSON.parse(
      (
        t.sqlite.prepare("SELECT timeline FROM quarantines").get() as {
          timeline: string;
        }
      ).timeline,
    ) as { tailnet: string[]; removed?: { at: string; by: string } };
    expect(timeline.tailnet).toEqual(["100.101.7.50"]);
    expect(timeline.removed).toMatchObject({ by: DEVICE });
    t.sqlite.prepare("UPDATE actions SET status = 'done'").run();
    const [again, policyId] = await t.operate("tailnet", [
      release(B, A),
      job("policy"),
    ]);
    await t.beat(B);
    await t.finish(B, again!, "c2VhbGVk");
    await t.beat(A);
    await t.finish(
      A,
      policyId!,
      JSON.stringify({
        at: "now",
        etag: '"e1"',
        kry: true,
        open: null,
        block: null,
        tags: [],
        devices: [{ id: "nA" }],
      }),
    );
    expect(
      t.sqlite
        .prepare(
          "SELECT cleared_at IS NOT NULL AS cleared FROM tailscale_alarms",
        )
        .get(),
    ).toEqual({ cleared: 1 });
  });
});
