import { afterEach, describe, expect, it, vi } from "vitest";

import { freshDb } from "../test/db";
import { hubHarness } from "../test/hub";

const SEAL =
  "BKjpRA_slHw4x3NdGJcyQ75R9_DQQtbaWv1M8JLZI1Y0jhyDrnX9kl3a9IjqweVG1-weFpLFHMr0nXfvK_uB2Iw";

const hello = {
  type: "hello",
  v: 1,
  version: "0.7.92",
  hostname: "server-1",
  os: "linux",
  arch: "amd64",
  kernel: "6.8.0-45-generic",
  kind: "server",
  sealKey: SEAL,
  trust: { version: 3, core: ["Y3JlZC1jb3Jl"], access: ["Y3JlZC1jb3Jl"] },
  network: null,
};

const command = {
  type: "command",
  id: "a1",
  kind: "host",
  name: "server-1",
  action: "reboot",
  signed: "c2lnbmVk",
};

async function setup() {
  const db = freshDb();
  await db
    .prepare(
      "INSERT INTO nodes (id, name, agent_token_hash, enrolled_at) VALUES ('n1', 'server-1', 'h1', '2026-11-22T00:00:00.000Z')",
    )
    .run();
  await db
    .prepare(
      "INSERT INTO actions (id, node_id, kind, name, action, title, status, created_at) VALUES ('a1', 'n1', 'host', 'server-1', 'reboot', 'Reboot server-1', 'sent', '2026-11-22T00:00:00.000Z')",
    )
    .run();
  const writes: string[] = [];
  const counted = {
    prepare: (sql: string) => {
      if (/^\s*(INSERT|UPDATE|DELETE)/iu.test(sql)) writes.push(sql);
      return db.prepare(sql);
    },
    batch: db.batch.bind(db),
  } as unknown as D1Database;
  return { db, writes, ...hubHarness(counted) };
}

const post = (path: string, body: unknown) =>
  new Request(`https://fleet${path}`, {
    method: "POST",
    body: JSON.stringify(body),
  });

afterEach(() => vi.useRealTimers());

describe("FleetHub", () => {
  it("answers pings without waking", async () => {
    const { autoResponses } = await setup();
    expect(autoResponses).toEqual([{ request: "ping", response: "pong" }]);
  });

  it("hello writes facts once and not again when nothing changed", async () => {
    const { db, writes, connect, say } = await setup();
    const ws = connect("n1");
    await say(ws, hello);
    expect(writes).toHaveLength(2);
    expect(
      await db
        .prepare(
          "SELECT hostname, os, arch, kernel, version, seal_key, last_seen_at IS NOT NULL AS seen FROM nodes WHERE id = 'n1'",
        )
        .first(),
    ).toEqual({
      hostname: "server-1",
      os: "linux",
      arch: "amd64",
      kernel: "6.8.0-45-generic",
      version: "0.7.92",
      seal_key: SEAL,
      seen: 1,
    });
    expect(
      await db
        .prepare(
          "SELECT version, core, access FROM node_trust WHERE node_id = 'n1'",
        )
        .first(),
    ).toEqual({
      version: 3,
      core: '["Y3JlZC1jb3Jl"]',
      access: '["Y3JlZC1jb3Jl"]',
    });

    await say(ws, hello);
    await say(connect("n1"), hello);
    expect(writes).toHaveLength(2);

    await say(connect("n1"), { ...hello, kernel: "6.8.0-46-generic" });
    expect(writes).toHaveLength(3);
  });

  it("writes last_seen_at again after ten minutes", async () => {
    vi.useFakeTimers({ now: Date.parse("2026-11-22T08:00:00.000Z") });
    const { writes, connect, say } = await setup();
    const ws = connect("n1");
    await say(ws, { ...hello, trust: null });
    vi.setSystemTime(Date.parse("2026-11-22T08:09:00.000Z"));
    await say(ws, { ...hello, trust: null });
    expect(writes).toHaveLength(1);
    vi.setSystemTime(Date.parse("2026-11-22T08:10:00.000Z"));
    await say(ws, { ...hello, trust: null });
    expect(writes).toHaveLength(2);
  });

  it("a command reaches the node's socket", async () => {
    const { connect, hub } = await setup();
    const ws = connect("n1");
    const other = connect("n2");
    const response = await hub.fetch(
      post("/command", { nodeId: "n1", command }),
    );
    expect(response.status).toBe(200);
    expect(ws.replies()).toEqual([command]);
    expect(other.sent).toEqual([]);
  });

  it("a command for a node with no socket is OFFLINE", async () => {
    const { connect, hub } = await setup();
    connect("n1").close(1001, "gone");
    const response = await hub.fetch(
      post("/command", { nodeId: "n1", command }),
    );
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({ code: "OFFLINE" });
  });

  it("refuses a command that is not one", async () => {
    const { connect, hub } = await setup();
    connect("n1");
    const response = await hub.fetch(
      post("/command", { nodeId: "n1", command: { type: "ack", id: "a1" } }),
    );
    expect(response.status).toBe(400);
  });

  it("drop closes the node's sockets and no other", async () => {
    const { connect, hub } = await setup();
    const first = connect("n1");
    const other = connect("n2");
    const response = await hub.fetch(post("/drop", { nodeId: "n1" }));
    expect(response.status).toBe(204);
    expect(first.closed).toEqual({ code: 4001, reason: "removed" });
    expect(other.closed).toBeNull();
  });

  it("a stored document goes to online members that have not applied it", async () => {
    const { db, connect, hub } = await setup();
    for (const [id, state, applied] of [
      ["n2", "in", 1],
      ["n3", "leaving", 1],
      ["n4", "in", 2],
      ["n5", "in", 1],
      ["n6", "requested", 0],
    ] as const) {
      await db
        .prepare(
          "INSERT INTO nodes (id, name, agent_token_hash, enrolled_at) VALUES (?1, ?1, ?1, '2026-11-22T00:00:00.000Z')",
        )
        .bind(id)
        .run();
      await db
        .prepare(
          "INSERT INTO network_members (node_id, state, applied, since) VALUES (?1, ?2, ?3, '2026-11-22T00:00:00.000Z')",
        )
        .bind(id, state, applied)
        .run();
    }
    await db
      .prepare(
        "INSERT INTO network_documents (version, signed, hash, created_at) VALUES (2, 'signed-two', 'h2', '2026-11-22T00:00:00.000Z')",
      )
      .run();
    const sockets = Object.fromEntries(
      ["n2", "n3", "n4", "n6"].map((id) => [id, connect(id)]),
    );
    const response = await hub.fetch(post("/document", { version: 2 }));
    expect(response.status).toBe(204);
    const pushed = { type: "document", version: 2, signed: "signed-two" };
    expect(sockets.n2!.replies()).toEqual([pushed]);
    expect(sockets.n3!.replies()).toEqual([pushed]);
    expect(sockets.n4!.sent).toEqual([]);
    expect(sockets.n6!.sent).toEqual([]);
    expect((await hub.fetch(post("/document", { version: 3 }))).status).toBe(
      404,
    );
    expect((await hub.fetch(post("/document", { version: "2" }))).status).toBe(
      400,
    );
  });

  it("a late result from a removed node is closed, not stored", async () => {
    const { db, connect, say } = await setup();
    const ws = connect("n1");
    await db.prepare("DELETE FROM nodes WHERE id = 'n1'").run();
    await say(ws, {
      type: "result",
      id: "a1",
      ok: true,
      message: "Done",
      trust: { version: 4, core: ["Y29yZQ"], access: [] },
    });
    expect(ws.closed?.code).toBe(4401);
    expect(ws.sent).toEqual([]);
    expect(
      await db.prepare("SELECT version FROM node_trust").first(),
    ).toBeNull();
  });

  it("a server stays online after the hub forgets its memory", async () => {
    const harness = await setup();
    harness.connect("n1");
    harness.forget();
    const response = await harness.hub.fetch(
      new Request("https://fleet/online"),
    );
    expect(await response.json()).toEqual(["n1"]);
  });

  it("a second socket replaces the first", async () => {
    const { connect, hub } = await setup();
    const first = connect("n1");
    const second = connect("n1");
    expect(first.closed).toEqual({ code: 4000, reason: "replaced" });
    expect(second.closed).toBeNull();
    await hub.fetch(post("/command", { nodeId: "n1", command }));
    expect(second.replies()).toEqual([command]);
  });

  it("resent result is stored once and acked twice", async () => {
    const { db, writes, connect, watch, say } = await setup();
    const ws = connect("n1");
    const dashboard = watch();
    const result = { type: "result", id: "a1", ok: true, message: "Rebooted" };
    await say(ws, result);
    const stored = await db
      .prepare(
        "SELECT status, message, finished_at FROM actions WHERE id = 'a1'",
      )
      .first<{ status: string; message: string; finished_at: string }>();
    expect(stored).toMatchObject({ status: "done", message: "Rebooted" });
    await say(ws, { ...result, ok: false, message: "Again" });
    expect(
      await db
        .prepare(
          "SELECT status, message, finished_at FROM actions WHERE id = 'a1'",
        )
        .first(),
    ).toEqual(stored);
    expect(ws.replies()).toEqual([
      { type: "ack", id: "a1" },
      { type: "ack", id: "a1" },
    ]);
    expect(writes.filter((sql) => sql.includes("actions"))).toHaveLength(2);
    expect(dashboard.replies()).toEqual([
      { type: "changed", topics: ["fleet"] },
    ]);
  });

  it("a failed result is failed and its trust is stored", async () => {
    const { db, connect, say } = await setup();
    await say(connect("n1"), {
      type: "result",
      id: "a1",
      ok: false,
      message: "No",
      trust: { version: 4, core: ["Y29yZQ"], access: [] },
    });
    expect(
      await db.prepare("SELECT status FROM actions WHERE id = 'a1'").first(),
    ).toEqual({ status: "failed" });
    expect(await db.prepare("SELECT version FROM node_trust").first()).toEqual({
      version: 4,
    });
  });

  it("another node cannot finish an action", async () => {
    const { db, connect, say } = await setup();
    await say(connect("n2"), {
      type: "result",
      id: "a1",
      ok: true,
      message: "Done",
    });
    expect(
      await db.prepare("SELECT status FROM actions WHERE id = 'a1'").first(),
    ).toEqual({ status: "sent" });
  });

  it("progress reaches dashboards only and is not stored", async () => {
    const { writes, connect, watch, say } = await setup();
    const ws = connect("n1");
    const other = connect("n2");
    const dashboard = watch();
    await say(ws, { type: "progress", id: "a1", line: "Pulling image" });
    expect(dashboard.replies()).toEqual([
      { type: "progress", id: "a1", line: "Pulling image" },
    ]);
    expect(ws.sent).toEqual([]);
    expect(other.sent).toEqual([]);
    expect(writes).toEqual([]);
  });

  it("an invalid message is answered and the socket kept", async () => {
    const { writes, connect, say } = await setup();
    const ws = connect("n1");
    await say(ws, "{not json");
    await say(ws, { type: "result", id: "a1" });
    expect(ws.replies()).toEqual([
      { type: "error", code: "INVALID_MESSAGE" },
      { type: "error", code: "INVALID_MESSAGE" },
    ]);
    expect(ws.closed).toBeNull();
    expect(writes).toEqual([]);
  });

  it("closing writes last_seen_at and tells dashboards", async () => {
    const { db, connect, watch, hub } = await setup();
    const ws = connect("n1");
    const dashboard = watch();
    await hub.webSocketClose(ws as unknown as WebSocket);
    expect(
      await db
        .prepare(
          "SELECT last_seen_at IS NOT NULL AS seen FROM nodes WHERE id = 'n1'",
        )
        .first(),
    ).toEqual({ seen: 1 });
    expect(dashboard.replies()).toEqual([
      { type: "changed", topics: ["fleet"] },
    ]);
  });

  it("announces topics to dashboards", async () => {
    const { connect, watch, hub } = await setup();
    const ws = connect("n1");
    const dashboard = watch();
    await hub.fetch(post("/announce", { topics: ["fleet", 3] }));
    expect(dashboard.replies()).toEqual([
      { type: "changed", topics: ["fleet"] },
    ]);
    expect(ws.sent).toEqual([]);
  });

  it("an agent below MIN_AGENT is closed with 4426", async () => {
    const { connect, hub } = await setup();
    for (const version of ["0.7.25", null]) {
      const ws = connect("n1", version);
      expect(ws.closed?.code).toBe(4426);
    }
    const response = await hub.fetch(new Request("https://fleet/online"));
    expect(await response.json()).toEqual([]);
  });

  describe("silent sockets", () => {
    const START = Date.parse("2026-11-22T08:00:00.000Z");
    const at = (seconds: number) => vi.setSystemTime(START + seconds * 1000);

    it("closes a socket silent for more than 75 seconds and the node reads offline", async () => {
      vi.useFakeTimers({ now: START });
      const { db, connect, watch, hub, settled, fire } = await setup();
      const ws = connect("n1");
      await settled();
      const dashboard = watch();
      at(75);
      await fire();
      expect(ws.closed).toBeNull();
      expect(dashboard.replies()).toEqual([]);
      at(76);
      await fire();
      expect(ws.closed).toEqual({ code: 4408, reason: "silent" });
      const online = await hub.fetch(new Request("https://fleet/online"));
      expect(await online.json()).toEqual([]);
      expect(
        await db
          .prepare(
            "SELECT last_seen_at IS NOT NULL AS seen FROM nodes WHERE id = 'n1'",
          )
          .first(),
      ).toEqual({ seen: 1 });
      expect(dashboard.replies()).toEqual([
        { type: "changed", topics: ["fleet"] },
      ]);
      const refused = await hub.fetch(
        post("/command", { nodeId: "n1", command }),
      );
      expect(refused.status).toBe(409);
    });

    it("keeps a socket that pinged or spoke recently and closes only the silent one", async () => {
      vi.useFakeTimers({ now: START });
      const { connect, hub, settled, ping, say, fire } = await setup();
      const pinged = connect("n1");
      const spoke = connect("n2");
      const silent = connect("n3");
      await settled();
      at(90);
      ping(pinged);
      await say(spoke, { type: "progress", id: "a1", line: "Pulling" });
      at(120);
      await fire();
      expect(pinged.closed).toBeNull();
      expect(spoke.closed).toBeNull();
      expect(silent.closed).toEqual({ code: 4408, reason: "silent" });
      const online = await hub.fetch(new Request("https://fleet/online"));
      expect(await online.json()).toEqual(["n1", "n2"]);
    });

    it("counts a silence from the last ping when it is newer than the last message", async () => {
      vi.useFakeTimers({ now: START });
      const { connect, settled, ping, fire } = await setup();
      const ws = connect("n1");
      await settled();
      at(100);
      ping(ws);
      at(170);
      await fire();
      expect(ws.closed).toBeNull();
      at(176);
      await fire();
      expect(ws.closed?.code).toBe(4408);
    });

    it("reads a silent socket as offline and refuses a command before the alarm comes", async () => {
      vi.useFakeTimers({ now: START });
      const { connect, hub, settled, ping } = await setup();
      const silent = connect("n1");
      const pinged = connect("n2");
      await settled();
      const online = async () =>
        (await hub.fetch(new Request("https://fleet/online"))).json();
      at(75);
      expect(await online()).toEqual(["n1", "n2"]);
      at(100);
      ping(pinged);
      at(150);
      expect(await online()).toEqual(["n2"]);
      const refused = await hub.fetch(
        post("/command", { nodeId: "n1", command }),
      );
      expect(refused.status).toBe(409);
      expect(await refused.json()).toEqual({ code: "OFFLINE" });
      expect(silent.sent).toEqual([]);
      expect(silent.closed).toBeNull();
      const sent = await hub.fetch(post("/command", { nodeId: "n2", command }));
      expect(sent.status).toBe(200);
    });

    it("sets no alarm while no agent is connected", async () => {
      vi.useFakeTimers({ now: START });
      const harness = await setup();
      expect(harness.alarmAt()).toBeNull();
      harness.watch();
      harness.connect("n1", "0.7.25");
      await harness.settled();
      expect(harness.alarmAt()).toBeNull();
    });

    it("arms one alarm 60 seconds out for the first agent and leaves it for the next", async () => {
      vi.useFakeTimers({ now: START });
      const { connect, settled, alarmAt } = await setup();
      connect("n1");
      await settled();
      expect(alarmAt()).toBe(START + 60_000);
    });

    it("does not push the alarm out when another agent joins", async () => {
      vi.useFakeTimers({ now: START });
      const harness = await setup();
      harness.connect("n1");
      await harness.settled();
      at(30);
      harness.connect("n2");
      await harness.settled();
      expect(harness.alarmAt()).toBe(START + 60_000);
    });

    it("sets the next alarm 60 seconds on while an agent remains", async () => {
      vi.useFakeTimers({ now: START });
      const harness = await setup();
      const ws = harness.connect("n1");
      await harness.settled();
      at(60);
      harness.ping(ws);
      await harness.fire();
      expect(ws.closed).toBeNull();
      expect(harness.alarmAt()).toBe(START + 120_000);
    });

    it("does not set another alarm when the last agent was closed", async () => {
      vi.useFakeTimers({ now: START });
      const harness = await setup();
      const ws = harness.connect("n1");
      await harness.settled();
      at(200);
      await harness.fire();
      expect(ws.closed?.code).toBe(4408);
      expect(harness.alarmAt()).toBeNull();
    });

    it("does not set another alarm when the agent had already closed", async () => {
      vi.useFakeTimers({ now: START });
      const harness = await setup();
      harness.connect("n1").close(1001, "gone");
      await harness.settled();
      at(60);
      await harness.fire();
      expect(harness.alarmAt()).toBeNull();
    });
  });
});

const S1 = "11111111-1111-4111-8111-111111111111";
const S2 = "22222222-2222-4222-8222-222222222222";
const S3 = "44444444-4444-4444-8444-444444444444";
const L1 = "33333333-3333-4333-8333-333333333333";
const RANGE = "10.88.37.0/24";
const AT = "2026-11-22T00:00:00.000Z";
const NUMBER: Record<string, number> = { [S1]: 1, [S2]: 2, [S3]: 3, [L1]: 4 };
const NAME: Record<string, string> = {
  [S1]: "server-1",
  [S2]: "server-2",
  [S3]: "server-3",
  [L1]: "laptop-1",
};

const wgKey = (n: number) => Buffer.alloc(32, n).toString("base64");

type Entry = Record<string, unknown> & { node: string; kind?: string };

const entry = (node: string, extra: Partial<Entry> = {}): Entry => ({
  node,
  name: NAME[node]!,
  address: `10.88.37.${NUMBER[node]! * 10}`,
  key: wgKey(NUMBER[node]!),
  signer: wgKey(NUMBER[node]! + 100),
  sealKey: Buffer.alloc(65, NUMBER[node]!).toString("base64url"),
  port: 51820,
  mtu: null,
  endpoint: `203.0.113.${NUMBER[node]! * 10}:51820`,
  nat: false,
  psk: {},
  ...extra,
});

function documentOf(
  version: number,
  members: Entry[],
  extra: Record<string, unknown> = {},
) {
  return {
    v: 1,
    version,
    range: RANGE,
    port: 51820,
    mtu: 1420,
    members: members.map((one) => ({
      ...one,
      psk: Object.fromEntries(
        members
          .filter(
            (other) =>
              other !== one &&
              !(one.kind === "laptop" && other.kind === "laptop"),
          )
          .map((other) => [other.node, "c2VhbGVk"]),
      ),
    })),
    blocked: [],
    allow: [],
    ...extra,
  };
}

const envelope = (document: object) =>
  JSON.stringify({
    grant: {
      credentialId: "pk1",
      authenticatorData: Buffer.alloc(37, 5).toString("base64url"),
      clientDataJSON: "e30",
      signature: "c2ln",
      grant: "e30",
    },
    document: Buffer.from(JSON.stringify(document)).toString("base64url"),
    signature: "c2ln",
  });

const joining = (
  id: string,
  version = 0,
  extra: Record<string, unknown> = {},
) => ({
  version,
  key: wgKey(NUMBER[id]!),
  signer: wgKey(NUMBER[id]! + 100),
  ready: true,
  reason: null,
  ...extra,
});

const helloFrom = (id: string, network: object | null) => ({
  ...hello,
  hostname: NAME[id],
  kind: id === L1 ? "laptop" : "server",
  trust: null,
  network,
});

const noHints = {
  type: "hints",
  endpoints: [],
  announced: [],
  meetings: [],
  held: [],
  connected: [],
};

async function signerOf() {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const raw = (await crypto.subtle.exportKey(
    "raw",
    pair.publicKey,
  )) as ArrayBuffer;
  return {
    public: Buffer.from(raw).toString("base64"),
    async announce(node: string, key: string) {
      const signature = await crypto.subtle.sign(
        { name: "Ed25519" },
        pair.privateKey,
        new TextEncoder().encode(`krynodes-network-key\n${node}\n${key}`),
      );
      return Buffer.from(signature).toString("base64url");
    },
  };
}

async function mesh() {
  const harness = await setup();
  const { db } = harness;
  await db.prepare("DELETE FROM nodes WHERE id = 'n1'").run();
  for (const id of [S1, S2, S3, L1]) {
    await db
      .prepare(
        "INSERT INTO nodes (id, name, agent_token_hash, enrolled_at, kind) VALUES (?1, ?2, ?1, ?3, ?4)",
      )
      .bind(id, NAME[id]!, AT, id === L1 ? "laptop" : "server")
      .run();
  }
  const store = async (
    document: ReturnType<typeof documentOf>,
    deleted = false,
  ) => {
    await db
      .prepare(
        "INSERT INTO network_documents (version, signed, hash, created_at) VALUES (?1, ?2, ?3, ?4)",
      )
      .bind(document.version, envelope(document), `h${document.version}`, AT)
      .run();
    await db
      .prepare(
        `INSERT INTO network (id, cidr, port, mtu, version, deleted, created_at)
         VALUES (1, ?1, 51820, 1420, ?2, ?3, ?4)
         ON CONFLICT (id) DO UPDATE SET cidr = excluded.cidr, version = excluded.version,
           deleted = excluded.deleted`,
      )
      .bind(document.range, document.version, deleted ? 1 : 0, AT)
      .run();
  };
  const member = async (
    id: string,
    state: "requested" | "rejected" | "in" | "leaving",
    applied = 0,
    signer = wgKey(NUMBER[id]! + 100),
  ) => {
    await db
      .prepare(
        "INSERT INTO network_members (node_id, state, key, signer, ready, applied, since) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6)",
      )
      .bind(id, state, wgKey(NUMBER[id]!), signer, applied, AT)
      .run();
  };
  const memberRow = (id: string) =>
    db
      .prepare(
        "SELECT state, key, signer, ready, reason, port, mtu, applied, failure, announce_key, announce_signature FROM network_members WHERE node_id = ?",
      )
      .bind(id)
      .first<Record<string, unknown>>();
  const memberWrites = () =>
    harness.writes.filter((sql) => sql.includes("network_members")).length;
  return { ...harness, store, member, memberRow, memberWrites };
}

describe("FleetHub private network", () => {
  it("a member behind by two versions gets both after hello", async () => {
    const { store, member, connect, say } = await mesh();
    const members = [entry(S1), entry(S2)];
    const v2 = documentOf(2, members, { dns: ["10.88.37.10"] });
    const v3 = documentOf(3, members, { mtu: 1400 });
    for (const document of [documentOf(1, members), v2, v3]) {
      await store(document);
    }
    await member(S1, "in", 3);
    await member(S2, "in", 1);
    const ws = connect(S2);
    await say(ws, helloFrom(S2, joining(S2, 1)));
    expect(ws.replies()).toEqual([
      { type: "document", version: 2, signed: envelope(v2) },
      { type: "document", version: 3, signed: envelope(v3) },
      {
        ...noHints,
        endpoints: [{ key: wgKey(1), endpoint: "203.0.113.10:51820" }],
      },
    ]);
  });

  it("a document is pushed again after the hub forgot its memory", async () => {
    const harness = await mesh();
    const members = [entry(S1), entry(S2)];
    const v2 = documentOf(2, members, { mtu: 1400 });
    await harness.store(documentOf(1, members));
    await harness.store(v2);
    await harness.member(S1, "in", 2);
    await harness.member(S2, "in", 1);
    const first = harness.connect(S2);
    await harness.hub.fetch(post("/document", { version: 2 }));
    const pushed = { type: "document", version: 2, signed: envelope(v2) };
    expect(first.replies()).toEqual([pushed]);
    harness.forget();
    const again = harness.connect(S2);
    await harness.say(again, helloFrom(S2, joining(S2, 1)));
    expect(again.replies()[0]).toEqual(pushed);
    const sent = again.sent.length;
    harness.forget();
    await harness.say(again, {
      type: "applied",
      version: 1,
      ok: true,
      message: "Already applied.",
    });
    expect(again.sent).toHaveLength(sent);
  });

  it("a hello that changed nothing writes nothing", async () => {
    const { store, member, memberRow, memberWrites, connect, say, watch } =
      await mesh();
    await store(documentOf(1, [entry(S1)]));
    await member(S1, "in", 1);
    const dashboard = watch();
    const cannot = joining(S3, 0, {
      ready: false,
      reason: "This kernel has no WireGuard.",
    });
    await say(connect(S3), helloFrom(S3, cannot));
    expect(await memberRow(S3)).toMatchObject({
      state: "requested",
      key: wgKey(3),
      signer: wgKey(103),
      ready: 0,
      reason: "This kernel has no WireGuard.",
    });
    expect(memberWrites()).toBe(1);
    expect(dashboard.replies()).toContainEqual({
      type: "changed",
      topics: ["network", "fleet"],
    });
    await say(connect(S3), helloFrom(S3, cannot));
    await say(connect(S1), helloFrom(S1, joining(S1, 1)));
    await say(connect(S1), helloFrom(S1, joining(S1, 1)));
    expect(memberWrites()).toBe(1);
    await say(connect(S3), helloFrom(S3, joining(S3)));
    expect(memberWrites()).toBe(2);
    expect(await memberRow(S3)).toMatchObject({ ready: 1, reason: null });
  });

  it("a rejected machine is not asked again", async () => {
    const { store, member, memberRow, connect, say, db } = await mesh();
    await store(documentOf(1, [entry(S1)]));
    await member(S3, "rejected");
    const ws = connect(S3);
    await say(ws, helloFrom(S3, joining(S3, 0, { key: wgKey(33) })));
    expect(await memberRow(S3)).toMatchObject({
      state: "rejected",
      key: wgKey(33),
    });
    expect(
      await db.prepare("SELECT COUNT(*) AS n FROM network_members").first(),
    ).toEqual({ n: 1 });
    expect(ws.sent).toEqual([]);
  });

  it("links that did not flip write nothing", async () => {
    const { store, member, connect, say, writes, watch, db } = await mesh();
    await store(documentOf(1, [entry(S1), entry(S2), entry(S3)]));
    for (const id of [S1, S2, S3]) await member(id, "in", 1);
    const ws = connect(S1);
    const now = Math.floor(Date.now() / 1000);
    const link = (n: number, answering: boolean, ms: number | null) => ({
      key: wgKey(n),
      handshake: answering ? now - 10 : null,
      rx: 1,
      tx: 1,
      endpoint: null,
      ms,
    });
    const linkWrites = () =>
      writes.filter((sql) => sql.includes("network_links")).length;
    const links = (ms: number) => ({
      type: "links",
      links: [link(2, true, ms), link(3, false, null), link(9, true, 1)],
    });
    await say(ws, links(3.5));
    expect(
      await db
        .prepare("SELECT a, b, answering, ms FROM network_links ORDER BY b")
        .all()
        .then((rows) => rows.results),
    ).toEqual([
      { a: S1, b: S2, answering: 1, ms: 3.5 },
      { a: S1, b: S3, answering: 0, ms: null },
    ]);
    const written = linkWrites();
    const dashboard = watch();
    await say(ws, links(3.5));
    await say(ws, links(3.9));
    expect(linkWrites()).toBe(written);
    expect(dashboard.sent).toEqual([]);
    await say(ws, {
      type: "links",
      links: [link(2, true, 3.5), link(3, true, 12)],
    });
    expect(linkWrites()).toBe(written + 1);
    expect(dashboard.replies()).toEqual([
      { type: "changed", topics: ["network", "fleet"] },
    ]);
  });

  it("an announce reaches online peers only", async () => {
    const { store, member, memberRow, connect, say } = await mesh();
    const signer = await signerOf();
    await store(
      documentOf(1, [
        entry(S1),
        entry(S2, { signer: signer.public }),
        entry(S3),
      ]),
    );
    await member(S1, "in", 1);
    await member(S2, "in", 1, signer.public);
    await member(S3, "in", 1);
    await member(L1, "requested");
    const one = connect(S1);
    const two = connect(S2);
    const stranger = connect(L1);
    const key = wgKey(52);
    await say(two, { type: "announce", key, signature: "c2lnbmF0dXJl" });
    expect(one.sent).toEqual([]);
    expect((await memberRow(S2))?.announce_key).toBeNull();
    const signature = await signer.announce(S2, key);
    await say(two, { type: "announce", key, signature });
    expect(one.replies()).toEqual([
      { ...noHints, announced: [{ node: S2, key, signature }] },
    ]);
    expect(two.sent).toEqual([]);
    expect(stranger.sent).toEqual([]);
    expect(await memberRow(S2)).toMatchObject({
      key: wgKey(2),
      announce_key: key,
      announce_signature: signature,
    });
    await say(two, { type: "announce", key, signature });
    expect(one.sent).toHaveLength(1);
  });

  it("a meet for a stranger is ignored", async () => {
    const harness = await mesh();
    const { store, member, connect, say } = harness;
    await store(
      documentOf(1, [
        entry(S1),
        entry(S2, { nat: true, endpoint: null }),
        entry(L1, {
          kind: "laptop",
          nat: true,
          endpoint: null,
          relay: { [S2]: 51920 },
        }),
      ]),
    );
    for (const id of [S1, S2, L1]) await member(id, "in", 1);
    const laptop = connect(L1);
    const behind = connect(S2);
    const open = connect(S1);
    const stranger = connect(S3);
    await say(laptop, { type: "meet", via: S3 });
    await say(laptop, { type: "meet", via: S2 });
    await say(stranger, { type: "meet", via: S1 });
    await say(behind, { type: "meet", via: S1 });
    for (const ws of [laptop, behind, open, stranger]) {
      expect(ws.sent).toEqual([]);
    }
    await say(laptop, { type: "meet", via: S1 });
    const met = { ...noHints, meetings: [{ laptop: L1, via: S1 }] };
    expect(laptop.replies()).toEqual([{ ...met, connected: [S2] }]);
    expect(behind.replies()).toEqual([met]);
    expect(open.sent).toEqual([]);
    await say(laptop, { type: "meet", via: S1 });
    expect(behind.sent).toHaveLength(1);
    const writes = harness.writes.length;
    const via = await harness.hub.fetch(new Request("https://fleet/via"));
    expect(await via.json()).toEqual({ [L1]: S1 });
    expect(harness.writes.length).toBe(writes);
  });

  it("refresh is sent at most once a minute", async () => {
    const START = Date.parse("2026-11-22T08:00:00.000Z");
    vi.useFakeTimers({ now: START });
    const harness = await mesh();
    await harness.member(S1, "in", 1);
    await harness.member(S2, "in", 1);
    await harness.member(S3, "requested");
    const sockets = [S1, S2, S3].map((id) => harness.connect(id));
    const refresh = () => harness.hub.fetch(post("/refresh", {}));
    expect((await refresh()).status).toBe(204);
    expect(sockets.map((ws) => ws.sent.length)).toEqual([1, 1, 0]);
    expect(sockets[0]!.replies()).toEqual([{ type: "refresh" }]);
    vi.setSystemTime(START + 30_000);
    await refresh();
    harness.forget();
    vi.setSystemTime(START + 59_000);
    await refresh();
    expect(sockets.map((ws) => ws.sent.length)).toEqual([1, 1, 0]);
    vi.setSystemTime(START + 60_000);
    await refresh();
    expect(sockets.map((ws) => ws.sent.length)).toEqual([2, 2, 0]);
  });

  it("a rekey result is written onto a request and taken as an announce from a member", async () => {
    const { db, store, member, memberRow, connect, say } = await mesh();
    const signer = await signerOf();
    await store(
      documentOf(1, [entry(S1), entry(S2, { signer: signer.public })]),
    );
    await member(S1, "in", 1);
    await member(S2, "in", 1, signer.public);
    await member(S3, "requested");
    for (const [id, node] of [
      ["a2", S2],
      ["a3", S3],
    ] as const) {
      await db
        .prepare(
          "INSERT INTO actions (id, node_id, kind, name, action, title, status, created_at) VALUES (?1, ?2, 'network', ?3, 'rekey', 'New Keys', 'sent', ?4)",
        )
        .bind(id, node, NAME[node]!, AT)
        .run();
    }
    const one = connect(S1);
    const rekeyed = (key: string, signerKey: string, signature: string) =>
      JSON.stringify({
        key,
        signer: signerKey,
        fingerprint: "ABCD-ABCD-ABCD-ABCD",
        signature,
      });
    await say(connect(S3), {
      type: "result",
      id: "a3",
      ok: true,
      message: rekeyed(wgKey(53), wgKey(103), "c2ln"),
    });
    expect(await memberRow(S3)).toMatchObject({
      state: "requested",
      key: wgKey(53),
      signer: wgKey(103),
      announce_key: null,
    });
    const key = wgKey(52);
    const signature = await signer.announce(S2, key);
    await say(connect(S2), {
      type: "result",
      id: "a2",
      ok: true,
      message: rekeyed(key, signer.public, signature),
    });
    expect(await memberRow(S2)).toMatchObject({
      key: wgKey(2),
      announce_key: key,
      announce_signature: signature,
    });
    expect(one.replies()).toEqual([
      { ...noHints, announced: [{ node: S2, key, signature }] },
    ]);
  });

  it("a prepare result writes its keys, port and mtu onto the request", async () => {
    const { db, member, memberRow, connect, say } = await mesh();
    await member(S3, "requested");
    for (const id of ["a3", "a4"]) {
      await db
        .prepare(
          "INSERT INTO actions (id, node_id, kind, name, action, title, status, created_at) VALUES (?1, ?2, 'network', 'server-3', 'prepare', 'Prepare', 'sent', ?3)",
        )
        .bind(id, S3, AT)
        .run();
    }
    const ws = connect(S3);
    const prepared = {
      key: wgKey(63),
      signer: wgKey(163),
      port: 51821,
      mtu: 1420,
    };
    await say(ws, {
      type: "result",
      id: "a4",
      ok: false,
      message: JSON.stringify(prepared),
    });
    expect(await memberRow(S3)).toMatchObject({ key: wgKey(3), port: null });
    await say(ws, {
      type: "result",
      id: "a3",
      ok: true,
      message: JSON.stringify(prepared),
    });
    expect(await memberRow(S3)).toMatchObject(prepared);
  });

  it("a failed apply keeps applied and stores its message for the Network page", async () => {
    const { store, member, memberRow, connect, say, watch } = await mesh();
    const members = [entry(S1), entry(S2)];
    await store(documentOf(1, members));
    await store(documentOf(2, members, { mtu: 1400 }));
    await member(S2, "in", 1);
    const ws = connect(S2);
    const dashboard = watch();
    const failed = "the document names another key for server-2";
    await say(ws, { type: "applied", version: 2, ok: false, message: failed });
    expect(await memberRow(S2)).toMatchObject({ applied: 1, failure: failed });
    expect(ws.sent).toEqual([]);
    expect(dashboard.replies()).toEqual([
      { type: "changed", topics: ["network"] },
    ]);
    await say(ws, {
      type: "applied",
      version: 2,
      ok: true,
      message: "Applied version 2.",
    });
    expect(await memberRow(S2)).toMatchObject({ applied: 2, failure: null });
  });

  it("a leaving machine is let go once it applied a document without it", async () => {
    const { store, member, memberRow, connect, say } = await mesh();
    await store(documentOf(1, [entry(S1), entry(S2)]));
    const v2 = documentOf(2, [entry(S1)]);
    await store(v2);
    await member(S1, "in", 2);
    await member(S2, "leaving", 1);
    const ws = connect(S2);
    await say(ws, helloFrom(S2, joining(S2, 1)));
    expect(ws.replies()).toEqual([
      { type: "document", version: 2, signed: envelope(v2) },
    ]);
    await say(ws, {
      type: "applied",
      version: 2,
      ok: true,
      message: "Left the private network.",
    });
    expect(await memberRow(S2)).toBeNull();
    await say(connect(S2), helloFrom(S2, joining(S2, 2, { key: wgKey(42) })));
    expect(await memberRow(S2)).toMatchObject({
      state: "requested",
      key: wgKey(42),
    });
  });

  it("a machine still on a deleted network is walked out of it as a fresh request", async () => {
    const { store, member, memberRow, connect, say } = await mesh();
    await store(documentOf(1, [entry(S1), entry(S2)]));
    const v2 = documentOf(2, [], { deleted: true });
    await store(v2, true);
    const v3 = documentOf(3, [entry(S1, { address: "10.88.38.10" })], {
      range: "10.88.38.0/24",
      parent: "h".repeat(43),
    });
    await store(v3);
    await member(S1, "in", 3);
    const ws = connect(S2);
    await say(ws, helloFrom(S2, joining(S2, 1)));
    expect(await memberRow(S2)).toMatchObject({ state: "requested" });
    expect(ws.replies()).toEqual([
      { type: "document", version: 2, signed: envelope(v2) },
      { type: "document", version: 3, signed: envelope(v3) },
    ]);
    const fresh = connect(S3);
    await say(fresh, helloFrom(S3, joining(S3)));
    expect(fresh.sent).toEqual([]);
  });
});

describe("FleetHub private network, fix round 1", () => {
  const documents = (ws: { replies(): Record<string, unknown>[] }) =>
    ws
      .replies()
      .filter((reply) => reply.type === "document")
      .map((reply) => reply.version);

  it("a member n versions behind gets n documents, a batch of 64 at a time", async () => {
    const { store, member, connect, say } = await mesh();
    const members = [entry(S1), entry(S2)];
    for (let version = 1; version <= 66; version += 1) {
      await store(documentOf(version, members, { mtu: 1280 + version }));
    }
    await member(S1, "in", 66);
    await member(S2, "in", 1);
    const ws = connect(S2);
    await say(ws, helloFrom(S2, joining(S2, 1)));
    const range = (from: number, to: number) =>
      Array.from({ length: to - from + 1 }, (_, index) => from + index);
    expect(documents(ws)).toEqual(range(2, 65));
    const applied = (
      version: number,
      message = `Applied version ${version}.`,
    ) => say(ws, { type: "applied", version, ok: true, message });
    for (let version = 2; version <= 64; version += 1) await applied(version);
    await applied(64, "Already applied.");
    expect(documents(ws)).toEqual(range(2, 65));
    await applied(65);
    expect(documents(ws)).toEqual(range(2, 66));
    await applied(66);
    await applied(66, "Already applied.");
    expect(documents(ws)).toEqual(range(2, 66));
  });

  it("a refused leave keeps the row leaving with its failure", async () => {
    const { store, member, memberRow, connect, say } = await mesh();
    await store(documentOf(1, [entry(S1), entry(S2)]));
    await store(documentOf(2, [entry(S1)]));
    await member(S2, "leaving", 1);
    const refused = "version 2 does not follow the version this server applied";
    await say(connect(S2), {
      type: "applied",
      version: 2,
      ok: false,
      message: refused,
    });
    expect(await memberRow(S2)).toMatchObject({
      state: "leaving",
      applied: 1,
      failure: refused,
    });
  });

  it("a request keeps the version its machine applied, so an approval walks it on", async () => {
    const { db, store, member, memberRow, connect, say, hub } = await mesh();
    await store(documentOf(1, [entry(S1), entry(S2)]));
    const v2 = documentOf(2, [], { deleted: true });
    await store(v2, true);
    await member(S1, "in", 2);
    await say(connect(S2), helloFrom(S2, joining(S2, 1)));
    expect(await memberRow(S2)).toMatchObject({
      state: "requested",
      applied: 1,
    });
    const v3 = documentOf(3, [entry(S1), entry(S2)], {
      parent: "h".repeat(43),
    });
    await store(v3);
    await db
      .prepare("UPDATE network_members SET state = 'in' WHERE node_id = ?")
      .bind(S2)
      .run();
    const ws = connect(S2);
    await hub.fetch(post("/document", { version: 3 }));
    expect(ws.replies()).toEqual([
      { type: "document", version: 2, signed: envelope(v2) },
      { type: "document", version: 3, signed: envelope(v3) },
    ]);
  });

  it("a hello past a failed version clears the failure", async () => {
    const { db, store, member, memberRow, connect, say } = await mesh();
    const members = [entry(S1), entry(S2)];
    await store(documentOf(1, members));
    await store(documentOf(2, members, { mtu: 1400 }));
    await member(S2, "in", 1);
    await db
      .prepare(
        "UPDATE network_members SET failure = 'refused' WHERE node_id = ?",
      )
      .bind(S2)
      .run();
    await say(connect(S2), helloFrom(S2, joining(S2, 2)));
    expect(await memberRow(S2)).toMatchObject({ applied: 2, failure: null });
  });

  it("a hello again on the same socket after leaving is taken like the first", async () => {
    const { store, member, memberRow, memberWrites, connect, say, watch } =
      await mesh();
    await store(documentOf(1, [entry(S1), entry(S2)]));
    await store(documentOf(2, [entry(S1)]));
    await member(S1, "in", 2);
    await member(S2, "leaving", 1);
    const ws = connect(S2);
    await say(ws, {
      type: "applied",
      version: 2,
      ok: true,
      message: "Left the private network.",
    });
    expect(await memberRow(S2)).toBeNull();
    const dashboard = watch();
    const fresh = joining(S2, 2, { key: wgKey(42), signer: wgKey(142) });
    await say(ws, helloFrom(S2, fresh));
    expect(await memberRow(S2)).toMatchObject({
      state: "requested",
      key: wgKey(42),
      signer: wgKey(142),
      applied: 2,
    });
    expect(dashboard.replies()).toContainEqual({
      type: "changed",
      topics: ["network", "fleet"],
    });
    const writes = memberWrites();
    await say(ws, helloFrom(S2, fresh));
    expect(memberWrites()).toBe(writes);
    expect(ws.sent).toEqual([]);
  });

  it("laptops hear who behind NAT is connected in every hints and whenever it changes", async () => {
    const { hub, store, member, memberWrites, connect, say } = await mesh();
    const signer = await signerOf();
    await store(
      documentOf(1, [
        entry(S1),
        entry(S2, { nat: true, endpoint: null, signer: signer.public }),
        entry(L1, {
          kind: "laptop",
          nat: true,
          endpoint: null,
          relay: { [S2]: 51920 },
        }),
      ]),
    );
    for (const id of [S1, L1]) await member(id, "in", 1);
    await member(S2, "in", 1, signer.public);
    const writes = memberWrites();
    const laptop = connect(L1);
    const open = connect(S1);
    await say(open, helloFrom(S1, joining(S1, 1)));
    expect(laptop.sent).toEqual([]);
    open.sent = [];
    const behind = connect(S2);
    await say(behind, helloFrom(S2, joining(S2, 1)));
    expect(laptop.replies()).toEqual([{ ...noHints, connected: [S2] }]);
    expect(open.replies()).toEqual([]);
    expect(memberWrites()).toBe(writes);
    const key = wgKey(52);
    const signature = await signer.announce(S2, key);
    await say(behind, { type: "announce", key, signature });
    expect(laptop.replies().at(-1)).toEqual({
      ...noHints,
      announced: [{ node: S2, key, signature }],
      connected: [S2],
    });
    expect(open.replies().at(-1)).toEqual({
      ...noHints,
      announced: [{ node: S2, key, signature }],
    });
    laptop.sent = [];
    const announced = memberWrites();
    behind.close(1001, "gone");
    await hub.webSocketClose(behind as unknown as WebSocket);
    expect(laptop.replies()).toEqual([noHints]);
    open.close(1001, "gone");
    await hub.webSocketClose(open as unknown as WebSocket);
    expect(laptop.replies()).toEqual([noHints]);
    expect(memberWrites()).toBe(announced);
  });
});
