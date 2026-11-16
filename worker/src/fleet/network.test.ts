import {
  links,
  type AgentHeartbeat,
  type NetworkBeat,
} from "@krynodes/protocol";
import { describe, expect, it } from "vitest";

import { hubHarness } from "../test/hub";
import { seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";

const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const C = "33333333-3333-4333-8333-333333333333";

const key = (n: number) => Buffer.alloc(32, n).toString("base64");

const SIGNED = {
  grant: {
    grant: "Z3JhbnQ",
    credentialId: "ZGV2aWNlLTE",
    authenticatorData: "YXV0aA",
    clientDataJSON: "Y2xpZW50",
    signature: "c2ln",
  },
  document: "eyJ2IjoxfQ",
  signature: "c2lnbmF0dXJl",
};

const signedOf = (version: number, nodes: string[]) => ({
  ...SIGNED,
  document: Buffer.from(
    JSON.stringify({
      v: 1,
      version,
      range: "10.88.0.0/24",
      port: 51820,
      mtu: 1420,
      members: nodes.map((node, index) => ({
        node,
        name: `vps-${index + 1}`,
        address: `10.88.0.${index + 1}`,
        key: key(index + 1),
        signer: key(index + 101),
        port: 51820,
        mtu: null,
        endpoint: null,
        nat: false,
        psk: Object.fromEntries(
          nodes
            .filter((other) => other !== node)
            .map((other) => [other, "c2VhbGVk"]),
        ),
      })),
      blocked: [],
    }),
  ).toString("base64url"),
});

const beat = (nodeId: string, network: NetworkBeat): AgentHeartbeat => ({
  nodeId,
  hostname: nodeId.slice(0, 4),
  operatingSystem: "linux",
  architecture: "amd64",
  agentVersion: "0.7.20",
  metrics: {
    cpuPercent: 1,
    memoryUsedBytes: 4,
    memoryTotalBytes: 8,
    diskUsedBytes: 1,
    diskTotalBytes: 2,
    load1: 0.1,
    load5: 0.1,
    load15: 0.1,
    uptimeSeconds: 100,
  },
  network,
});

const link = (
  peer: number,
  ago: number | null,
  ms: number | null = ago === null || ago >= 180 ? null : 4,
) => ({
  key: key(peer),
  handshake: ago === null ? null : Math.floor(Date.now() / 1000) - ago,
  rx: 1000,
  tx: 2000,
  endpoint: null,
  ms,
});

function keep(
  sqlite: ReturnType<typeof createTestDb>["sqlite"],
  history: ReturnType<typeof signedOf>[],
) {
  for (const [index, signed] of history.entries()) {
    sqlite
      .prepare(
        "INSERT INTO network_documents (owner_user_id, version, document) VALUES ('standalone', ?, ?)",
      )
      .run(index + 1, JSON.stringify(signed));
  }
  sqlite
    .prepare(
      "UPDATE network SET version = ?, document = ? WHERE owner_user_id = 'standalone'",
    )
    .run(history.length, JSON.stringify(history.at(-1)));
}

function setup() {
  const { db, sqlite } = createTestDb();
  for (const id of [A, B, C]) {
    seedNode(sqlite, { id });
    sqlite
      .prepare("UPDATE nodes SET agent_version = '0.7.20' WHERE id = ?")
      .run(id);
  }
  sqlite
    .prepare(
      `INSERT INTO network (owner_user_id, cidr, port, mtu, version, document, stamp, created_at, created_by)
       VALUES ('standalone', '10.88.0.0/24', 51820, 1420, 2, ?, 's1', 'now', 'owner')`,
    )
    .run(JSON.stringify(SIGNED));
  sqlite.exec(
    `INSERT INTO network_members (node_id, state, address, port, key, signer, endpoint, nat, since) VALUES
     ('${A}', 'in', '10.88.0.1', 51820, '${key(1)}', '${key(101)}', '203.0.113.21:51820', 0, 'now'),
     ('${B}', 'in', '10.88.0.2', 51820, '${key(2)}', '${key(102)}', '203.0.113.22:51820', 0, 'now'),
     ('${C}', 'waiting', NULL, 51820, '${key(3)}', '${key(103)}', NULL, 0, 'now')`,
  );
  const harness = hubHarness({ DB: db });
  const send = async (
    ws: Awaited<ReturnType<typeof harness.connect>>,
    nodeId: string,
    network: NetworkBeat,
  ) =>
    (
      (await harness.request(ws, "heartbeat", {
        heartbeat: beat(nodeId, network),
      })) as { response: { network?: Record<string, unknown> } }
    ).response.network;
  const writes = () =>
    (sqlite.prepare("SELECT total_changes() AS n").get() as { n: number }).n;
  return { ...harness, sqlite, send, writes };
}

describe("the network on the heartbeat", () => {
  it("gives the document only to an agent with an older version", async () => {
    const { connect, send } = setup();
    const ws = await connect(A);
    expect(
      (await send(ws, A, { version: 1, key: key(1), links: [] }))?.document,
    ).toEqual(SIGNED);
    expect(
      (await send(ws, A, { version: 2, key: key(1), links: [] }))?.document,
    ).toBeUndefined();
  });

  it("walks a lagging member one version at a time", async () => {
    const { connect, send, sqlite } = setup();
    const history = [
      signedOf(1, [A, B]),
      signedOf(2, [A, B]),
      signedOf(3, [A, B]),
    ];
    keep(sqlite, history);
    const ws = await connect(A);
    expect(
      (await send(ws, A, { version: 1, key: key(1), links: [] }))?.document,
    ).toEqual(history[1]);
    expect(
      (await send(ws, A, { version: 2, key: key(1), links: [] }))?.document,
    ).toEqual(history[2]);
  });

  it("gives the latest to a server that was not a member of the version it reports", async () => {
    const { connect, send, sqlite } = setup();
    const history = [signedOf(1, [B]), signedOf(2, [B]), signedOf(3, [A, B])];
    keep(sqlite, history);
    const ws = await connect(A);
    expect(
      (await send(ws, A, { version: 1, key: key(1), links: [] }))?.document,
    ).toEqual(history[2]);
  });

  it("writes a pair's state once each time it flips", async () => {
    const { connect, send, sqlite, writes } = setup();
    const ws = await connect(A);
    await send(ws, A, { version: 2, key: key(1), links: [link(2, 10)] });
    expect(
      sqlite.prepare("SELECT a, b, answering FROM network_links").all(),
    ).toEqual([{ a: A, b: B, answering: 1 }]);
    const before = writes();
    await send(ws, A, { version: 2, key: key(1), links: [link(2, 30)] });
    expect(writes()).toBe(before);
    await send(ws, A, { version: 2, key: key(1), links: [link(2, 400)] });
    expect(sqlite.prepare("SELECT answering FROM network_links").all()).toEqual(
      [{ answering: 0 }],
    );
    expect(writes()).toBe(before + 1);
  });

  it("keeps a pair answering while its ping answers, though its handshake was read late", async () => {
    const { connect, send, sqlite, writes } = setup();
    const ws = await connect(A);
    await send(ws, A, { version: 2, key: key(1), links: [link(2, 10)] });
    const before = writes();
    await send(ws, A, { version: 2, key: key(1), links: [link(2, 190, 4)] });
    expect(sqlite.prepare("SELECT answering FROM network_links").all()).toEqual(
      [{ answering: 1 }],
    );
    expect(writes()).toBe(before);
  });

  it("keeps links out of the stored beat and serves the latest", async () => {
    const { connect, send, hub } = setup();
    const ws = await connect(A);
    const links = [link(2, 10)];
    await send(ws, A, { version: 2, key: key(1), links });
    expect(
      (ws.deserializeAttachment() as { beat: Record<string, unknown> }).beat,
    ).not.toHaveProperty("network");
    const served = (await (
      await hub.fetch(new Request("https://fleet/network"))
    ).json()) as Record<string, { links: unknown[] }>;
    expect(served[A]?.links).toEqual(links);
  });

  it("sends the others' endpoints once and their new keys while pending", async () => {
    const { connect, send } = setup();
    const a = await connect(A);
    const b = await connect(B);
    expect(
      (await send(a, A, { version: 2, key: key(1), links: [] }))?.endpoints,
    ).toEqual([{ key: key(2), endpoint: "203.0.113.22:51820" }]);
    expect(
      (await send(a, A, { version: 2, key: key(1), links: [] }))?.endpoints,
    ).toBeUndefined();
    await send(b, B, {
      version: 2,
      key: key(12),
      links: [],
      announce: { key: key(12), signature: "c2lnbmVk" },
    });
    expect(
      (await send(a, A, { version: 2, key: key(1), links: [] }))?.announced,
    ).toEqual([{ node: B, key: key(12), signature: "c2lnbmVk" }]);
  });

  it("forgets a server that left once it reports no key", async () => {
    const { connect, send, sqlite } = setup();
    sqlite.exec(
      `UPDATE network_members SET state = 'leaving' WHERE node_id = '${B}'`,
    );
    const ws = await connect(B);
    await send(ws, B, { version: 2, key: key(2), links: [] });
    expect(
      sqlite
        .prepare("SELECT state FROM network_members WHERE node_id = ?")
        .get(B),
    ).toEqual({ state: "leaving" });
    await send(ws, B, { version: 2, key: null, links: [] });
    expect(
      sqlite
        .prepare("SELECT state FROM network_members WHERE node_id = ?")
        .get(B),
    ).toBeUndefined();
  });
});

describe("laptops on the hub", () => {
  const L = "44444444-4444-4444-8444-444444444444";

  interface Entry {
    node: string;
    name: string;
    address: string;
    key: string;
    signer: string;
    port: number;
    mtu: null;
    endpoint: string | null;
    nat: boolean;
    psk: Record<string, string>;
    kind?: "laptop";
    cut?: true;
  }

  const entry = (node: string, n: number, extra: Partial<Entry> = {}) => ({
    node,
    name: `server-${n}`,
    address: `10.88.0.${n}`,
    key: key(n),
    signer: key(n + 100),
    port: 51820,
    mtu: null,
    endpoint: `203.0.113.${n}:51820`,
    nat: false,
    psk: {},
    ...extra,
  });

  const signedWith = (members: Entry[]) => ({
    ...SIGNED,
    document: Buffer.from(
      JSON.stringify({
        v: 1,
        version: 2,
        range: "10.88.0.0/24",
        port: 51820,
        mtu: 1420,
        members: members.map((one) => ({
          ...one,
          psk: Object.fromEntries(
            members
              .filter((other) => other !== one && links(one, other))
              .map((other) => [other.node, "c2VhbGVk"]),
          ),
        })),
        blocked: [],
      }),
    ).toString("base64url"),
  });

  function laptopSetup(cut = false) {
    const { db, sqlite } = createTestDb();
    for (const id of [A, B, L]) {
      seedNode(sqlite, { id });
      sqlite
        .prepare("UPDATE nodes SET agent_version = '0.7.24' WHERE id = ?")
        .run(id);
    }
    sqlite.prepare("UPDATE nodes SET kind = 'laptop' WHERE id = ?").run(L);
    const document = signedWith([
      entry(A, 1),
      entry(B, 2, { endpoint: null, nat: true }),
      entry(L, 3, {
        endpoint: null,
        nat: true,
        kind: "laptop",
        ...(cut ? { cut: true as const } : {}),
      }),
    ]);
    sqlite
      .prepare(
        `INSERT INTO network (owner_user_id, cidr, port, mtu, version, document, stamp, created_at, created_by)
         VALUES ('standalone', '10.88.0.0/24', 51820, 1420, 2, ?, 's1', 'now', 'owner')`,
      )
      .run(JSON.stringify(document));
    sqlite.exec(
      `INSERT INTO network_members (node_id, state, address, port, key, signer, endpoint, nat, since) VALUES
       ('${A}', 'in', '10.88.0.1', 51820, '${key(1)}', '${key(101)}', '203.0.113.1:51820', 0, 'now'),
       ('${B}', 'in', '10.88.0.2', 51820, '${key(2)}', '${key(102)}', NULL, 1, 'now'),
       ('${L}', 'in', '10.88.0.3', 51820, '${key(3)}', '${key(103)}', NULL, 1, 'now')`,
    );
    let calls = 0;
    const counted = (statement: D1PreparedStatement): D1PreparedStatement =>
      ({
        ...statement,
        bind: (...values: unknown[]) => counted(statement.bind(...values)),
        run: () => {
          calls += 1;
          return statement.run();
        },
      }) as unknown as D1PreparedStatement;
    const watched = {
      prepare: (sql: string) => counted(db.prepare(sql)),
      batch: (statements: D1PreparedStatement[]) => {
        calls += 1;
        return db.batch(statements);
      },
    } as unknown as D1Database;
    const harness = hubHarness({ DB: watched });
    const send = async (
      ws: Awaited<ReturnType<typeof harness.connect>>,
      nodeId: string,
      network: NetworkBeat,
    ) =>
      (
        (await harness.request(ws, "heartbeat", {
          heartbeat: { ...beat(nodeId, network), agentVersion: "0.7.24" },
        })) as { response: { network?: Record<string, unknown> } }
      ).response.network;
    const laptop = () => harness.connect(L, "standalone", 60, true);
    return { ...harness, sqlite, send, laptop, calls: () => calls };
  }

  const at = (meet?: string): NetworkBeat => ({
    version: 2,
    key: key(3),
    links: [link(1, 10)],
    ...(meet ? { meet } : {}),
  });
  const quiet = (n: number): NetworkBeat => ({
    version: 2,
    key: key(n),
    links: [],
  });
  const pokes = (ws: { replies: () => Record<string, unknown>[] }) =>
    ws.replies().filter((reply) => reply.type === "poke").length;

  it("a laptop's meeting point reaches the NAT members and costs no D1 write", async () => {
    const { connect, send, laptop, calls, sqlite } = laptopSetup();
    const nat = await connect(B);
    const l = await laptop();
    expect((await send(nat, B, quiet(2)))?.meetings).toBeUndefined();
    await send(l, L, at());
    const before = calls();
    await send(l, L, at(A));
    expect(calls()).toBe(before);
    expect(pokes(nat)).toBe(1);
    expect((await send(nat, B, quiet(2)))?.meetings).toEqual([
      { laptop: L, via: A },
    ]);
    expect((await send(nat, B, quiet(2)))?.meetings).toBeUndefined();
    const again = calls();
    await send(l, L, at(A));
    expect(pokes(nat)).toBe(1);
    expect(calls()).toBe(again);
    expect(sqlite.prepare("SELECT * FROM network_links").all()).toEqual([]);
    expect(
      sqlite.prepare("SELECT last_seen_at FROM nodes WHERE id = ?").get(L),
    ).toEqual({ last_seen_at: null });
  });

  it("ignores a meeting point that is no public server of the network", async () => {
    const { connect, send, laptop } = laptopSetup();
    const nat = await connect(B);
    const l = await laptop();
    await send(l, L, at(B));
    await send(l, L, at(L));
    await send(l, L, at(C));
    expect(pokes(nat)).toBe(0);
    expect((await send(nat, B, quiet(2)))?.meetings).toBeUndefined();
  });

  it("takes no meeting point from a server, nor for a laptop that is cut", async () => {
    const server = laptopSetup();
    const nat = await server.connect(B);
    const a = await server.connect(A);
    await server.send(a, A, { ...quiet(1), meet: A });
    expect(pokes(nat)).toBe(0);
    const cut = laptopSetup(true);
    const natOfCut = await cut.connect(B);
    await cut.send(await cut.laptop(), L, at(A));
    expect(pokes(natOfCut)).toBe(0);
    expect((await cut.send(natOfCut, B, quiet(2)))?.meetings).toBeUndefined();
  });

  it("a laptop's reply lists held servers", async () => {
    const { send, laptop, connect, sqlite } = laptopSetup();
    const l = await laptop();
    expect((await send(l, L, at()))?.held).toEqual([]);
    expect((await send(l, L, at()))?.held).toBeUndefined();
    sqlite.exec(
      `INSERT INTO quarantines (id, node_id, why, at, timeline) VALUES ('q1', '${A}', 'test', 'now', '{}')`,
    );
    expect((await send(l, L, at()))?.held).toEqual([A]);
    expect((await send(l, L, at()))?.held).toBeUndefined();
    sqlite.exec("UPDATE quarantines SET released_at = 'later'");
    expect((await send(l, L, at()))?.held).toEqual([]);
    const nat = await connect(B);
    expect((await send(nat, B, quiet(2)))?.held).toBeUndefined();
  });

  it("pokes the connected laptops when a hold starts or ends, without a D1 write", async () => {
    const { send, laptop, connect, hub, sqlite, calls } = laptopSetup();
    const l = await laptop();
    const nat = await connect(B);
    const poke = (nodeIds: string[]) =>
      hub.fetch(
        new Request("https://fleet/poke", {
          method: "POST",
          body: JSON.stringify({ nodeIds }),
        }),
      );
    expect((await send(l, L, at()))?.held).toEqual([]);
    await poke([A]);
    const settled = pokes(l);
    await poke([A]);
    expect(pokes(l)).toBe(settled);
    sqlite.exec(
      `INSERT INTO quarantines (id, node_id, why, at, timeline) VALUES ('q1', '${A}', 'test', 'now', '{}')`,
    );
    const before = calls();
    await poke([A]);
    expect(calls()).toBe(before);
    expect(pokes(l)).toBe(settled + 1);
    expect(pokes(nat)).toBe(0);
    expect((await send(l, L, at()))?.held).toEqual([A]);
    sqlite.exec("UPDATE quarantines SET released_at = 'later'");
    await poke([A]);
    expect(pokes(l)).toBe(settled + 2);
    expect((await send(l, L, at()))?.held).toEqual([]);
  });

  it("a warning's cut-off reaches the connected laptops at once", async () => {
    const { send, laptop, hub, sqlite, storage } = laptopSetup();
    const l = await laptop();
    expect((await send(l, L, at()))?.held).toEqual([]);
    await hub.fetch(
      new Request("https://fleet/poke", {
        method: "POST",
        body: JSON.stringify({ nodeIds: [A] }),
      }),
    );
    const settled = pokes(l);
    const cut = Date.now() - 1_000;
    sqlite
      .prepare(
        "INSERT INTO warnings (node_id, id, kind, detail, at, cut_at) VALUES (?, 'w1', 'port', '{}', ?, ?)",
      )
      .run(A, new Date(cut).toISOString(), new Date(cut).toISOString());
    await storage.put("cutoffs", { [`${A}|w1`]: cut });
    await hub.alarm();
    expect(sqlite.prepare("SELECT node_id FROM quarantines").all()).toEqual([
      { node_id: A },
    ]);
    expect(pokes(l)).toBe(settled + 1);
    expect((await send(l, L, at()))?.held).toEqual([A]);
  });

  it("never watches a laptop for silence and writes when it was last seen as it leaves", async () => {
    const { send, laptop, hub, sqlite, storage } = laptopSetup();
    const l = await laptop();
    await send(l, L, at());
    expect(Object.keys((await storage.get("roster")) ?? {})).not.toContain(L);
    await hub.webSocketClose(l as unknown as WebSocket);
    expect(
      (
        sqlite
          .prepare("SELECT last_seen_at FROM nodes WHERE id = ?")
          .get(L) as {
          last_seen_at: string | null;
        }
      ).last_seen_at,
    ).not.toBeNull();
  });

  it("keeps the network version each laptop last asked with, written only when it moves", async () => {
    const { send, laptop, connect, sqlite, calls } = laptopSetup();
    const applied = (id: string) =>
      sqlite
        .prepare("SELECT applied FROM network_members WHERE node_id = ?")
        .get(id);
    expect(applied(L)).toEqual({ applied: null });
    const l = await laptop();
    await send(l, L, { ...at(), version: 1 });
    expect(applied(L)).toEqual({ applied: 1 });
    const before = calls();
    await send(l, L, { ...at(), version: 1 });
    expect(calls()).toBe(before);
    await send(l, L, at());
    expect(applied(L)).toEqual({ applied: 2 });
    await send(await connect(B), B, quiet(2));
    expect(applied(B)).toEqual({ applied: null });
  });

  it("hands a laptop its trust change and writes its version only when it moves", async () => {
    const { request, laptop, sqlite } = laptopSetup();
    const now = new Date().toISOString();
    sqlite
      .prepare(
        `INSERT INTO actions (id, batch_id, position, mode, node_id, kind, name, action,
           status, requested_by, requested_at, deliverable_at, signed)
         VALUES ('t1', 'b1', 0, 'parallel', ?, 'trust', 'devices', 'trust', 'queued',
           'user1@example.com', ?, ?, '{"change":"Y2hhbmdl","approvals":[]}')`,
      )
      .run(L, now, now);
    const l = await laptop();
    const answer = (await request(l, "heartbeat", {
      heartbeat: { ...beat(L, at()), agentVersion: "0.7.25" },
    })) as { response: { actions?: { id: string }[] } };
    expect(answer.response.actions?.map((action) => action.id)).toEqual(["t1"]);
    expect(
      sqlite
        .prepare("SELECT agent_version, last_seen_at FROM nodes WHERE id = ?")
        .get(L),
    ).toMatchObject({ agent_version: "0.7.25" });
    expect(
      sqlite.prepare("SELECT COUNT(*) AS n FROM node_windows").get(),
    ).toEqual({ n: 0 });
  });
});
