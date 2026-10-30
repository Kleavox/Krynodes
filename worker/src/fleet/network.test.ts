import type { AgentHeartbeat, NetworkBeat } from "@krynodes/protocol";
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
  agentVersion: "0.7.0",
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

const link = (peer: number, ago: number | null) => ({
  key: key(peer),
  handshake: ago === null ? null : Math.floor(Date.now() / 1000) - ago,
  rx: 1000,
  tx: 2000,
  endpoint: null,
  ms: ago === null ? null : 4,
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
      .prepare("UPDATE nodes SET agent_version = '0.7.0' WHERE id = ?")
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
