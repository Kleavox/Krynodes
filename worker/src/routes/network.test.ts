import type { AgentActionsRequest } from "@krynodes/protocol";
import { describe, expect, it } from "vitest";

import { receiveReport } from "../actions/report";
import type { AgentNode } from "../agent/ingest";
import { app } from "../app";
import type { Env } from "../env";
import { seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";

const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const C = "33333333-3333-4333-8333-333333333333";
const D = "66666666-6666-4666-8666-666666666666";
const OLD = "44444444-4444-4444-8444-444444444444";
const FOREIGN = "55555555-5555-4555-8555-555555555555";
const NOW = Date.parse("2026-10-26T09:00:00.000Z");

const NAMES: Record<string, string> = {
  [A]: "vps-1",
  [B]: "vps-2",
  [C]: "vps-3",
  [D]: "vps-4",
  [OLD]: "old",
  [FOREIGN]: "theirs",
};

const key = (n: number) => Buffer.alloc(32, n).toString("base64");
const b64 = (value: unknown) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

const grant = {
  grant: "Z3JhbnQ",
  credentialId: "ZGV2aWNlLTE",
  authenticatorData: Buffer.from(
    Uint8Array.from({ length: 37 }, (_, index) => (index === 32 ? 5 : 0)),
  ).toString("base64url"),
  clientDataJSON: "Y2xpZW50",
  signature: "c2ln",
};

const KEYS: Record<string, number> = {
  [A]: 1,
  [B]: 2,
  [C]: 3,
  [D]: 4,
  [OLD]: 5,
  [FOREIGN]: 6,
};

const member = (node: string, address: string) => ({
  node,
  name: NAMES[node]!,
  address,
  key: key(KEYS[node]!),
  signer: key(KEYS[node]! + 100),
  port: 51820,
  mtu: null,
  endpoint: null,
  nat: false,
  psk: {} as Record<string, string>,
});

type Member = ReturnType<typeof member>;

function documentOf(
  version: number,
  members: Member[],
  over: Record<string, unknown> = {},
) {
  const nodes = members.map((entry) => entry.node);
  return {
    v: 1,
    version,
    range: "10.88.0.0/24",
    port: 51820,
    mtu: 1420,
    members: members.map((entry) => ({
      ...entry,
      psk: Object.fromEntries(
        nodes
          .filter((node) => node !== entry.node)
          .map((node) => [node, "c2VhbGVk"]),
      ),
    })),
    blocked: [] as string[],
    ...over,
  };
}

const signedFor = (target: Record<string, string>) => ({
  grant,
  command: b64({ v: 1, ...target }),
  signature: "c2lnbmF0dXJl",
});

function setup() {
  const { db, sqlite } = createTestDb();
  for (const [id, version, owner] of [
    [A, "0.7.0", undefined],
    [B, "0.7.0", undefined],
    [C, "0.7.0", undefined],
    [D, "0.7.0", undefined],
    [OLD, "0.6.14", undefined],
    [FOREIGN, "0.7.0", "someone-else"],
  ] as const) {
    seedNode(sqlite, { id, owner });
    sqlite
      .prepare(
        "UPDATE nodes SET name = ?, agent_version = ?, last_seen_at = datetime('now') WHERE id = ?",
      )
      .run(NAMES[id]!, version, id);
  }
  const env = {
    DB: db,
    PUBLIC_ORIGIN: "https://kry.example.test",
  } as unknown as Env;
  const call = (method: string, path: string, body?: unknown) =>
    app.request(
      `https://kry.example.test${path}`,
      {
        method,
        headers: { "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      },
      env,
    );
  const post = (
    document: unknown,
    change = "Change the private network",
    detail: string | null = null,
  ) =>
    call("POST", "/api/network/document", {
      signed: { grant, document: b64(document), signature: "c2lnbmF0dXJl" },
      change,
      detail,
    });
  const network = async () =>
    (await (await call("GET", "/api/network")).json()) as Record<
      string,
      unknown
    > & {
      members: Record<string, unknown>[];
      waiting: Record<string, unknown>[];
      held: Record<string, unknown>[];
      changes: Record<string, unknown>[];
    };
  const inventory = (
    id: string,
    extra: Partial<NonNullable<AgentActionsRequest["inventory"]>>,
    hash = "a",
  ) =>
    receiveReport(
      db,
      {
        id,
        inventory_hash: null,
        refresh_requested_at: null,
        security: null,
      } as unknown as AgentNode,
      {
        nodeId: id,
        inventory: { hash: hash.repeat(64), services: [], ...extra },
      },
      NOW,
    );
  const change = (nodeId: string, action: string) => {
    const target = {
      id: crypto.randomUUID(),
      nodeId,
      kind: "network",
      name: "kry0",
    };
    return call("POST", "/api/actions", {
      action,
      targets: [{ ...target, signed: signedFor({ ...target, action }) }],
    });
  };
  const ask = (nodeId: string, action: string, args: Record<string, string>) =>
    call("POST", "/api/actions", {
      action,
      targets: [{ nodeId, kind: "network", name: "kry0", args }],
    });
  return { db, sqlite, call, post, network, inventory, change, ask };
}

const json = async (response: Response | Promise<Response>) =>
  (await (await response).json()) as Record<string, unknown>;

describe("the network document", () => {
  it("takes the first version and then only the next one", async () => {
    const { post, network } = setup();
    const first = documentOf(1, [
      member(A, "10.88.0.1"),
      member(B, "10.88.0.2"),
    ]);
    const created = await post(
      first,
      "Create the private network with vps-1 and vps-2",
    );
    expect(created.status).toBe(200);
    const read = await network();
    expect(read.network).toMatchObject({
      range: "10.88.0.0/24",
      port: 51820,
      mtu: 1420,
      version: 1,
    });
    expect(read.document).toEqual(first);
    expect(
      read.members.map((entry) => [entry.nodeId, entry.address, entry.state]),
    ).toEqual([
      [A, "10.88.0.1", "in"],
      [B, "10.88.0.2", "in"],
    ]);
    expect(read.changes).toMatchObject([
      { change: "Create the private network with vps-1 and vps-2" },
    ]);
    for (const version of [1, 3]) {
      const refused = await post({ ...first, version });
      expect(refused.status).toBe(409);
      expect(await json(refused)).toEqual({
        code: "VERSION_NOT_NEXT",
        message: "Someone changed the network meanwhile. Open it again.",
      });
    }
    const next = documentOf(2, [
      member(A, "10.88.0.1"),
      member(B, "10.88.0.2"),
      member(C, "10.88.0.3"),
    ]);
    expect((await post(next, "Add vps-3 to the private network")).status).toBe(
      200,
    );
    expect((await network()).network).toMatchObject({ version: 2 });
  });

  it("refuses an old agent, a foreign server, a bad document, and a changed range, port or address", async () => {
    const { post } = setup();
    const old = await post(
      documentOf(1, [member(A, "10.88.0.1"), member(OLD, "10.88.0.2")]),
    );
    expect(old.status).toBe(422);
    expect(await json(old)).toEqual({
      code: "AGENT_TOO_OLD",
      message: "Update the agent on old to 0.7.0 or newer.",
    });
    expect(
      (
        await post(
          documentOf(1, [member(A, "10.88.0.1"), member(FOREIGN, "10.88.0.2")]),
        )
      ).status,
    ).toBe(404);
    expect(
      (
        await post({
          ...documentOf(1, [member(A, "10.88.0.1")]),
          members: [{ ...member(A, "10.88.0.1"), address: "10.0.0.1" }],
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await post(
          documentOf(1, [member(A, "10.88.0.1"), member(B, "10.88.0.2")]),
        )
      ).status,
    ).toBe(200);
    for (const changed of [
      documentOf(2, [member(A, "10.88.0.1"), member(B, "10.88.0.2")], {
        port: 51821,
      }),
      documentOf(
        2,
        [{ ...member(A, "10.88.1.1") }, { ...member(B, "10.88.1.2") }],
        { range: "10.88.1.0/24" },
      ),
      documentOf(2, [member(A, "10.88.0.1"), member(B, "10.88.0.7")]),
    ]) {
      const refused = await post(changed);
      expect(refused.status).toBe(422);
      expect((await json(refused)).code).toBe("NETWORK_FIXED");
    }
  });

  it("hands out never-used addresses first, freed ones last, and never a held one", async () => {
    const { post, network, inventory, call } = setup();
    await post(
      documentOf(1, [
        member(A, "10.88.0.1"),
        member(B, "10.88.0.2"),
        member(C, "10.88.0.3"),
      ]),
    );
    await inventory(A, {
      network: { points: [{ stack: "backup", target: "vps-3.kry" }] },
    });
    await post(
      documentOf(2, [member(A, "10.88.0.1"), member(B, "10.88.0.2")], {
        blocked: [key(3)],
      }),
      "Remove vps-3 from the private network",
    );
    await post(
      documentOf(3, [member(A, "10.88.0.1")], { blocked: [key(3), key(2)] }),
    );
    const read = await network();
    expect(read.held).toEqual([
      {
        address: "10.88.0.3",
        nodeId: C,
        nodeName: "vps-3",
        points: [{ nodeId: A, stack: "backup", target: "vps-3.kry" }],
      },
    ]);
    expect(read.members[0]).toMatchObject({
      points: [{ stack: "backup", target: "vps-3.kry" }],
    });
    expect(read.members.map((entry) => [entry.nodeId, entry.state])).toEqual([
      [A, "in"],
      [B, "leaving"],
      [C, "leaving"],
    ]);
    expect(await json(call("GET", `/api/network/next?nodes=${D}`))).toEqual({
      addresses: [{ nodeId: D, address: "10.88.0.4", name: "vps-4.kry" }],
      held: [
        {
          address: "10.88.0.3",
          nodeName: "vps-3",
          points: [{ nodeId: A, stack: "backup", target: "vps-3.kry" }],
        },
      ],
    });
    for (const address of ["10.88.0.2", "10.88.0.3"]) {
      const refused = await post(
        documentOf(4, [member(A, "10.88.0.1"), member(D, address)]),
      );
      expect(refused.status).toBe(422);
      expect((await json(refused)).code).toBe("ADDRESS_NOT_NEXT");
    }
    expect(
      (
        await post(
          documentOf(4, [member(A, "10.88.0.1"), member(D, "10.88.0.4")]),
        )
      ).status,
    ).toBe(200);
    await inventory(A, { network: { points: [] } }, "b");
    expect((await network()).held).toEqual([]);
    const next = await json(call("GET", `/api/network/next?nodes=${B},${C}`));
    expect(next.addresses).toEqual([
      { nodeId: B, address: "10.88.0.5", name: "vps-2.kry" },
      { nodeId: C, address: "10.88.0.6", name: "vps-3.kry" },
    ]);
  });

  it("deletes the network, lets every address go, and a new one continues the versions", async () => {
    const { post, network, call } = setup();
    await post(documentOf(1, [member(A, "10.88.0.1"), member(B, "10.88.0.2")]));
    expect(await json(call("GET", "/api/settings/private-ranges"))).toEqual({
      ranges: [],
      network: "10.88.0.0/24",
    });
    const deleted = documentOf(2, [], { deleted: true });
    expect((await post(deleted, "Delete the private network")).status).toBe(
      200,
    );
    const read = await network();
    expect(read.network).toBeNull();
    expect(read.version).toBe(2);
    expect(read.held).toEqual([]);
    expect(read.members.map((entry) => entry.state)).toEqual([
      "leaving",
      "leaving",
    ]);
    expect(await json(call("GET", "/api/settings/private-ranges"))).toEqual({
      ranges: [],
      network: null,
    });
    const again = documentOf(3, [{ ...member(A, "10.88.5.1") }], {
      range: "10.88.5.0/24",
    });
    expect((await post(again)).status).toBe(200);
    expect((await network()).network).toMatchObject({
      range: "10.88.5.0/24",
      version: 3,
    });
  });
});

describe("servers getting ready", () => {
  it("wait to join while they report a prepared key, and stop waiting after Not Now", async () => {
    const { inventory, network } = setup();
    await inventory(D, {
      network: {
        prepared: { key: key(4), signer: key(104), port: 51821, mtu: 1500 },
        points: [],
      },
    });
    expect((await network()).waiting).toMatchObject([
      {
        nodeId: D,
        name: "vps-4",
        key: key(4),
        signer: key(104),
        port: 51821,
        mtu: 1500,
      },
    ]);
    await inventory(D, {}, "b");
    expect((await network()).waiting).toEqual([]);
  });
});

describe("network actions", () => {
  it("are refused below 0.7.0 and read beside a pending change", async () => {
    const { change, ask } = setup();
    const old = await change(OLD, "prepare");
    expect(old.status).toBe(422);
    expect(await json(old)).toEqual({
      code: "AGENT_TOO_OLD",
      message: "Update the agent on old to 0.7.0 or newer.",
    });
    expect((await ask(OLD, "inspect", {})).status).toBe(422);
    expect((await change(A, "prepare")).status).toBe(201);
    expect((await change(A, "rekey")).status).toBe(409);
    expect((await ask(A, "inspect", {})).status).toBe(201);
    expect((await ask(A, "inspect", {})).status).toBe(201);
    const peers = Array.from(
      { length: 17 },
      (_, index) => `10.0.0.${index + 1}:51820`,
    ).join(" ");
    expect((await ask(A, "probe", { port: "51820", peers })).status).toBe(400);
    expect(
      (await ask(A, "probe", { port: "51820", peers: "141.95.0.21:51820" }))
        .status,
    ).toBe(201);
    expect(
      (await ask(A, "test", { peer: B, address: "10.88.0.2", mtu: "1420" }))
        .status,
    ).toBe(201);
  });
});

describe("network changes", () => {
  it("show in History, are found by Search, and name the servers that joined and left", async () => {
    const { post, call } = setup();
    await post(
      documentOf(1, [member(A, "10.88.0.1"), member(B, "10.88.0.2")]),
      "Create the private network with vps-1 and vps-2",
      "Addresses 10.88.0.0/24 · Port 51820/udp",
    );
    await post(
      documentOf(2, [member(A, "10.88.0.1")], { blocked: [key(2)] }),
      "Remove vps-2 from the private network",
    );
    expect(
      (
        await call("POST", "/api/network/tests", {
          change: "Test vps-1 ↔ vps-2",
          detail: "Large packets lost · Use 1380 was offered",
          nodes: [A, B],
        })
      ).status,
    ).toBe(201);
    const history = await json(call("GET", "/api/history"));
    expect(
      (history.entries as { type: string; change?: { change: string } }[])
        .filter((entry) => entry.type === "network")
        .map((entry) => entry.change!.change),
    ).toEqual([
      "Test vps-1 ↔ vps-2",
      "Remove vps-2 from the private network",
      "Create the private network with vps-1 and vps-2",
    ]);
    const found = await json(call("GET", "/api/history?q=1380"));
    expect(
      (found.entries as { type: string }[]).map((entry) => entry.type),
    ).toEqual(["network"]);
    const own = await json(call("GET", `/api/nodes/${B}/actions`));
    expect(
      (own.network as { change: string }[]).map((entry) => entry.change),
    ).toEqual(["Left Private Network", "Joined Private Network"]);
    expect(
      (
        (await json(call("GET", `/api/history?node=${A}`))).entries as {
          type: string;
        }[]
      ).filter((entry) => entry.type === "network"),
    ).toHaveLength(3);
  });
});

describe("Delete Node", () => {
  it("is refused while the server is in the network", async () => {
    const { post, call } = setup();
    await post(documentOf(1, [member(A, "10.88.0.1"), member(B, "10.88.0.2")]));
    const refused = await call("DELETE", `/api/nodes/${A}`);
    expect(refused.status).toBe(409);
    expect(await json(refused)).toEqual({
      code: "NETWORK_MEMBER",
      message: "Remove vps-1 from the private network first.",
    });
  });
});
