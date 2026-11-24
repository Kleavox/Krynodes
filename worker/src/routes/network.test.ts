import { documentHash } from "@krynodes/protocol";
import { beforeAll, describe, expect, it } from "vitest";

import { addNode, ORIGIN, testEnv } from "../test/env";
import { signDocument, testPasskey, type TestPasskey } from "../test/passkeys";

const S1 = "11111111-1111-4111-8111-111111111111";
const S2 = "22222222-2222-4222-8222-222222222222";
const S3 = "44444444-4444-4444-8444-444444444444";
const L1 = "33333333-3333-4333-8333-333333333333";
const RANGE = "10.88.37.0/24";
const AT = "2026-11-22T00:00:00.000Z";

const encoder = new TextEncoder();
const wgKey = (n: number) => Buffer.alloc(32, n).toString("base64");
const sealKey = (n: number) => Buffer.alloc(65, n).toString("base64url");
const SEALED = "c2VhbGVkLXByZXNoYXJlZA";

const NUMBER: Record<string, number> = { [S1]: 1, [S2]: 2, [S3]: 3, [L1]: 4 };
const NAME: Record<string, string> = {
  [S1]: "server-1",
  [S2]: "server-2",
  [S3]: "server-3",
  [L1]: "laptop-1",
};

let passkey: TestPasskey;
let session: CryptoKeyPair;

beforeAll(async () => {
  passkey = await testPasskey("pk1");
  session = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
});

async function machine(
  db: D1Database,
  id: string,
  options: {
    kind?: "server" | "laptop";
    state?: "requested" | "rejected" | "in" | "leaving" | null;
    ready?: boolean;
    reason?: string | null;
    key?: string;
  } = {},
) {
  const n = NUMBER[id]!;
  await addNode(db, id, NAME[id]!, "0.7.92");
  await db
    .prepare(
      "UPDATE nodes SET kind = ?1, seal_key = ?2, hostname = ?3, os = 'linux' WHERE id = ?4",
    )
    .bind(options.kind ?? "server", sealKey(n), `vps-${n}`, id)
    .run();
  if (options.state === null) return;
  await db
    .prepare(
      "INSERT INTO network_members (node_id, state, key, signer, ready, reason, port, since) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 51820, ?7)",
    )
    .bind(
      id,
      options.state ?? "requested",
      options.key ?? wgKey(n),
      wgKey(n + 100),
      options.ready === false ? 0 : 1,
      options.reason ?? null,
      AT,
    )
    .run();
}

type Member = Record<string, unknown> & { node: string; kind?: string };

const member = (id: string, host: number, extra: Partial<Member> = {}) => ({
  node: id,
  name: NAME[id]!,
  address: `10.88.37.${host}`,
  key: wgKey(NUMBER[id]!),
  signer: wgKey(NUMBER[id]! + 100),
  sealKey: sealKey(NUMBER[id]!),
  port: 51820,
  mtu: null,
  endpoint: `203.0.113.${host}:51820`,
  nat: false,
  psk: {},
  ...extra,
});

function documentOf(
  version: number,
  members: Member[],
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
          .map((other) => [other.node, SEALED]),
      ),
    })),
    blocked: [],
    allow: [],
    ...extra,
  };
}

async function sign(document: object, verified = true) {
  const assertion = await passkey.sign({
    challenge: new Uint8Array(32),
    origin: ORIGIN,
    rpId: new URL(ORIGIN).hostname,
    verified,
  });
  return signDocument(
    { key: session.privateKey, grant: { grant: "e30", ...assertion } },
    encoder.encode(JSON.stringify(document)),
  );
}

const hashOf = (document: object) =>
  documentHash(new Uint8Array(encoder.encode(JSON.stringify(document))));

async function network() {
  const harness = testEnv();
  const post = async (document: object, verified = true) =>
    harness.send("POST", "/api/network/document", {
      signed: await sign(document, verified),
      change: "Change the network",
      detail: null,
    });
  return { ...harness, post };
}

async function created() {
  const harness = await network();
  await machine(harness.db, S1);
  await machine(harness.db, S2);
  const first = documentOf(1, [member(S1, 10), member(S2, 20)], {
    allow: [
      { from: { group: "laptops" }, to: { group: "servers" }, ports: "all" },
    ],
  });
  expect((await harness.post(first)).status).toBe(200);
  harness.hub.calls.length = 0;
  return { ...harness, first, parent: await hashOf(first) };
}

const stale = (db: D1Database, match: string, row: unknown) =>
  ({
    prepare: (sql: string) =>
      sql.includes(match)
        ? { bind: () => ({ first: async () => row }) }
        : db.prepare(sql),
    batch: db.batch.bind(db),
  }) as unknown as D1Database;

const refusal = async (response: Response) => ({
  status: response.status,
  ...((await response.json()) as { code: string; message: string }),
});

describe("POST /api/network/document", () => {
  it("stores the first document, its members, addresses and a change", async () => {
    const { db, post, hub } = await network();
    await machine(db, S1);
    await machine(db, S2);
    const first = documentOf(1, [member(S1, 10), member(S2, 20)]);
    const response = await post(first);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ version: 1 });
    expect(
      await db
        .prepare("SELECT cidr, port, mtu, version, dns, deleted FROM network")
        .first(),
    ).toEqual({
      cidr: RANGE,
      port: 51820,
      mtu: 1420,
      version: 1,
      dns: null,
      deleted: 0,
    });
    expect(
      await db
        .prepare("SELECT version, hash FROM network_documents")
        .all()
        .then((rows) => rows.results),
    ).toEqual([{ version: 1, hash: await hashOf(first) }]);
    expect(
      (
        await db
          .prepare(
            "SELECT node_id, state, address, key, endpoint, joined_at IS NOT NULL AS joined FROM network_members ORDER BY node_id",
          )
          .all()
      ).results,
    ).toEqual([
      {
        node_id: S1,
        state: "in",
        address: "10.88.37.10",
        key: wgKey(1),
        endpoint: "203.0.113.10:51820",
        joined: 1,
      },
      {
        node_id: S2,
        state: "in",
        address: "10.88.37.20",
        key: wgKey(2),
        endpoint: "203.0.113.20:51820",
        joined: 1,
      },
    ]);
    expect(
      (
        await db
          .prepare(
            "SELECT address, node_id, freed_at FROM network_addresses ORDER BY address",
          )
          .all()
      ).results,
    ).toEqual([
      { address: "10.88.37.10", node_id: S1, freed_at: null },
      { address: "10.88.37.20", node_id: S2, freed_at: null },
    ]);
    expect(
      await db
        .prepare("SELECT change, detail, nodes FROM network_changes")
        .first(),
    ).toEqual({
      change: "Change the network",
      detail: null,
      nodes: JSON.stringify([S1, S2]),
    });
    expect(hub.calls).toEqual([
      { path: "/document", body: { version: 1 } },
      { path: "/announce", body: { topics: ["network", "fleet", "history"] } },
    ]);
  });

  it("a stored document is pushed to online members", async () => {
    const { post, hub, first, parent } = await created();
    const second = documentOf(2, [member(S1, 10), member(S2, 20)], {
      parent,
      allow: first.allow,
      dns: ["10.88.37.10"],
    });
    expect((await post(second)).status).toBe(200);
    expect(hub.calls[0]).toEqual({ path: "/document", body: { version: 2 } });
  });

  it("a document that is not the next version is refused", async () => {
    const { db, post, hub, parent } = await created();
    for (const version of [1, 3]) {
      expect(
        await refusal(
          await post(documentOf(version, [member(S1, 10)], { parent })),
        ),
      ).toEqual({
        status: 409,
        code: "VERSION_NOT_NEXT",
        message: "Someone changed the network meanwhile. Open it again.",
      });
    }
    expect(
      await db
        .prepare("SELECT COUNT(*) AS n FROM network_documents")
        .first("n"),
    ).toBe(1);
    expect(hub.calls).toEqual([]);
  });

  it("a document on another parent is refused", async () => {
    const { post } = await created();
    const other = await hashOf({ another: "body" });
    for (const parent of [other, undefined]) {
      const response = await post(
        documentOf(2, [member(S1, 10), member(S2, 20)], { parent }),
      );
      expect(await refusal(response)).toMatchObject({
        status: 409,
        code: "VERSION_NOT_NEXT",
      });
    }
  });

  it("a member key that differs from the request is refused", async () => {
    const { db, post } = await network();
    await machine(db, S1);
    await machine(db, S2);
    for (const changed of [
      { key: wgKey(9) },
      { signer: wgKey(9) },
      { sealKey: sealKey(9) },
    ]) {
      const response = await post(
        documentOf(1, [member(S1, 10), member(S2, 20, changed)]),
      );
      expect(await refusal(response)).toEqual({
        status: 422,
        code: "KEY_CHANGED",
        message:
          "server-2's keys differ from the ones it reported. Open it again.",
      });
    }
    expect(await db.prepare("SELECT version FROM network").first()).toBeNull();
  });

  it("a member keeps its key unless its signer announced the new one", async () => {
    const { db, post, first, parent } = await created();
    const moved = documentOf(
      2,
      [member(S1, 10, { key: wgKey(7) }), member(S2, 20)],
      { parent, allow: first.allow },
    );
    expect(await refusal(await post(moved))).toMatchObject({
      status: 422,
      code: "KEY_CHANGED",
    });
    await db
      .prepare(
        "UPDATE network_members SET announce_key = ?1, announce_signature = 'c2ln' WHERE node_id = ?2",
      )
      .bind(wgKey(7), S1)
      .run();
    expect((await post(moved)).status).toBe(200);
    expect(
      await db
        .prepare(
          "SELECT key, announce_key FROM network_members WHERE node_id = ?",
        )
        .bind(S1)
        .first(),
    ).toEqual({ key: wgKey(7), announce_key: null });
  });

  it("a new member that was rejected is refused", async () => {
    const { db, post, first, parent } = await created();
    await machine(db, S3, { state: "rejected" });
    const response = await post(
      documentOf(2, [member(S1, 10), member(S2, 20), member(S3, 30)], {
        parent,
        allow: first.allow,
      }),
    );
    expect(await refusal(response)).toEqual({
      status: 422,
      code: "NOT_REQUESTED",
      message: "server-3 has not asked to join the private network.",
    });
  });

  it("a new member that is not ready is refused with its reason", async () => {
    const { db, post } = await network();
    await machine(db, S1);
    await machine(db, S2, {
      ready: false,
      reason: "The kernel has no WireGuard module.",
    });
    const response = await post(
      documentOf(1, [member(S1, 10), member(S2, 20)]),
    );
    expect(await refusal(response)).toEqual({
      status: 422,
      code: "NOT_READY",
      message: "server-2 cannot join: The kernel has no WireGuard module.",
    });
  });

  it("refuses a member that is not enrolled or named as the wrong kind", async () => {
    const { db, post } = await network();
    await machine(db, S1);
    await machine(db, L1, { kind: "laptop" });
    expect(
      await refusal(
        await post(documentOf(1, [member(S1, 10), member(S2, 20)])),
      ),
    ).toEqual({
      status: 404,
      code: "NOT_FOUND",
      message: "server-2 is not enrolled.",
    });
    expect(
      await refusal(
        await post(documentOf(1, [member(S1, 10), member(L1, 40)])),
      ),
    ).toEqual({
      status: 422,
      code: "WRONG_KIND",
      message: "The document lists laptop-1 as the wrong kind of member.",
    });
  });

  it("refuses a malformed document and a passkey opened without UV", async () => {
    const { db, post, send } = await network();
    await machine(db, S1);
    expect(
      await refusal(await post(documentOf(1, [member(S1, 10)]), false)),
    ).toEqual({
      status: 400,
      code: "VERIFICATION_NEEDED",
      message:
        "This passkey was opened without your fingerprint, face or PIN. Open it with one of those.",
    });
    const broken = await send("POST", "/api/network/document", {
      signed: await sign({ v: 1, version: 1 }),
      change: "Change the network",
      detail: null,
    });
    expect(broken.status).toBe(400);
    const loose = await send("POST", "/api/network/document", {
      signed: "{}",
      change: "Change the network",
      detail: null,
    });
    expect(loose.status).toBe(400);
  });

  it("a broken authenticatorData is a malformed request, not an error", async () => {
    const { db, send } = await network();
    await machine(db, S1);
    for (const authenticatorData of ["A", "AAAA"]) {
      const signed = JSON.parse(
        await sign(documentOf(1, [member(S1, 10)])),
      ) as { grant: Record<string, string> };
      signed.grant.authenticatorData = authenticatorData;
      const response = await send("POST", "/api/network/document", {
        signed: JSON.stringify(signed),
        change: "Change the network",
      });
      expect(await refusal(response)).toMatchObject({
        status: 400,
        code: "INVALID_REQUEST",
      });
    }
  });

  it("a live network keeps its range and every member its address", async () => {
    const { post, first, parent } = await created();
    const moved = documentOf(
      2,
      [
        member(S1, 10, { address: "10.88.38.10" }),
        member(S2, 20, { address: "10.88.38.20" }),
      ],
      { parent, allow: first.allow, range: "10.88.38.0/24" },
    );
    expect(await refusal(await post(moved))).toEqual({
      status: 422,
      code: "RANGE_CHANGED",
      message: `The network keeps its range ${RANGE}. Delete it and create it again to change it.`,
    });
    const readdressed = documentOf(2, [member(S1, 11), member(S2, 20)], {
      parent,
      allow: first.allow,
    });
    expect(await refusal(await post(readdressed))).toEqual({
      status: 422,
      code: "ADDRESS_CHANGED",
      message: "server-1 keeps its address 10.88.37.10.",
    });
  });

  it("a second document for the same version stores nothing of it", async () => {
    const { db, post, hub, first, parent } = await created();
    await db
      .prepare(
        "INSERT INTO network_documents (version, signed, hash, created_at) VALUES (2, 'the other dashboard', 'h2', ?1)",
      )
      .bind(AT)
      .run();
    const response = await post(
      documentOf(2, [member(S1, 10)], {
        parent,
        allow: first.allow,
        blocked: [wgKey(2)],
      }),
    );
    expect(await refusal(response)).toMatchObject({
      status: 409,
      code: "VERSION_NOT_NEXT",
    });
    expect(await db.prepare("SELECT version FROM network").first()).toEqual({
      version: 1,
    });
    expect(
      await db
        .prepare("SELECT signed FROM network_documents WHERE version = 2")
        .first("signed"),
    ).toBe("the other dashboard");
    expect(
      await db
        .prepare("SELECT state FROM network_members WHERE node_id = ?")
        .bind(S2)
        .first("state"),
    ).toBe("in");
    expect(
      await db.prepare("SELECT COUNT(*) AS n FROM network_changes").first("n"),
    ).toBe(1);
    expect(
      await db.prepare("SELECT COUNT(*) AS n FROM network_blocked").first("n"),
    ).toBe(0);
    expect(hub.calls).toEqual([]);
  });

  it("a removed member leaves, frees its address and its key is blocked", async () => {
    const { db, post, first, parent } = await created();
    const second = documentOf(2, [member(S1, 10)], {
      parent,
      allow: first.allow,
      blocked: [wgKey(2)],
    });
    expect((await post(second)).status).toBe(200);
    expect(
      await db
        .prepare("SELECT state FROM network_members WHERE node_id = ?")
        .bind(S2)
        .first("state"),
    ).toBe("leaving");
    expect(
      await db
        .prepare(
          "SELECT freed_at IS NOT NULL AS freed FROM network_addresses WHERE address = '10.88.37.20'",
        )
        .first("freed"),
    ).toBe(1);
    expect(
      await db.prepare("SELECT key, node_id FROM network_blocked").first(),
    ).toEqual({ key: wgKey(2), node_id: S2 });
    expect(
      await db
        .prepare("SELECT nodes FROM network_changes ORDER BY at DESC LIMIT 1")
        .first("nodes"),
    ).toBe(JSON.stringify([S1, S2]));
  });
});

describe("addresses and machines that never left", () => {
  it("a new member's address that another machine still holds is refused", async () => {
    const { db, post, first, parent } = await created();
    await machine(db, S3);
    const taken = documentOf(2, [member(S1, 10), member(S3, 20)], {
      parent,
      allow: first.allow,
    });
    expect(await refusal(await post(taken))).toEqual({
      status: 422,
      code: "ADDRESS_TAKEN",
      message: "10.88.37.20 is still held by server-2. Open it again.",
    });
    expect(await db.prepare("SELECT version FROM network").first()).toEqual({
      version: 1,
    });
    const free = documentOf(2, [member(S1, 10), member(S3, 30)], {
      parent,
      allow: first.allow,
    });
    expect((await post(free)).status).toBe(200);
  });

  it("creating the network again lets go of machines that never left", async () => {
    const { db, post, parent } = await created();
    const deleted = documentOf(2, [], { parent, deleted: true });
    expect((await post(deleted)).status).toBe(200);
    await machine(db, S3);
    const again = documentOf(3, [member(S3, 30, { address: "10.88.38.30" })], {
      parent: await hashOf(deleted),
      range: "10.88.38.0/24",
    });
    expect((await post(again)).status).toBe(200);
    expect(
      await db
        .prepare("SELECT node_id, state FROM network_members ORDER BY node_id")
        .all()
        .then((rows) => rows.results),
    ).toEqual([{ node_id: S3, state: "in" }]);
  });
});

describe("GET /api/network", () => {
  it("shows the network, members, requests and rules", async () => {
    const { db, call, first, hub } = await created();
    await machine(db, L1, { kind: "laptop" });
    await machine(db, S3, { state: "rejected" });
    await db
      .prepare("UPDATE network_members SET failure = ?1 WHERE node_id = ?2")
      .bind("the document names another key for server-1", S1)
      .run();
    await db
      .prepare(
        "INSERT INTO network_links (a, b, answering, ms, since) VALUES (?1, ?2, 1, 3.5, ?3)",
      )
      .bind(S1, S2, AT)
      .run();
    const response = await call("/api/network");
    expect(response.status).toBe(200);
    const view = (await response.json()) as Record<string, unknown>;
    expect(view.network).toEqual({
      range: RANGE,
      port: 51820,
      mtu: 1420,
      version: 1,
      dns: null,
      deleted: false,
    });
    expect(view.members).toEqual([
      {
        node: S1,
        name: "server-1",
        kind: "server",
        state: "in",
        address: "10.88.37.10",
        key: wgKey(1),
        signer: wgKey(101),
        port: 51820,
        mtu: null,
        endpoint: "203.0.113.10:51820",
        nat: false,
        applied: 0,
        failure: "the document names another key for server-1",
        announced: null,
        since: expect.any(String),
        joinedAt: expect.any(String),
      },
      expect.objectContaining({ node: S2, name: "server-2", failure: null }),
    ]);
    expect(hub.calls).toEqual([{ path: "/refresh", body: {} }]);
    expect(view.requests).toEqual([
      {
        node: L1,
        name: "laptop-1",
        kind: "laptop",
        hostname: "vps-4",
        os: "linux",
        key: wgKey(4),
        signer: wgKey(104),
        sealKey: sealKey(4),
        ready: true,
        reason: null,
        since: AT,
      },
    ]);
    expect(view.rejected).toEqual([{ node: S3, name: "server-3" }]);
    expect(view.allow).toEqual(first.allow);
    expect(view.links).toEqual([
      { a: S1, b: S2, answering: true, ms: 3.5, since: AT },
    ]);
  });

  it("shows no network before one is made", async () => {
    const { call } = await network();
    expect(await (await call("/api/network")).json()).toEqual({
      network: null,
      members: [],
      requests: [],
      rejected: [],
      allow: [],
      links: [],
    });
  });

  it("the view never contains a preshared key", async () => {
    const { call, db } = await created();
    await machine(db, S3);
    const view = await (await call("/api/network")).text();
    expect(view).not.toContain(SEALED);
    expect(view).not.toMatch(/psk|preshared|private/iu);
    const next = await (await call(`/api/network/next?for=${S3}`)).text();
    expect(next).not.toMatch(/preshared|private/iu);
  });
});

describe("GET /api/network/applied", () => {
  it("says what each member applied without asking the hub", async () => {
    const { db, call, hub } = await created();
    hub.online = [S1];
    await db
      .prepare(
        "UPDATE network_members SET applied = 1, failure = NULL WHERE node_id = ?1",
      )
      .bind(S1)
      .run();
    await db
      .prepare("UPDATE network_members SET failure = ?1 WHERE node_id = ?2")
      .bind("the tunnel did not come up", S2)
      .run();
    const response = await call("/api/network/applied");
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      version: 1,
      members: [
        {
          node: S1,
          name: "server-1",
          applied: 1,
          failure: null,
          online: true,
        },
        {
          node: S2,
          name: "server-2",
          applied: 0,
          failure: "the tunnel did not come up",
          online: false,
        },
      ],
    });
    expect(hub.calls.map((one) => one.path)).toEqual(["/online"]);
  });

  it("is empty before a network exists", async () => {
    const { call } = await network();
    expect(await (await call("/api/network/applied")).json()).toEqual({
      version: 0,
      members: [],
    });
  });
});

describe("GET /api/network/current", () => {
  it("hands the live document's stored bytes and their hash", async () => {
    const { call, first, parent } = await created();
    const response = await call("/api/network/current");
    expect(response.status).toBe(200);
    const current = (await response.json()) as Record<string, unknown>;
    expect(Object.keys(current)).toEqual(["version", "hash", "document"]);
    expect(current.version).toBe(1);
    expect(current.hash).toBe(parent);
    const body = Buffer.from(current.document as string, "base64url");
    expect(body.toString("utf8")).toBe(JSON.stringify(first));
    expect(await documentHash(new Uint8Array(body))).toBe(parent);
  });

  it("answers 404 when there is no network or it was deleted", async () => {
    const { call } = await network();
    expect((await call("/api/network/current")).status).toBe(404);
    const live = await created();
    const gone = documentOf(2, [], {
      deleted: true,
      parent: live.parent,
      blocked: [wgKey(1), wgKey(2)],
    });
    expect((await live.post(gone)).status).toBe(200);
    expect((await live.call("/api/network/current")).status).toBe(404);
  });
});

describe("GET /api/network/next", () => {
  it("hands the current document, its hash and what the new members need", async () => {
    const { call, db, first, parent } = await created();
    await machine(db, L1, { kind: "laptop" });
    const response = await call(`/api/network/next?for=${L1}`);
    expect(response.status).toBe(200);
    const next = (await response.json()) as {
      document: unknown;
      hash: string;
      prepared: unknown;
      addresses: Record<string, string>;
      relayPorts: unknown;
    };
    expect(next.document).toEqual(first);
    expect(next.hash).toBe(parent);
    expect(next.prepared).toEqual({
      [L1]: { key: wgKey(4), signer: wgKey(104), port: 51820, mtu: null },
    });
    expect(next).not.toHaveProperty("sealKeys");
    expect(Object.keys(next.addresses)).toEqual([L1]);
    expect(next.addresses[L1]).toMatch(/^10\.88\.37\.\d+$/u);
    expect(next.relayPorts).toEqual({});
  });

  it("hands the address each requested machine connects from", async () => {
    const { call, db } = await created();
    await machine(db, S3);
    await machine(db, L1, { kind: "laptop" });
    await db
      .prepare("UPDATE nodes SET seen_ip = '203.0.113.9' WHERE id = ?")
      .bind(S3)
      .run();
    const next = (await (
      await call(`/api/network/next?for=${S3},${L1}`)
    ).json()) as { seen: Record<string, string | null> };
    expect(next.seen).toEqual({ [S3]: "203.0.113.9", [L1]: null });
  });

  it("addresses for new members are random and never taken", async () => {
    const { call, db } = await created();
    await machine(db, S3);
    for (let host = 1; host <= 254; host += 1) {
      if (host === 7 || host === 200) continue;
      await db
        .prepare(
          "INSERT OR IGNORE INTO network_addresses (address, node_id, freed_at) VALUES (?1, NULL, NULL)",
        )
        .bind(`10.88.37.${host}`)
        .run();
    }
    const seen = new Set<string>();
    for (let round = 0; round < 40; round += 1) {
      const next = (await (
        await call(`/api/network/next?for=${S3}`)
      ).json()) as { addresses: Record<string, string> };
      seen.add(next.addresses[S3]!);
    }
    expect([...seen].sort()).toEqual(["10.88.37.200", "10.88.37.7"]);
  });

  it("uses the browser's range when there is no network, and checks it", async () => {
    const { call, db } = await network();
    await machine(db, S1);
    const fresh = (await (
      await call(`/api/network/next?for=${S1}&range=10.88.9.0/24`)
    ).json()) as {
      document: unknown;
      hash: unknown;
      addresses: Record<string, string>;
    };
    expect(fresh.document).toBeNull();
    expect(fresh.hash).toBeNull();
    expect(fresh.addresses[S1]).toMatch(/^10\.88\.9\.\d+$/u);
    for (const query of [
      `for=${S1}`,
      `for=${S1}&range=10.89.9.0/24`,
      `for=${S1}&range=10.88.9.0/16`,
      "range=10.88.9.0/24",
      `for=${S1},${S1}&range=10.88.9.0/24`,
    ]) {
      expect((await call(`/api/network/next?${query}`)).status).toBe(400);
    }
  });

  it("refuses a range over the live one and a machine that did not ask", async () => {
    const { call, db } = await created();
    await machine(db, S3, { state: "rejected" });
    expect(
      (await call(`/api/network/next?for=${S3}&range=${RANGE}`)).status,
    ).toBe(400);
    expect(
      await refusal(await call(`/api/network/next?for=${S3}`)),
    ).toMatchObject({
      status: 422,
      code: "NOT_REQUESTED",
    });
    expect(
      (await call(`/api/network/next?for=55555555-5555-4555-8555-555555555555`))
        .status,
    ).toBe(404);
  });
});

describe("join requests", () => {
  it("reject and again flip the request and log a change", async () => {
    const { db, send, hub } = await network();
    await machine(db, S3);
    const state = () =>
      db
        .prepare("SELECT state FROM network_members WHERE node_id = ?")
        .bind(S3)
        .first("state");
    expect(
      (await send("POST", `/api/network/requests/${S3}/reject`)).status,
    ).toBe(200);
    expect(await state()).toBe("rejected");
    expect(
      await refusal(await send("POST", `/api/network/requests/${S3}/reject`)),
    ).toMatchObject({ status: 409, code: "NOT_REQUESTED" });
    expect(
      (await send("POST", `/api/network/requests/${S3}/again`)).status,
    ).toBe(200);
    expect(await state()).toBe("requested");
    expect(
      (
        await db
          .prepare("SELECT change, nodes FROM network_changes ORDER BY rowid")
          .all()
      ).results,
    ).toEqual([
      {
        change: "Reject server-3's request to join",
        nodes: JSON.stringify([S3]),
      },
      { change: "Ask server-3 to join again", nodes: JSON.stringify([S3]) },
    ]);
    expect(hub.calls.filter((entry) => entry.path === "/announce")).toEqual([
      { path: "/announce", body: { topics: ["network", "fleet", "history"] } },
      { path: "/announce", body: { topics: ["network", "fleet", "history"] } },
    ]);
    expect(
      (await send("POST", `/api/network/requests/${S1}/again`)).status,
    ).toBe(404);
  });
});

describe("a request that changed meanwhile", () => {
  it("is refused and logs nothing", async () => {
    const harness = await network();
    await machine(harness.db, S3, { state: "rejected" });
    harness.env.DB = stale(
      harness.db,
      "SELECT n.name, m.state FROM nodes n JOIN network_members",
      { name: "server-3", state: "requested" },
    );
    expect(
      await refusal(
        await harness.send("POST", `/api/network/requests/${S3}/reject`),
      ),
    ).toMatchObject({ status: 409, code: "NOT_REQUESTED" });
    expect(
      await harness.db
        .prepare("SELECT COUNT(*) AS n FROM network_changes")
        .first("n"),
    ).toBe(0);
    expect(harness.hub.calls).toEqual([]);
  });
});

describe("GET /api/network/changes", () => {
  it("lists the newest changes first, at most the limit", async () => {
    const { db, call } = await network();
    for (const [id, at] of [
      ["c1", "2026-11-22T01:00:00.000Z"],
      ["c2", "2026-11-22T03:00:00.000Z"],
      ["c3", "2026-11-22T02:00:00.000Z"],
    ]) {
      await db
        .prepare(
          "INSERT INTO network_changes (id, at, change, nodes) VALUES (?1, ?2, 'Change', '[]')",
        )
        .bind(id, at)
        .run();
    }
    const changes = (await (
      await call("/api/network/changes?limit=2")
    ).json()) as { id: string }[];
    expect(changes).toEqual([
      {
        id: "c2",
        at: "2026-11-22T03:00:00.000Z",
        change: "Change",
        detail: null,
        nodes: [],
      },
      expect.objectContaining({ id: "c3" }),
    ]);
  });
});
