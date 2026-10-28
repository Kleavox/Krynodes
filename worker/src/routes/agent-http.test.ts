import { describe, expect, it } from "vitest";

import { app } from "../app";
import type { Env } from "../env";
import { sha256 } from "../lib/crypto";
import { seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";

const NODE = "11111111-1111-4111-8111-111111111111";

async function setup() {
  const { db, sqlite } = createTestDb();
  seedNode(sqlite, { id: NODE });
  sqlite
    .prepare("UPDATE nodes SET agent_version = '0.6.10' WHERE id = ?")
    .run(NODE);
  sqlite
    .prepare("UPDATE nodes SET agent_token_hash = ? WHERE id = ?")
    .run(await sha256("agent-token"), NODE);
  const hub: Request[] = [];
  const env = {
    DB: db,
    FLEET: {
      idFromName: (name: string) => ({ name }),
      get: () => ({
        fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
          hub.push(new Request(input, init));
          return new Response("from hub");
        },
      }),
    },
  } as unknown as Env;
  const call = (
    method: string,
    path: string,
    headers: Record<string, string> = {},
    body?: unknown,
  ) =>
    app.request(
      `https://kry.example.test${path}`,
      {
        method,
        headers: {
          "content-type": "application/json",
          authorization: "Bearer agent-token",
          ...headers,
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      },
      env,
    );
  const fromNetwork = (
    method: string,
    ip: string,
    cf: unknown,
    body?: unknown,
  ) => {
    const request = new Request(`https://kry.example.test/api/agent/address`, {
      method,
      headers: {
        "content-type": "application/json",
        authorization: "Bearer agent-token",
        "cf-connecting-ip": ip,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    Object.defineProperty(request, "cf", { value: cf });
    return app.request(request, undefined, env);
  };
  const row = () =>
    sqlite
      .prepare(
        "SELECT ipv4, ipv4_at, ipv6, ipv6_at, ipv4_network, ipv6_network, interfaces FROM nodes WHERE id = ?",
      )
      .get(NODE) as {
      ipv4: string | null;
      ipv4_at: string | null;
      ipv6: string | null;
      ipv6_at: string | null;
      ipv4_network: string | null;
      ipv6_network: string | null;
      interfaces: string | null;
    };
  return { call, fromNetwork, hub, row, sqlite };
}

const OTHER = "22222222-2222-4222-8222-222222222222";

function joinNetwork(sqlite: ReturnType<typeof createTestDb>["sqlite"]) {
  seedNode(sqlite, { id: OTHER });
  sqlite.exec(
    `INSERT INTO network (owner_user_id, cidr, port, mtu, version, document, stamp, created_at, created_by)
     VALUES ('standalone', '10.88.0.0/24', 51820, 1420, 2, '{}', 's1', 'now', 'owner');
     INSERT INTO network_members (node_id, state, address, port, key, signer, endpoint, nat, since) VALUES
     ('${NODE}', 'in', '10.88.0.1', 51821, 'k1', 's1', '141.95.0.21:51821', 0, 'now'),
     ('${OTHER}', 'in', '10.88.0.2', 51820, 'k2', 's2', '141.95.0.22:51820', 0, 'now');`,
  );
}

describe("a member's public address", () => {
  const seen = (t: Awaited<ReturnType<typeof setup>>, ip: string) =>
    t.call("GET", "/api/agent/address", { "cf-connecting-ip": ip });

  it("moves its endpoint on the others by itself and says so once", async () => {
    const t = await setup();
    joinNetwork(t.sqlite);
    await seen(t, "141.95.0.99");
    await seen(t, "141.95.0.99");
    await seen(t, "2001:db8:1:2::8f2a");
    expect(
      t.sqlite
        .prepare("SELECT endpoint FROM network_members WHERE node_id = ?")
        .get(NODE),
    ).toEqual({ endpoint: "141.95.0.99:51821" });
    expect(t.sqlite.prepare("SELECT stamp FROM network").get()).not.toEqual({
      stamp: "s1",
    });
    expect(
      t.sqlite
        .prepare(
          "SELECT change, detail, requested_by, device_id, nodes FROM network_changes",
        )
        .all(),
    ).toEqual([
      {
        change: `Update the public address of ${NODE}`,
        detail: "141.95.0.21 → 141.95.0.99",
        requested_by: "Krynodes",
        device_id: null,
        nodes: JSON.stringify([NODE]),
      },
    ]);
    const pokes = t.hub.filter(
      (request) => new URL(request.url).pathname === "/poke",
    );
    expect(pokes).toHaveLength(1);
    expect(await pokes[0]!.json()).toEqual({ nodeIds: [OTHER] });
  });

  it("leaves a server behind NAT alone", async () => {
    const t = await setup();
    joinNetwork(t.sqlite);
    t.sqlite.exec(
      `UPDATE network_members SET nat = 1, endpoint = NULL WHERE node_id = '${NODE}'`,
    );
    await seen(t, "141.95.0.99");
    expect(
      t.sqlite.prepare("SELECT count(*) AS n FROM network_changes").get(),
    ).toEqual({ n: 0 });
  });
});

describe("the server's own addresses", () => {
  it("are what Cloudflare saw the agent come from, one per family", async () => {
    const t = await setup();
    const seen = async (ip: string) =>
      (
        await t.call("GET", "/api/agent/address", { "cf-connecting-ip": ip })
      ).json();
    expect(await seen("103.28.54.214")).toEqual({
      address: "103.28.54.214",
      family: 4,
    });
    expect(await seen("2001:db8:1:2::8f2a")).toEqual({
      address: "2001:db8:1:2::8f2a",
      family: 6,
    });
    const stored = t.row();
    expect(stored).toMatchObject({
      ipv4: "103.28.54.214",
      ipv6: "2001:db8:1:2::8f2a",
    });
    expect(stored.ipv4_at).not.toBeNull();
    expect(stored.ipv6_at).not.toBeNull();
  });

  it("ignore what is not an address and refuse a stranger", async () => {
    const t = await setup();
    expect(
      await (
        await t.call("GET", "/api/agent/address", {
          "cf-connecting-ip": "999.1.1.1",
        })
      ).json(),
    ).toEqual({ address: null });
    expect(await (await t.call("GET", "/api/agent/address")).json()).toEqual({
      address: null,
    });
    expect(t.row()).toMatchObject({ ipv4: null, ipv6: null });
    expect(
      (
        await t.call("GET", "/api/agent/address", {
          authorization: "Bearer wrong",
          "cf-connecting-ip": "103.28.54.214",
        })
      ).status,
    ).toBe(401);
  });

  it("keep the network Cloudflare names for each family", async () => {
    const t = await setup();
    await t.fromNetwork("GET", "103.28.54.214", {
      asOrganization: "PT Telkom Indonesia",
    });
    await t.fromNetwork("GET", "2001:db8:1:2::8f2a", undefined);
    expect(t.row()).toMatchObject({
      ipv4_network: "PT Telkom Indonesia",
      ipv6_network: null,
    });
  });

  it("store the interfaces a 0.6.13 agent sends with its call", async () => {
    const t = await setup();
    const interfaces = [
      { name: "eth0", address: "192.168.1.5" },
      { name: "tailscale0", address: "100.101.102.7" },
    ];
    const response = await t.call(
      "POST",
      "/api/agent/address",
      { "cf-connecting-ip": "103.28.54.214" },
      { interfaces },
    );
    expect(await response.json()).toEqual({
      address: "103.28.54.214",
      family: 4,
    });
    const stored = t.row();
    expect(stored.ipv4).toBe("103.28.54.214");
    expect(JSON.parse(stored.interfaces!)).toEqual(interfaces);
  });

  it("drop interface entries that are not an interface and an address, and keep the rest", async () => {
    const t = await setup();
    const many = Array.from({ length: 70 }, (_, index) => ({
      name: `wg${index}`,
      address: `10.8.0.${index + 1}`,
    }));
    await t.call(
      "POST",
      "/api/agent/address",
      { "cf-connecting-ip": "103.28.54.214" },
      {
        interfaces: [
          { name: "", address: "10.0.0.1" },
          { name: "a/b", address: "10.0.0.2" },
          { name: "x".repeat(16), address: "10.0.0.3" },
          { name: "wg0", address: "999.1.1.1" },
          "nonsense",
          { name: "wg0", address: "10.8.0.1" },
          { name: "wg0", address: "10.8.0.1" },
          ...many,
        ],
      },
    );
    const stored = JSON.parse(t.row().interfaces!) as {
      name: string;
      address: string;
    }[];
    expect(stored).toHaveLength(64);
    expect(stored[0]).toEqual({ name: "wg0", address: "10.8.0.1" });
    expect(stored[1]).toEqual({ name: "wg1", address: "10.8.0.2" });
    expect(
      new Set(stored.map((entry) => `${entry.name} ${entry.address}`)).size,
    ).toBe(64);
  });

  it("leave the interfaces alone when an older agent calls with GET", async () => {
    const t = await setup();
    const interfaces = [{ name: "eth0", address: "51.79.0.10" }];
    await t.call(
      "POST",
      "/api/agent/address",
      { "cf-connecting-ip": "51.79.0.10" },
      { interfaces },
    );
    await t.call("GET", "/api/agent/address", {
      "cf-connecting-ip": "51.79.0.10",
    });
    expect(JSON.parse(t.row().interfaces!)).toEqual(interfaces);
  });

  it("keep the stored interfaces when a call carries none it can read", async () => {
    const t = await setup();
    const interfaces = [{ name: "eth0", address: "51.79.0.10" }];
    const send = (body: unknown) =>
      t.call(
        "POST",
        "/api/agent/address",
        { "cf-connecting-ip": "51.79.0.10" },
        body,
      );
    await send({ interfaces });
    for (const body of [
      { interfaces: {} },
      { interfaces: "eth0" },
      { interfaces: [] },
      { interfaces: [{ iface: "eth0", ip: "51.79.0.10" }] },
    ]) {
      await send(body);
      expect(JSON.parse(t.row().interfaces!)).toEqual(interfaces);
    }
  });
});

describe("older agents", () => {
  it("get 410 on the HTTP report routes, which no longer exist", async () => {
    const t = await setup();
    for (const [method, path] of [
      ["POST", "/api/agent/heartbeat"],
      ["GET", "/api/agent/config"],
      ["POST", "/api/agent/actions"],
    ] as const) {
      const response = await t.call(
        method,
        path,
        {},
        method === "POST" ? {} : undefined,
      );
      expect(response.status).toBe(410);
      expect(await response.json()).toMatchObject({
        code: "AGENT_UPDATE_REQUIRED",
      });
    }
  });

  it("are refused at the live connection by the version they announce", async () => {
    const t = await setup();
    const open = (agent: string) =>
      t.call("GET", "/api/agent/stream", {
        upgrade: "websocket",
        "user-agent": agent,
      });
    for (const agent of [
      "kry-agent/0.4.1",
      "kry-agent/0.5.1",
      "kry-agent/0.6.14",
    ]) {
      const old = await open(agent);
      expect(old.status).toBe(426);
      expect(await old.json()).toMatchObject({ code: "AGENT_UPDATE_REQUIRED" });
    }
    expect(t.hub).toHaveLength(0);
    expect(await (await open("kry-agent/0.7.0")).text()).toBe("from hub");
    expect(await (await open("kry-agent/dev")).text()).toBe("from hub");
  });

  it("leave no switch behind on the dashboard", async () => {
    const t = await setup();
    const overview = (await (
      await t.call("GET", "/api/overview")
    ).json()) as Record<string, unknown>;
    expect(overview).not.toHaveProperty("agentHttp");
    expect(
      (await t.call("PUT", "/api/agent-http", {}, { enabled: true })).status,
    ).toBe(404);
  });
});
