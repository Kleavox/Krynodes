import {
  networkDocumentSchema,
  type NetworkDocument,
} from "@krynodes/protocol";
import { describe, expect, it } from "vitest";

import type { FleetNode, JoinRequest, NetworkView } from "../types";
import { ApiError } from "./http";
import {
  canExit,
  exitOf,
  firstReadyServer,
  fleetRow,
  laptopInstall,
  memberRow,
  networkFailure,
  newDocument,
  nextOf,
  rangeFor,
  requestCount,
  testLines,
  testPeers,
  withDns,
  withExit,
  withJoiner,
  withNewKey,
  withoutMember,
  withoutNetwork,
} from "./network";
import { open, recipient } from "./seal-test-utils";

const S1 = "11111111-1111-4111-8111-111111111111";
const S2 = "22222222-2222-4222-8222-222222222222";
const L1 = "33333333-3333-4333-8333-333333333333";
const S3 = "44444444-4444-4444-8444-444444444444";
const L2 = "55555555-5555-4555-8555-555555555555";

const wgKey = () =>
  btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));

const KEYS: Record<string, Awaited<ReturnType<typeof recipient>>> = {
  [S1]: await recipient(),
  [S2]: await recipient(),
  [L1]: await recipient(),
  [S3]: await recipient(),
  [L2]: await recipient(),
};

const sequence =
  (...values: number[]) =>
  () =>
    values.shift() ?? 0;

const member = (
  node: string,
  name: string,
  address: string,
  extra: Partial<NetworkDocument["members"][number]> = {},
): NetworkDocument["members"][number] => ({
  node,
  name,
  address,
  key: wgKey(),
  signer: wgKey(),
  sealKey: KEYS[node]!.public,
  port: 51820,
  mtu: null,
  endpoint: null,
  nat: false,
  psk: {},
  ...extra,
});

function network(): NetworkDocument {
  const s1 = member(S1, "server-1", "10.88.37.14", {
    endpoint: "203.0.113.10:51820",
    psk: { [S2]: "c2VhbGVk", [L1]: "c2VhbGVk" },
  });
  const s2 = member(S2, "server-2", "10.88.37.201", {
    endpoint: "203.0.113.20:51820",
    psk: { [S1]: "c2VhbGVk", [L1]: "c2VhbGVk" },
  });
  const l1 = member(L1, "laptop-1", "10.88.37.77", {
    kind: "laptop",
    nat: true,
    psk: { [S1]: "c2VhbGVk", [S2]: "c2VhbGVk" },
    relay: {},
  });
  return networkDocumentSchema.parse({
    v: 1,
    version: 4,
    range: "10.88.37.0/24",
    port: 51820,
    mtu: 1420,
    members: [s1, s2, l1],
    blocked: [],
    allow: [
      { from: { group: "laptops" }, to: { group: "servers" }, ports: "all" },
      { from: { node: S1 }, to: { node: S2 }, ports: ["81/tcp"] },
      { from: { node: L1 }, to: { node: S2 }, ports: ["22/tcp"] },
      { from: { node: L1 }, to: { node: S1 }, ports: ["443/tcp"] },
    ],
  });
}

const BASE = { document: network(), hash: "q".repeat(43) };

describe("a new network", () => {
  it("a new network gets the default rule and a random range", () => {
    const used = ["10.88.0.0/17", "192.168.1.0/24"];
    const first = rangeFor(used, sequence(0));
    const last = rangeFor(used, sequence(0.999));
    expect(first).toBe("10.88.128.0/24");
    expect(last).toBe("10.88.255.0/24");
    expect(rangeFor(used, sequence(0.5))).toBe("10.88.192.0/24");

    const document = newDocument(first, 51820, 1420, null);
    expect(networkDocumentSchema.safeParse(document).success).toBe(true);
    expect(document).toMatchObject({ version: 1, range: first, members: [] });
    expect(document).not.toHaveProperty("parent");
    expect(document.allow).toEqual([
      { from: { group: "laptops" }, to: { group: "servers" }, ports: "all" },
    ]);
  });

  it("says so when every range clashes", () => {
    expect(() => rangeFor(["10.0.0.0/8"], sequence(0.3))).toThrow(
      "Every 10.88.x.0/24 clashes with a network on these servers.",
    );
  });

  it("follows a deleted network's last version", () => {
    const deleted = withoutNetwork(nextOf(BASE));
    const again = newDocument("10.88.90.0/24", 51820, 1420, {
      document: deleted,
      hash: "h".repeat(43),
    });
    expect(again).toMatchObject({ version: 6, parent: "h".repeat(43) });
    expect(again).not.toHaveProperty("deleted");
  });
});

describe("the next version", () => {
  it("names the current document as its parent", () => {
    const next = nextOf(BASE);
    expect(next.version).toBe(5);
    expect(next.parent).toBe(BASE.hash);
    next.members[0]!.psk[S2] = "b3RoZXI";
    expect(BASE.document.members[0]!.psk[S2]).toBe("c2VhbGVk");
  });

  it("withoutMember drops its rules and keys", () => {
    const gone = BASE.document.members[1]!;
    const next = withoutMember(nextOf(BASE), S2);
    expect(networkDocumentSchema.safeParse(next).success).toBe(true);
    expect(next.members.map((one) => one.node)).toEqual([S1, L1]);
    expect(next.members.map((one) => one.address)).not.toContain(gone.address);
    for (const one of next.members) expect(one.psk).not.toHaveProperty(S2);
    expect(next.allow).toEqual([
      { from: { group: "laptops" }, to: { group: "servers" }, ports: "all" },
      { from: { node: L1 }, to: { node: S1 }, ports: ["443/tcp"] },
    ]);
    expect(next.blocked).toEqual([gone.key]);
  });

  it("a delete document carries the live range", () => {
    const next = withoutNetwork(nextOf(BASE));
    expect(networkDocumentSchema.safeParse(next).success).toBe(true);
    expect(next).toMatchObject({
      version: 5,
      parent: BASE.hash,
      range: "10.88.37.0/24",
      deleted: true,
      members: [],
      allow: [],
    });
    expect(next.blocked).toEqual(BASE.document.members.map((one) => one.key));
  });
});

describe("a joiner", () => {
  const joiner = (node: string, name: string, kind?: "laptop") => ({
    node,
    name,
    key: wgKey(),
    signer: wgKey(),
    sealKey: KEYS[node]!.public,
    port: 51821,
    endpoint: null,
    nat: true,
    ...(kind ? { kind } : {}),
  });

  it("a joiner's address is random and free", async () => {
    const base = nextOf(BASE);
    for (const taken of ["10.88.37.14", "10.88.37.77", "10.88.38.9"]) {
      await expect(
        withJoiner(base, joiner(S3, "server-3"), taken),
      ).rejects.toThrow(`${taken} is not a free address of 10.88.37.0/24.`);
    }
    const next = await withJoiner(base, joiner(S3, "server-3"), "10.88.37.163");
    expect(next.members.at(-1)).toMatchObject({
      node: S3,
      address: "10.88.37.163",
      sealKey: KEYS[S3]!.public,
      mtu: null,
      endpoint: null,
      nat: true,
    });
    expect(next.allow).toEqual(BASE.document.allow);
    expect(next.version).toBe(5);
  });

  it("seals one preshared key per linked pair, to the seal keys in the document", async () => {
    const next = await withJoiner(
      nextOf(BASE),
      joiner(L2, "laptop-2", "laptop"),
      "10.88.37.5",
    );
    expect(networkDocumentSchema.safeParse(next).success).toBe(true);
    const laptop = next.members.find((one) => one.node === L2)!;
    expect(Object.keys(laptop.psk).sort()).toEqual([S1, S2].sort());
    for (const peer of [S1, S2]) {
      const mine = await open(KEYS[L2]!, laptop.psk[peer]!);
      const held = next.members.find((one) => one.node === peer)!.psk[L2]!;
      const theirs = await open(KEYS[peer]!, held);
      expect(mine).toEqual(theirs);
    }
    const other = next.members.find((one) => one.node === L1)!;
    expect(other.psk).not.toHaveProperty(L2);
  });

  it("gives every laptop a relay port to a new server behind NAT", async () => {
    const next = await withJoiner(
      nextOf(BASE),
      joiner(S3, "server-3"),
      "10.88.37.99",
    );
    expect(next.members.find((one) => one.node === L1)!.relay).toEqual({
      [S3]: 51920,
    });
  });

  it("refuses a joiner without a seal key or with a blocked key", async () => {
    await expect(
      withJoiner(
        nextOf(BASE),
        { ...joiner(S3, "server-3"), sealKey: "" },
        "10.88.37.9",
      ),
    ).rejects.toThrow("server-3 has not reported its seal key yet.");
    const blocked = joiner(S3, "server-3");
    const base = { ...nextOf(BASE), blocked: [blocked.key] };
    await expect(withJoiner(base, blocked, "10.88.37.9")).rejects.toThrow(
      "server-3's key was taken out of the network",
    );
  });
});

describe("the exit node", () => {
  it("an exit node must be a server with a public endpoint", () => {
    const base = nextOf(BASE);
    expect(() => withExit(base, L1)).toThrow(
      "laptop-1 needs a public address to be an Exit Node for Laptops.",
    );
    const natted = {
      ...base,
      members: base.members.map((one) =>
        one.node === S2 ? { ...one, nat: true, endpoint: null } : one,
      ),
    };
    expect(() => withExit(natted, S2)).toThrow(
      "server-2 needs a public address to be an Exit Node for Laptops.",
    );
    expect(() => withExit(base, S3)).toThrow(
      "That server is not in the private network.",
    );

    const on = withExit(base, S1);
    expect(networkDocumentSchema.safeParse(on).success).toBe(true);
    expect(on.members.filter((one) => one.exit).map((one) => one.node)).toEqual(
      [S1],
    );
    expect(on.dns).toEqual(["1.1.1.1", "1.0.0.1"]);
    const moved = withExit(on, S2);
    expect(
      moved.members.filter((one) => one.exit).map((one) => one.node),
    ).toEqual([S2]);
    const off = withExit(moved, null);
    expect(off.members.some((one) => one.exit)).toBe(false);
  });
});

describe("a member line", () => {
  const view: NetworkView = {
    network: {
      range: "10.88.37.0/24",
      port: 51820,
      mtu: 1420,
      version: 4,
      dns: null,
      deleted: false,
    },
    members: BASE.document.members.map((one, index) => ({
      node: one.node,
      name: one.name,
      kind: one.kind ?? "server",
      state: "in",
      address: one.address,
      key: one.key,
      signer: one.signer,
      port: one.port,
      mtu: one.mtu,
      endpoint: one.endpoint,
      nat: one.nat,
      applied: index === 0 ? 4 : 3,
      failure: index === 2 ? "The tunnel did not come up." : null,
      announced: null,
      since: "2026-11-22T00:00:00.000Z",
      joinedAt: "2026-11-22T00:00:00.000Z",
    })),
    requests: [],
    rejected: [],
    allow: [],
    links: [],
  };
  const fleet = (id: string, patch: Partial<FleetNode> = {}): FleetNode => ({
    id,
    name: id,
    hostname: null,
    os: null,
    arch: null,
    version: null,
    online: true,
    lastSeenAt: null,
    trust: null,
    update: null,
    kind: "server",
    address: null,
    via: null,
    ms: null,
    request: null,
    ...patch,
  });

  it("a server with no endpoint in the document is behind NAT, a laptop is not", () => {
    const behind: NetworkView = {
      ...view,
      members: view.members.map((one) =>
        one.node === S1 ? { ...one, endpoint: null, nat: true } : one,
      ),
    };
    expect(memberRow(behind, fleet(S1))).toMatchObject({ path: "Behind NAT" });
    expect(memberRow(behind, fleet(S2))).toMatchObject({ path: "Direct" });
    expect(memberRow(behind, fleet(L1))).toMatchObject({ path: "Direct" });
    expect(memberRow(behind, fleet(L1, { via: S1 }))).toMatchObject({
      path: "Via server-1",
    });
    expect(memberRow(behind, fleet(S1, { via: S2 }))).toMatchObject({
      path: "Via server-2",
    });
  });

  it("a missing round trip shows --", () => {
    expect(memberRow(view, fleet(S1))).toEqual({
      address: "10.88.37.14",
      path: "Direct",
      ms: "--",
      state: "Applied",
    });
    expect(memberRow(view, fleet(S2, { ms: 12.4 }))).toMatchObject({
      ms: "12 ms",
      state: "Applying…",
    });
    expect(memberRow(view, fleet(L1, { via: S2, ms: 0 }))).toEqual({
      address: "10.88.37.77",
      path: "Via server-2",
      ms: "0.0 ms",
      state: "The tunnel did not come up.",
    });
    expect(memberRow(view, fleet(S3))).toBeNull();
  });
});

describe("the worker's refusals", () => {
  it("the worker's own message comes first", () => {
    const refused = new ApiError(
      "server-2's keys differ.",
      422,
      "KEY_CHANGED",
      {
        code: "KEY_CHANGED",
        message: "server-2's keys differ.",
      },
    );
    expect(networkFailure(refused)).toBe("server-2's keys differ.");
  });

  it("each code without a message has one plain line", () => {
    const codes = [
      "VERSION_NOT_NEXT",
      "KEY_CHANGED",
      "NOT_REQUESTED",
      "NOT_READY",
      "WRONG_KIND",
      "RANGE_CHANGED",
      "ADDRESS_CHANGED",
      "ADDRESS_TAKEN",
    ];
    const lines = codes.map((code) =>
      networkFailure(new ApiError("worker text", 422, code)),
    );
    for (const line of lines) {
      expect(line).toMatch(/^[A-Z][^\n]+\.$/u);
      expect(line).not.toBe("worker text");
    }
    expect(new Set(lines).size).toBe(codes.length);
    expect(networkFailure(new ApiError("worker text", 409, "OTHER"))).toBe(
      "worker text",
    );
  });
});

describe("the Network page's changes", () => {
  it("only a server with a public endpoint can be the exit node", () => {
    const [s1, , l1] = network().members;
    expect(canExit(s1!)).toBe(true);
    expect(canExit({ ...s1!, nat: true })).toBe(false);
    expect(canExit({ ...s1!, endpoint: null })).toBe(false);
    expect(canExit(l1!)).toBe(false);
  });

  it("new keys replace the member's key and block the old one", () => {
    const base = network();
    const old = base.members[0]!;
    const fresh = wgKey();
    const next = withNewKey(base, S1, fresh, old.signer);
    expect(next.members[0]!.key).toBe(fresh);
    expect(next.blocked).toContain(old.key);
    expect(() => withNewKey(base, S1, fresh, wgKey())).toThrow(
      "server-1 reported different keys; nothing was changed",
    );
    expect(() => withNewKey(base, S3, fresh, old.signer)).toThrow(
      "That machine is not in the private network.",
    );
  });

  it("laptop DNS takes one or two IPv4 addresses", () => {
    expect(withDns(network(), ["9.9.9.9", ""]).dns).toEqual(["9.9.9.9"]);
    expect(withDns(network(), [" 1.1.1.1 ", "1.0.0.1"]).dns).toEqual([
      "1.1.1.1",
      "1.0.0.1",
    ]);
    expect(() => withDns(network(), ["", ""])).toThrow(
      "Enter at least one DNS address, like 1.1.1.1.",
    );
    expect(() => withDns(network(), ["dns.example.test", ""])).toThrow(
      "dns.example.test is not an IPv4 address.",
    );
  });

  it("the laptop install names the agent origin only when it differs", () => {
    const code = {
      code: "code-1",
      expiresAt: "2026-11-22T11:00:00Z",
      origin: "https://kry.example.test",
      endpoint: "https://kry.example.test",
      download: "https://example.test/agent-v0.7.92/krynodes-windows-amd64.exe",
    };
    expect(laptopInstall(code)).toBe(
      '& "$HOME\\Downloads\\krynodes-windows-amd64.exe" install --code code-1 --origin https://kry.example.test | Out-Host',
    );
    expect(
      laptopInstall({ ...code, endpoint: "https://agent.example.test" }),
    ).toContain("--endpoint https://agent.example.test");
  });

  it("a link test reads as plain lines, with -- for what was not measured", () => {
    const answer = {
      up: true,
      hasKey: true,
      version: 4,
      clock: 1,
      publicAddress: null,
      firewall: { lets: false, rule: null },
      handshakes: { sent: 2, received: 0, answered: 0, third: null },
      small: { sent: 5, lost: 5, ms: null },
      large: { passed: null, tried: [1420, 1400] },
    };
    expect(testLines(JSON.stringify(answer), "server-1", "server-2")).toEqual([
      "The tunnel on server-1 is up.",
      "server-1 knows server-2's key.",
      "The firewall on server-1 blocks the network port.",
      "server-2 did not answer a handshake.",
      "Round trip --, 5 of 5 lost.",
      "Largest packet --.",
    ]);
    expect(() => testLines("nope", "server-1", "server-2")).toThrow(
      "server-1 sent an answer Krynodes cannot read.",
    );
  });

  it("a link whose session is already up and passes pings does not read as unanswered", () => {
    const answer = {
      up: true,
      hasKey: true,
      version: 4,
      clock: 1,
      publicAddress: null,
      firewall: { lets: true, rule: null },
      handshakes: { sent: 0, received: 0, answered: 0, third: null },
      small: { sent: 5, lost: 0, ms: 1.8 },
      large: { passed: 1420, tried: [1420] },
    };
    expect(testLines(JSON.stringify(answer), "server-1", "server-2")[3]).toBe(
      "server-2 already has a working session; no new handshake was needed.",
    );
  });

  it("a fleet row shows the path through the network", () => {
    const names = new Map([[S1, "server-1"]]);
    const node = {
      address: "10.88.37.77",
      via: S1,
      ms: null,
    };
    expect(fleetRow(node, names)).toEqual({
      address: "10.88.37.77",
      path: "Via server-1",
      ms: "--",
    });
    expect(fleetRow({ ...node, via: null, ms: 3 }, names)).toMatchObject({
      path: "Direct",
      ms: "3.0 ms",
    });
    expect(fleetRow({ ...node, address: null }, names)).toBeNull();
  });

  it("a passkey that was not confirmed says so", () => {
    expect(networkFailure(new DOMException("no", "NotAllowedError"))).not.toBe(
      "no",
    );
  });
});

describe("the Network page's lookups", () => {
  it("the exit node comes from the loaded document only", () => {
    const base = network();
    expect(exitOf(undefined)).toBeUndefined();
    expect(exitOf(base)).toBeNull();
    expect(exitOf(withExit(base, S1))).toBe(S1);
  });

  it("Create Network starts with the first ready server", () => {
    const request = (node: string, patch: Partial<JoinRequest> = {}) =>
      ({
        node,
        name: node,
        kind: "server",
        hostname: null,
        os: null,
        key: null,
        signer: null,
        sealKey: null,
        ready: true,
        reason: null,
        since: "2026-11-22T00:00:00.000Z",
        ...patch,
      }) satisfies JoinRequest;
    expect(
      firstReadyServer([
        request(L1, { kind: "laptop" }),
        request(S1, { ready: false }),
        request(S2),
      ])?.node,
    ).toBe(S2);
    expect(firstReadyServer([request(S1, { ready: false })])).toBeUndefined();
  });

  it("a link is tested to every other member with an address", () => {
    const view = {
      members: [
        { node: S1, address: "10.88.37.14" },
        { node: S2, address: null },
        { node: L1, address: "10.88.37.77" },
      ],
    } as NetworkView;
    expect(testPeers(view, S1).map((one) => one.node)).toEqual([L1]);
  });

  it("counts the machines that asked to join", () => {
    expect(
      requestCount([
        { request: "requested" },
        { request: "rejected" },
        { request: null },
        { request: "requested" },
      ]),
    ).toBe(2);
    expect(requestCount(undefined)).toBe(0);
  });
});
