import { describe, expect, it } from "vitest";

import document from "./fixtures/network-document.json";
import {
  agentActionSchema,
  agentHeartbeatSchema,
  stackEntrySchema,
} from "./index";
import {
  dnsName,
  NETWORK,
  networkArgsValid,
  networkDocumentSchema,
  placeSchema,
  stackNetworkSchema,
  type NetworkDocument,
} from "./network";

const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";

const changed = (change: (copy: NetworkDocument) => void) => {
  const copy = JSON.parse(JSON.stringify(document)) as NetworkDocument;
  change(copy);
  return networkDocumentSchema.safeParse(copy).success;
};

describe("the network document", () => {
  it("reads the shared fixture", () => {
    expect(networkDocumentSchema.safeParse(document).success).toBe(true);
    expect(NETWORK).toMatchObject({
      interface: "kry0",
      port: 51820,
      lastPort: 51919,
      pool: "10.88.0.0/16",
      keepalive: 25,
      answerSeconds: 180,
      mtuMargin: 80,
    });
  });

  it("refuses an address outside the range or given twice", () => {
    expect(
      changed((copy) => {
        copy.members[1]!.address = "10.89.0.2";
      }),
    ).toBe(false);
    expect(
      changed((copy) => {
        copy.members[1]!.address = "10.88.0.1";
      }),
    ).toBe(false);
    expect(
      changed((copy) => {
        copy.members[1]!.address = "10.88.0.255";
      }),
    ).toBe(false);
  });

  it("names its parent by hash, marks cut members and carries the knock settings", () => {
    const parent = "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0";
    expect(
      changed((copy) => {
        copy.parent = parent;
        copy.members[1]!.cut = true;
        copy.knocks = { scan: 5, stop: false };
      }),
    ).toBe(true);
    expect(
      changed((copy) => {
        copy.parent = "abc";
      }),
    ).toBe(false);
    expect(
      changed((copy) => {
        copy.knocks = { scan: 7 as 5, stop: true };
      }),
    ).toBe(false);
  });

  it("wants a preshared key for every other member and no one else", () => {
    expect(
      changed((copy) => {
        copy.members[0]!.psk = {
          "33333333-3333-4333-8333-333333333333": "eyJ2IjoxfQ",
        };
      }),
    ).toBe(false);
    expect(
      changed((copy) => {
        copy.members[0]!.psk = {};
      }),
    ).toBe(false);
  });

  it("refuses a member whose key is blocked", () => {
    expect(
      changed((copy) => {
        copy.blocked = [copy.members[0]!.key];
      }),
    ).toBe(false);
  });

  it("makes a name DNS-safe", () => {
    expect(dnsName("VPS_2 (Singapore)")).toBe("vps-2-singapore");
    expect(dnsName("---")).toBe("server");
  });
});

describe("stacks on the network", () => {
  const stack = {
    project: "tracker",
    directory: "/var/lib/krynodes/compose/tracker",
    running: 1,
    total: 1,
    compose: true,
    rollback: false,
    access: "contained",
  };
  const serve = (value: unknown) =>
    stackEntrySchema.safeParse({
      ...stack,
      network: { serves: [value], reaches: [], private: [] },
    }).success;

  it("reports what a stack serves and reaches", () => {
    expect(
      stackEntrySchema.safeParse({
        ...stack,
        network: {
          serves: [
            { port: "5432/tcp", all: true },
            { port: "9090/tcp", to: [A, B] },
          ],
          reaches: ["10.88.0.2:5432/tcp"],
          private: ["5432/tcp"],
        },
      }).success,
    ).toBe(true);
    expect(NETWORK).toMatchObject({ variable: "KRY_PRIVATE_IP", places: 32 });
  });

  it("serves a port to all servers or to chosen ones, never both or neither", () => {
    expect(serve({ port: "5432/tcp", all: true, to: [A] })).toBe(false);
    expect(serve({ port: "5432/tcp" })).toBe(false);
    expect(serve({ port: "5432/tcp", to: [] })).toBe(false);
    expect(serve({ port: "5432", all: true })).toBe(false);
  });

  it("takes places as addresses, at most 32", () => {
    expect(placeSchema.safeParse("10.88.0.2:5432/tcp").success).toBe(true);
    expect(placeSchema.safeParse("vps-2:5432/tcp").success).toBe(false);
    expect(placeSchema.safeParse("10.88.0.2:5432").success).toBe(false);
    expect(
      stackNetworkSchema.safeParse({
        serves: [],
        reaches: Array.from({ length: 33 }, (_, i) => `10.88.0.2:${i + 1}/tcp`),
        private: [],
      }).success,
    ).toBe(false);
  });

  it("changes a stack's reach only with a signature", () => {
    const reach = {
      id: "55555555-5555-4555-8555-555555555555",
      kind: "compose",
      name: "shop",
      action: "reach",
      expiresAt: "2026-10-26T10:00:00.000Z",
    };
    const signed = {
      grant: {
        grant: "Z3JhbnQ",
        credentialId: "Y3JlZA",
        authenticatorData: "YXV0aA",
        clientDataJSON: "Y2xpZW50",
        signature: "c2ln",
      },
      command: "Y29tbWFuZA",
      signature: "c2lnbmF0dXJl",
    };
    expect(agentActionSchema.safeParse({ ...reach, signed }).success).toBe(
      true,
    );
    expect(agentActionSchema.safeParse(reach).success).toBe(false);
  });
});

describe("network actions", () => {
  const action = (name: string, verb: string, signed?: unknown) => ({
    id: "44444444-4444-4444-8444-444444444444",
    kind: "network",
    name,
    action: verb,
    expiresAt: "2026-10-26T10:00:00.000Z",
    ...(signed === undefined ? {} : { signed }),
  });

  it("reads kry0 without a signature and changes it only with one", () => {
    expect(agentActionSchema.safeParse(action("kry0", "inspect")).success).toBe(
      true,
    );
    expect(agentActionSchema.safeParse(action("kry0", "prepare")).success).toBe(
      false,
    );
    expect(agentActionSchema.safeParse(action("wg0", "inspect")).success).toBe(
      false,
    );
  });

  it("limits a probe to 16 peers on the network's ports", () => {
    const peers = (count: number, port = 51820) =>
      Array.from(
        { length: count },
        (_, i) => `203.0.113.${i + 1}:${port}`,
      ).join(" ");
    expect(networkArgsValid("probe", { port: "51820", peers: peers(16) })).toBe(
      true,
    );
    expect(networkArgsValid("probe", { port: "51820", peers: peers(17) })).toBe(
      false,
    );
    expect(
      networkArgsValid("probe", { port: "51820", peers: peers(1, 52000) }),
    ).toBe(false);
    expect(networkArgsValid("probe", { port: "53", peers: peers(1) })).toBe(
      false,
    );
    expect(networkArgsValid("inspect", {})).toBe(true);
    expect(
      networkArgsValid("test", {
        peer: B,
        address: "10.88.0.2",
        mtu: "1420",
      }),
    ).toBe(true);
    expect(
      networkArgsValid("test", { peer: A, address: "8.8.8.8", mtu: "1420" }),
    ).toBe(false);
  });

  it("carries the links on the heartbeat", () => {
    const beat = {
      nodeId: A,
      hostname: "vps-1",
      operatingSystem: "linux",
      architecture: "amd64",
      agentVersion: "0.7.0",
      metrics: {
        cpuPercent: null,
        memoryUsedBytes: null,
        memoryTotalBytes: null,
        diskUsedBytes: null,
        diskTotalBytes: null,
        load1: null,
        load5: null,
        load15: null,
        uptimeSeconds: null,
      },
      network: {
        version: 3,
        key: document.members[0]!.key,
        links: [
          {
            key: document.members[1]!.key,
            handshake: 1_793_000_000,
            rx: 310,
            tx: 1200,
            endpoint: null,
            ms: 4,
          },
        ],
      },
    };
    expect(agentHeartbeatSchema.safeParse(beat).success).toBe(true);
  });
});
