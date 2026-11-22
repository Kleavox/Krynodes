import { describe, expect, it } from "vitest";

import document from "./fixtures/network-document.json";
import laptopDocument from "./fixtures/network-document-laptop.json";
import {
  dnsName,
  laptopAddress6,
  links,
  NETWORK,
  networkArgsValid,
  networkBeatSchema,
  networkDocumentSchema,
  placeSchema,
  stackNetworkSchema,
  type NetworkDocument,
  type NetworkMember,
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
      relayPort: 51920,
      lastRelayPort: 52175,
      pool: "10.88.0.0/16",
      keepalive: 25,
      answerSeconds: 180,
      mtuMargin: 80,
    });
  });

  it("reads the shared laptop fixture with its relay port", () => {
    const parsed = networkDocumentSchema.safeParse(laptopDocument);
    expect(parsed.success).toBe(true);
    expect(parsed.data?.members[2]?.relay).toEqual({ [B]: 51920 });
    expect(parsed.data?.members[0]?.relay).toBeUndefined();
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

describe("laptops on the network", () => {
  const id = (n: number) => {
    const d = String(n);
    return `${d.repeat(8)}-${d.repeat(4)}-4${d.repeat(3)}-8${d.repeat(3)}-${d.repeat(12)}`;
  };
  const key = (n: number) => `${String(n).padStart(42, "A")}A=`;
  const member = (
    n: number,
    extra: Partial<NetworkMember> = {},
  ): NetworkMember => ({
    node: id(n),
    name: `server-${n}`,
    address: `10.88.0.${n}`,
    key: key(n),
    signer: key(n + 50),
    port: 51820,
    mtu: null,
    endpoint: extra.nat ? null : `203.0.113.${n}:51820`,
    nat: false,
    psk: {},
    ...extra,
  });
  const publicServer = member(1);
  const natServer = member(2, { nat: true });
  const laptop = member(3, { kind: "laptop", endpoint: null, nat: true });
  const otherLaptop = member(4, { kind: "laptop", endpoint: null, nat: true });

  const document = (
    members: NetworkMember[],
    extra: Record<string, unknown> = {},
  ) => {
    const behind = members.filter(
      (one) => one.kind !== "laptop" && one.nat && !one.cut,
    );
    let next = NETWORK.relayPort;
    return {
      v: 1,
      version: 1,
      range: "10.88.0.0/24",
      port: 51820,
      mtu: 1420,
      members: members.map((one) => ({
        ...one,
        psk: Object.fromEntries(
          members
            .filter((other) => other.node !== one.node && links(one, other))
            .map((other) => [other.node, "eyJ2IjoxfQ"]),
        ),
        ...(one.kind === "laptop"
          ? {
              relay: Object.fromEntries(
                behind.map((nat) => [nat.node, next++]),
              ),
            }
          : {}),
      })),
      blocked: [],
      ...extra,
    };
  };
  const parses = (value: unknown) =>
    networkDocumentSchema.safeParse(value).success;
  const withMembers = (
    members: NetworkMember[],
    change: (made: ReturnType<typeof document>) => void,
  ) => {
    const made = document(members);
    change(made);
    return made;
  };
  const named = (made: ReturnType<typeof document>, who: NetworkMember) =>
    made.members.find((one) => one.node === who.node)!;

  it("a laptop links with every member except another laptop", () => {
    expect(links(laptop, publicServer)).toBe(true);
    expect(links(publicServer, laptop)).toBe(true);
    expect(links(laptop, natServer)).toBe(true);
    expect(links(natServer, laptop)).toBe(true);
    expect(links(laptop, otherLaptop)).toBe(false);
    expect(links(publicServer, natServer)).toBe(true);
    expect(links(natServer, member(5, { nat: true }))).toBe(true);
  });

  it("a document with laptops parses, and each member holds a psk for exactly the members it links with", () => {
    const all = [publicServer, natServer, laptop, otherLaptop];
    expect(parses(document(all))).toBe(true);
    expect(Object.keys(named(document(all), laptop).psk).sort()).toEqual(
      [publicServer.node, natServer.node].sort(),
    );
    expect(Object.keys(named(document(all), natServer).psk).sort()).toEqual(
      [publicServer.node, laptop.node, otherLaptop.node].sort(),
    );
  });

  it("a document whose laptop and NAT member lack each other's psk is refused", () => {
    const all = [publicServer, natServer, laptop];
    expect(
      parses(
        withMembers(all, (made) => {
          delete named(made, laptop).psk[natServer.node];
        }),
      ),
    ).toBe(false);
    expect(
      parses(
        withMembers(all, (made) => {
          delete named(made, natServer).psk[laptop.node];
        }),
      ),
    ).toBe(false);
  });

  it("a document with a psk between two laptops is refused", () => {
    const all = [publicServer, laptop, otherLaptop];
    expect(parses(document(all))).toBe(true);
    expect(
      parses(
        withMembers(all, (made) => {
          named(made, laptop).psk[otherLaptop.node] = "eyJ2IjoxfQ";
          named(made, otherLaptop).psk[laptop.node] = "eyJ2IjoxfQ";
        }),
      ),
    ).toBe(false);
  });

  it("a document whose laptop lacks a psk for a public member is refused", () => {
    expect(
      parses(
        withMembers([publicServer, laptop], (made) => {
          named(made, laptop).psk = {};
        }),
      ),
    ).toBe(false);
  });

  it("a document without kinds parses as before", () => {
    expect(parses(document([publicServer, natServer]))).toBe(true);
    expect(parses(document([natServer, member(5, { nat: true })]))).toBe(true);
    expect(
      parses(
        withMembers([publicServer, natServer], (made) => {
          named(made, publicServer).psk = {};
        }),
      ),
    ).toBe(false);
  });

  describe("relay ports", () => {
    const secondNat = member(5, { nat: true });
    const cutNat = member(6, { nat: true, cut: true });
    const all = [publicServer, natServer, laptop];
    const relayOf = (made: ReturnType<typeof document>, who = laptop) =>
      named(made, who).relay!;

    it("a laptop holds exactly one port for each server behind NAT, from the relay range", () => {
      expect(parses(document(all))).toBe(true);
      expect(parses(document([publicServer, laptop]))).toBe(true);
      expect(
        parses(document([publicServer, natServer, secondNat, laptop])),
      ).toBe(true);
      expect(
        parses(
          document([publicServer, natServer, secondNat, laptop, otherLaptop]),
        ),
      ).toBe(true);
      for (const port of [NETWORK.relayPort, NETWORK.lastRelayPort]) {
        expect(
          parses(
            withMembers(all, (made) => {
              relayOf(made)[natServer.node] = port;
            }),
          ),
        ).toBe(true);
      }
    });

    it("a missing port, or a laptop without relay, is refused", () => {
      expect(
        parses(
          withMembers(all, (made) => {
            named(made, laptop).relay = {};
          }),
        ),
      ).toBe(false);
      expect(
        parses(
          withMembers(all, (made) => {
            delete named(made, laptop).relay;
          }),
        ),
      ).toBe(false);
      expect(
        parses(
          withMembers([publicServer, laptop], (made) => {
            delete named(made, laptop).relay;
          }),
        ),
      ).toBe(false);
      expect(
        parses(
          withMembers([publicServer, natServer, secondNat, laptop], (made) => {
            delete relayOf(made)[secondNat.node];
          }),
        ),
      ).toBe(false);
    });

    it("a duplicate port is refused on one laptop and across laptops", () => {
      expect(
        parses(
          withMembers([publicServer, natServer, secondNat, laptop], (made) => {
            relayOf(made)[secondNat.node] = relayOf(made)[natServer.node]!;
          }),
        ),
      ).toBe(false);
      expect(
        parses(
          withMembers(
            [publicServer, natServer, laptop, otherLaptop],
            (made) => {
              relayOf(made, otherLaptop)[natServer.node] =
                relayOf(made)[natServer.node]!;
            },
          ),
        ),
      ).toBe(false);
    });

    it("a port outside the relay range is refused", () => {
      for (const port of [
        0,
        NETWORK.lastPort,
        NETWORK.relayPort - 1,
        NETWORK.lastRelayPort + 1,
        51920.5,
        65536,
      ]) {
        expect(
          parses(
            withMembers(all, (made) => {
              relayOf(made)[natServer.node] = port;
            }),
          ),
        ).toBe(false);
      }
    });

    it("a port for anyone but a server behind NAT is refused", () => {
      const extra = (node: string) =>
        parses(
          withMembers(all, (made) => {
            relayOf(made)[node] = NETWORK.relayPort + 9;
          }),
        );
      expect(extra(publicServer.node)).toBe(false);
      expect(extra(laptop.node)).toBe(false);
      expect(extra(otherLaptop.node)).toBe(false);
      expect(extra(id(9))).toBe(false);
      expect(extra("not-an-id")).toBe(false);
    });

    it("a cut NAT member holds no port, and is refused one", () => {
      const members = [publicServer, natServer, cutNat, laptop];
      expect(parses(document(members))).toBe(true);
      expect(Object.keys(relayOf(document(members)))).toEqual([natServer.node]);
      expect(
        parses(
          withMembers(members, (made) => {
            relayOf(made)[cutNat.node] = NETWORK.relayPort + 9;
          }),
        ),
      ).toBe(false);
    });

    it("only a laptop has relay ports", () => {
      for (const who of [publicServer, natServer]) {
        expect(
          parses(
            withMembers(all, (made) => {
              named(made, who).relay = {};
            }),
          ),
        ).toBe(false);
      }
    });

    it("a relay of null is refused on every member", () => {
      for (const who of [publicServer, natServer, laptop]) {
        expect(
          parses(
            withMembers(all, (made) => {
              (named(made, who) as { relay?: unknown }).relay = null;
            }),
          ),
        ).toBe(false);
      }
    });
  });

  it("only laptop is a kind", () => {
    expect(
      parses(
        withMembers([publicServer, laptop], (made) => {
          (named(made, laptop) as { kind?: string }).kind = "server";
        }),
      ),
    ).toBe(false);
  });

  it("exit is refused on a laptop or a NAT member", () => {
    const exitOn = (who: NetworkMember) =>
      parses(
        withMembers([publicServer, natServer, laptop], (made) => {
          named(made, who).exit = true;
        }),
      );
    expect(exitOn(publicServer)).toBe(true);
    expect(exitOn(laptop)).toBe(false);
    expect(exitOn(natServer)).toBe(false);
    expect(
      parses(
        withMembers([publicServer], (made) => {
          (named(made, publicServer) as { exit?: boolean }).exit = false;
        }),
      ),
    ).toBe(false);
  });

  it("dns takes one or two IPv4 addresses", () => {
    const parsesWithDns = (dns: unknown) =>
      parses(document([publicServer, laptop], { dns }));
    expect(parsesWithDns(["1.1.1.1", "1.0.0.1"])).toBe(true);
    expect(parsesWithDns(["1.1.1.1"])).toBe(true);
    expect(parsesWithDns([])).toBe(false);
    expect(parsesWithDns(["::1"])).toBe(false);
    expect(parsesWithDns(["1.1.1.1", "1.0.0.1", "9.9.9.9"])).toBe(false);
    expect(parsesWithDns(["1.1.1"])).toBe(false);
    expect(parsesWithDns(["1.1.1.256"])).toBe(false);
    expect(parses(document([publicServer, laptop]))).toBe(true);
  });

  it("a laptop's IPv6 address follows its IPv4 one", () => {
    expect(NETWORK.pool6).toBe("fd88:88::/64");
    expect(laptopAddress6("10.88.3.9")).toBe("fd88:88::3:9");
    expect(laptopAddress6("10.88.0.254")).toBe("fd88:88::0:fe");
    expect(laptopAddress6("10.88.10.16")).toBe("fd88:88::a:10");
    expect(() => laptopAddress6("192.168.1.1")).toThrow();
    expect(() => laptopAddress6("10.88.3.255")).toThrow();
  });

  it("a laptop names its meeting point on the beat", () => {
    const beat = {
      version: 3,
      key: key(3),
      links: [],
      meet: id(1),
    };
    expect(networkBeatSchema.safeParse(beat).success).toBe(true);
    expect(
      networkBeatSchema.safeParse({ ...beat, meet: undefined }).success,
    ).toBe(true);
    expect(networkBeatSchema.safeParse({ ...beat, meet: "1" }).success).toBe(
      false,
    );
  });
});

describe("stacks on the network", () => {
  const serve = (value: unknown) =>
    stackNetworkSchema.safeParse({
      serves: [value],
      reaches: [],
      private: [],
    }).success;

  it("reports what a stack serves and reaches", () => {
    expect(
      stackNetworkSchema.safeParse({
        serves: [
          { port: "5432/tcp", all: true },
          { port: "9090/tcp", to: [A, B] },
        ],
        reaches: ["10.88.0.2:5432/tcp"],
        private: ["5432/tcp"],
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
});

describe("network actions", () => {
  it("limits a probe to 31 peers on the network's ports", () => {
    const peers = (count: number, port = 51820) =>
      Array.from(
        { length: count },
        (_, i) => `203.0.113.${i + 1}:${port}`,
      ).join(" ");
    expect(networkArgsValid("probe", { port: "51820", peers: peers(31) })).toBe(
      true,
    );
    expect(networkArgsValid("probe", { port: "51820", peers: peers(32) })).toBe(
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
});
