import { describe, expect, it } from "vitest";

import hashes from "./fixtures/document-hash.json";
import fingerprints from "./fixtures/fingerprint.json";
import allow from "./fixtures/network-allow.json";
import document from "./fixtures/network-document.json";
import laptopDocument from "./fixtures/network-document-laptop.json";
import {
  DEFAULT_RULE,
  dnsName,
  DOCUMENT_TAG,
  documentHash,
  joinFingerprint,
  laptopAddress6,
  links,
  NETWORK,
  networkArgsValid,
  networkDocumentSchema,
  networkInspectSchema,
  networkRekeySchema,
  pickAddresses,
  pickRange,
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

  it("names its parent by hash and marks cut members", () => {
    const parent = "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0";
    expect(
      changed((copy) => {
        copy.parent = parent;
        copy.members[1]!.cut = true;
      }),
    ).toBe(true);
    expect(
      changed((copy) => {
        copy.parent = "abc";
      }),
    ).toBe(false);
  });

  it("no longer knows the knock settings", () => {
    expect(
      changed((copy) => {
        (copy as { knocks?: unknown }).knocks = { scan: 5, stop: false };
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

describe("the connection rules of a document", () => {
  it.each(allow.valid)("reads $why", ({ document: value }) => {
    const parsed = networkDocumentSchema.safeParse(value);
    expect(parsed.success).toBe(true);
    expect(parsed.data).toEqual(value);
  });

  it.each(allow.invalid)("refuses $why", ({ document: value }) => {
    expect(networkDocumentSchema.safeParse(value).success).toBe(false);
  });

  it("holds rules in the fixtures both documents share", () => {
    expect(allow.valid.length).toBeGreaterThan(3);
    expect(allow.invalid.length).toBeGreaterThan(10);
    expect(document.allow).toHaveLength(1);
    expect(laptopDocument.allow).toHaveLength(1);
  });

  const base = allow.valid[0]!.document;
  const withRules = (rules: unknown[]) =>
    networkDocumentSchema.safeParse({ ...base, allow: rules }).success;
  const rule = (extra: Record<string, unknown>) => ({
    from: { group: "laptops" },
    to: { group: "servers" },
    ports: "all",
    ...extra,
  });

  it("takes 64 rules and no more", () => {
    const many = (size: number) =>
      Array.from({ length: size }, (_, i) => rule({ ports: [`${i + 1}/tcp`] }));
    expect(withRules(many(64))).toBe(true);
    expect(withRules(many(65))).toBe(false);
  });

  it("takes eight ports in a rule and no more, and each one whole", () => {
    const ports = (size: number) =>
      Array.from({ length: size }, (_, i) => `${i + 1}/tcp`);
    expect(withRules([rule({ ports: ports(8) })])).toBe(true);
    expect(withRules([rule({ ports: ports(9) })])).toBe(false);
    for (const good of ["1/tcp", "65535/udp", "7-8/tcp", "1-65535/tcp"]) {
      expect(withRules([rule({ ports: [good] })]), good).toBe(true);
    }
    for (const bad of [
      "0/tcp",
      "65536/tcp",
      "0-80/tcp",
      "80-65536/tcp",
      "90-80/tcp",
      "80-80/tcp",
      "7-7/udp",
      "080/tcp",
      "00080/tcp",
      "0080/tcp",
      "080-90/tcp",
      "80-090/tcp",
      "80",
      "80/",
      "80/sctp",
      "80/TCP",
      "80-/tcp",
      "-80/tcp",
      "1-2-3/tcp",
      "123456/tcp",
      " 80/tcp",
    ]) {
      expect(withRules([rule({ ports: [bad] })]), bad).toBe(false);
    }
  });

  it("takes one spelling for a port and no overlap inside a rule", () => {
    for (const ok of [
      ["80/tcp", "80/udp"],
      ["1-99/tcp", "100-200/tcp"],
      ["1-100/tcp", "1-100/udp"],
      ["22/tcp", "80/tcp", "443/tcp", "53/udp"],
    ]) {
      expect(withRules([rule({ ports: ok })]), ok.join()).toBe(true);
    }
    for (const bad of [
      ["1-100/tcp", "50/tcp"],
      ["50/tcp", "1-100/tcp"],
      ["1-100/tcp", "100-200/tcp"],
      ["10-20/tcp", "15-30/tcp"],
      ["80/tcp", "80/tcp"],
      ["80/udp", "70-90/udp"],
    ]) {
      expect(withRules([rule({ ports: bad })]), bad.join()).toBe(false);
    }
  });

  it("sees the same rule through the order of its ports", () => {
    const first = { node: laptopDocument.members[0]!.node };
    const second = { node: laptopDocument.members[1]!.node };
    const open = (ports: string[]) => ({ from: first, to: second, ports });
    expect(
      withRules([open(["22/tcp", "80/tcp"]), open(["22/tcp", "53/udp"])]),
    ).toBe(true);
    expect(
      withRules([open(["22/tcp", "80/tcp"]), open(["80/tcp", "22/tcp"])]),
    ).toBe(false);
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
    sealKey: String(n).repeat(87),
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
      allow: [],
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
    const parent = "a".repeat(43);
    for (const [args, valid] of [
      [{ range: "10.88.3.0/24", port: "51821" }, true],
      [{ range: "10.88.3.0/24", port: "51821", parent }, true],
      [{ range: "10.88.3.0/24", port: "51821", parent: "" }, false],
      [{ range: "10.88.3.0/24", port: "51821", parent: "a".repeat(42) }, false],
      [{ range: "10.88.3.0/24", port: "51821", other: parent }, false],
    ] as const) {
      expect(networkArgsValid("prepare", args), JSON.stringify(args)).toBe(
        valid,
      );
    }
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

describe("join fingerprints and random picks", () => {
  const seeded = (seed: number) => () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };

  it("fingerprint matches the shared fixture", async () => {
    expect(fingerprints.length).toBeGreaterThanOrEqual(2);
    for (const one of fingerprints) {
      expect(await joinFingerprint(one.key, one.signer, one.sealKey)).toBe(
        one.fingerprint,
      );
    }
  });

  it("a fingerprint is four groups of four capital hex digits and follows every key", async () => {
    const [one] = fingerprints;
    const found = await joinFingerprint(one!.key, one!.signer, one!.sealKey);
    expect(found).toMatch(/^[0-9A-F]{4}(-[0-9A-F]{4}){3}$/u);
    const other = fingerprints[1]!;
    for (const changed of [
      [other.key, one!.signer, one!.sealKey],
      [one!.key, other.signer, one!.sealKey],
      [one!.key, one!.signer, other.sealKey],
    ] as const) {
      expect(await joinFingerprint(...changed)).not.toBe(found);
    }
  });

  it("a rekey answers the new key, the signer and the fingerprint over them", () => {
    const [one] = fingerprints;
    const answer = {
      key: one!.key,
      signer: one!.signer,
      fingerprint: one!.fingerprint,
      signature: "c2lnbmF0dXJl",
    };
    expect(networkRekeySchema.safeParse(answer).success).toBe(true);
    for (const broken of [
      { ...answer, fingerprint: undefined },
      { ...answer, signer: undefined },
      { ...answer, fingerprint: "bffc-fa17-2a62-f0f5" },
      { ...answer, fingerprint: "BFFC-FA17-2A62" },
      { ...answer, private: one!.key },
    ]) {
      expect(networkRekeySchema.safeParse(broken).success).toBe(false);
    }
  });

  describe("pickRange", () => {
    const rangeOf = (x: number) => `10.88.${x}.0/24`;

    it("pickRange never returns a range that overlaps a used subnet", () => {
      const used = [
        "10.88.3.0/24",
        "10.88.200.17",
        "10.88.64.9/26",
        "10.88.8.0/22",
        "10.88.128.0/17",
        "192.168.1.0/24",
        "fd00::/8",
      ];
      const blocked = new Set([3, 200, 64, 8, 9, 10, 11]);
      for (let x = 128; x < 256; x += 1) blocked.add(x);
      const random = seeded(7);
      const seen = new Set<string>();
      for (let draw = 0; draw < 1000; draw += 1) {
        const range = pickRange(used, random);
        expect(range).not.toBeNull();
        const x = Number(range!.split(".")[2]);
        expect(range).toBe(rangeOf(x));
        expect(blocked.has(x), range!).toBe(false);
        seen.add(range!);
      }
      expect(seen.size).toBeGreaterThan(40);
    });

    it("pickRange treats a host address with a prefix as its whole subnet", () => {
      const used = Array.from({ length: 255 }, (_, x) => `10.88.${x}.5/24`);
      expect(pickRange(used, seeded(1))).toBe(rangeOf(255));
    });

    it("pickRange returns null when every /24 is used", () => {
      expect(pickRange(["10.88.0.0/16"], seeded(1))).toBeNull();
      expect(pickRange(["10.0.0.0/8"], seeded(1))).toBeNull();
      expect(pickRange(["0.0.0.0/0"], seeded(1))).toBeNull();
      expect(
        pickRange(
          Array.from({ length: 256 }, (_, x) => rangeOf(x)),
          seeded(1),
        ),
      ).toBeNull();
    });

    it("pickRange takes any of the 256 when nothing is used", () => {
      expect(pickRange([], () => 0)).toBe(rangeOf(0));
      expect(pickRange([], () => 0.999999)).toBe(rangeOf(255));
      expect(
        pickRange(["10.89.0.0/16", "fd00::/8", "fe80::1/64"], () => 0),
      ).toBe(rangeOf(0));
    });

    it("pickRange names an entry it cannot read instead of skipping it", () => {
      for (const bad of [
        "not an address",
        "",
        "10.88.3.0/33",
        "10.88.3.0/255.255.255.0",
        "10.88.3.0/",
        "10.88.3.0/-1",
        "10.88.3",
        "10.88.3.256",
        "10.88.3.0.1/24",
        " 10.88.3.0/24",
        "10.88.3.0/24 ",
      ]) {
        expect(() => pickRange(["10.88.1.0/24", bad], seeded(1)), bad).toThrow(
          RangeError,
        );
        expect(() => pickRange([bad], seeded(1)), bad).toThrow(
          `${bad} is not an IPv4 address or subnet`,
        );
      }
    });

    it("pickRange refuses a random number outside 0 up to 1", () => {
      for (const value of [1, 1.5, -0.1, Number.NaN, Infinity, -Infinity]) {
        expect(() => pickRange([], () => value), String(value)).toThrow(
          RangeError,
        );
      }
      expect(pickRange([], () => 0.9999999999999999)).toBe(rangeOf(255));
    });
  });

  describe("pickAddresses", () => {
    const range = "10.88.37.0/24";
    const host = (address: string) => Number(address.split(".")[3]);
    const hosts = (from: number, to: number) =>
      Array.from({ length: to - from + 1 }, (_, i) => `10.88.37.${from + i}`);

    it("pickAddresses prefers never-used hosts", () => {
      const taken = hosts(1, 3);
      const freed = hosts(4, 250);
      const never = new Set([251, 252, 253, 254]);
      const random = seeded(3);
      for (let draw = 0; draw < 200; draw += 1) {
        const picked = pickAddresses(range, taken, freed, 4, random);
        expect(new Set(picked.map(host))).toEqual(never);
      }
      const more = pickAddresses(range, taken, freed, 6, random);
      expect(new Set(more).size).toBe(6);
      expect([...never].every((one) => more.map(host).includes(one))).toBe(
        true,
      );
      expect(more.every((one) => !taken.includes(one))).toBe(true);
    });

    it("pickAddresses falls back to freed hosts", () => {
      const taken = hosts(1, 200);
      const freed = hosts(201, 254);
      const picked = pickAddresses(range, taken, freed, 3, seeded(5));
      expect(picked).toHaveLength(3);
      expect(new Set(picked).size).toBe(3);
      expect(picked.every((one) => freed.includes(one))).toBe(true);
      expect(pickAddresses(range, [], [], 0, seeded(1))).toEqual([]);
    });

    it("pickAddresses never returns .0 or .255", () => {
      const random = seeded(11);
      const everything = pickAddresses(range, [], [], 254, random);
      expect(new Set(everything.map(host))).toEqual(
        new Set(Array.from({ length: 254 }, (_, i) => i + 1)),
      );
      for (let draw = 0; draw < 1000; draw += 1) {
        const [one] = pickAddresses(range, [], [], 1, random);
        expect(host(one!)).toBeGreaterThanOrEqual(1);
        expect(host(one!)).toBeLessThanOrEqual(254);
        expect(one!.startsWith("10.88.37.")).toBe(true);
      }
    });

    it("pickAddresses never returns a taken host, and says when too few are free", () => {
      const taken = hosts(1, 253);
      expect(pickAddresses(range, taken, [], 1, seeded(1))).toEqual([
        "10.88.37.254",
      ]);
      expect(() => pickAddresses(range, taken, [], 2, seeded(1))).toThrow(
        RangeError,
      );
      expect(() =>
        pickAddresses(range, hosts(1, 254), hosts(1, 254), 1, seeded(1)),
      ).toThrow(RangeError);
      expect(
        pickAddresses(range, ["10.88.38.5"], ["10.88.38.6"], 254, seeded(1)),
      ).toHaveLength(254);
    });

    it("pickAddresses refuses a random number outside 0 up to 1", () => {
      for (const value of [1, 1.5, -0.1, Number.NaN, Infinity, -Infinity]) {
        expect(
          () => pickAddresses(range, [], [], 1, () => value),
          String(value),
        ).toThrow(RangeError);
      }
      expect(pickAddresses(range, [], [], 1, () => 0.9999999999999999)).toEqual(
        ["10.88.37.254"],
      );
    });

    it("pickAddresses refuses a range that is not a /24 of the pool", () => {
      for (const bad of ["10.89.0.0/24", "10.88.0.0/16", "10.88.0.1/24", ""]) {
        expect(() => pickAddresses(bad, [], [], 1, seeded(1)), bad).toThrow(
          RangeError,
        );
      }
      expect(() => pickAddresses(range, [], [], -1, seeded(1))).toThrow(
        RangeError,
      );
    });
  });
});

describe("what every side of a document shares", () => {
  it("documentHash matches the shared fixture", async () => {
    expect(hashes.length).toBeGreaterThan(0);
    for (const { body, hash } of hashes) {
      const padded = body.replaceAll("-", "+").replaceAll("_", "/");
      const bytes = Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
      expect(await documentHash(bytes)).toBe(hash);
    }
  });

  it("the default rule opens every server to every laptop and parses", () => {
    expect(DEFAULT_RULE).toEqual({
      from: { group: "laptops" },
      to: { group: "servers" },
      ports: "all",
    });
    expect(DOCUMENT_TAG).toBe("krynodes-document-v1\n");
    expect(
      changed((copy) => {
        copy.allow = [DEFAULT_RULE];
      }),
    ).toBe(true);
  });

  it("an inspect answer names the public address or null", () => {
    const answer = {
      kernel: { ok: true, version: "6.8", reason: null },
      tools: true,
      iptables: true,
      used: [],
      others: [],
      port: 51820,
      mtu: 1500,
      public: "203.0.113.21",
    };
    expect(networkInspectSchema.safeParse(answer).success).toBe(true);
    expect(
      networkInspectSchema.safeParse({ ...answer, public: null }).success,
    ).toBe(true);
    for (const bad of ["203.0.113.21:51820", "2001:db8::1", "server-1"]) {
      expect(
        networkInspectSchema.safeParse({ ...answer, public: bad }).success,
      ).toBe(false);
    }
    const { public: _, ...without } = answer;
    expect(networkInspectSchema.safeParse(without).success).toBe(false);
  });
});
