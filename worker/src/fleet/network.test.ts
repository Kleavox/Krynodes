import type { NetworkDocument } from "@krynodes/protocol";
import { describe, expect, it } from "vitest";

import { answering, hintsFor, meetingFor, msMoved, viaOf } from "./network";

const S1 = "11111111-1111-4111-8111-111111111111";
const S2 = "22222222-2222-4222-8222-222222222222";
const S3 = "44444444-4444-4444-8444-444444444444";
const L1 = "33333333-3333-4333-8333-333333333333";

const wgKey = (n: number) => Buffer.alloc(32, n).toString("base64");

type Member = NetworkDocument["members"][number];

const member = (node: string, n: number, extra: Partial<Member> = {}) =>
  ({
    node,
    name: `server-${n}`,
    address: `10.88.37.${n * 10}`,
    key: wgKey(n),
    signer: wgKey(n + 100),
    sealKey: Buffer.alloc(65, n).toString("base64url"),
    port: 51820,
    mtu: null,
    endpoint: `203.0.113.${n * 10}:51820`,
    nat: false,
    psk: {},
    ...extra,
  }) satisfies Member;

const document = {
  v: 1,
  version: 4,
  range: "10.88.37.0/24",
  port: 51820,
  mtu: 1420,
  members: [
    member(S3, 3),
    member(S1, 1),
    member(S2, 2, { nat: true, endpoint: null }),
    member(L1, 4, {
      kind: "laptop",
      nat: true,
      endpoint: null,
      relay: { [S2]: 51920 },
    }),
  ],
  blocked: [],
  allow: [],
} satisfies NetworkDocument;

describe("hub network", () => {
  it("a laptop meets where it asked, or at the lowest public member", () => {
    expect(meetingFor(document, S3)).toBe(S3);
    expect(meetingFor(document, S2)).toBe(S1);
    expect(meetingFor(document, undefined)).toBe(S1);
    const cut = {
      ...document,
      members: document.members.map((one) =>
        one.node === S1 ? { ...one, cut: true as const } : one,
      ),
    };
    expect(meetingFor(cut, S1)).toBe(S3);
  });

  it("a laptop's via is its meeting point while a member is behind NAT, and nothing otherwise", () => {
    expect(viaOf(document, {})).toEqual({ [L1]: S1 });
    expect(viaOf(document, { [L1]: S3 })).toEqual({ [L1]: S3 });
    const direct = {
      ...document,
      members: document.members.filter((one) => one.node !== S2),
    };
    expect(viaOf(direct, { [L1]: S3 })).toEqual({});
  });

  it("a member behind NAT hears every laptop's meeting point, a laptop hears its own and who is connected", () => {
    const behind = hintsFor(
      document,
      document.members[2]!,
      [{ node: S1, key: wgKey(51), signature: "c2ln" }],
      { [L1]: S3 },
      new Set([S2]),
    );
    expect(behind).toEqual({
      type: "hints",
      endpoints: [
        { key: wgKey(3), endpoint: "203.0.113.30:51820" },
        { key: wgKey(51), endpoint: "203.0.113.10:51820" },
      ],
      announced: [{ node: S1, key: wgKey(51), signature: "c2ln" }],
      meetings: [{ laptop: L1, via: S3 }],
      held: [],
      connected: [],
    });
    const laptop = hintsFor(
      document,
      document.members[3]!,
      [],
      {},
      new Set([S2]),
    );
    expect(laptop.meetings).toEqual([{ laptop: L1, via: S1 }]);
    expect(laptop.connected).toEqual([S2]);
    expect(
      hintsFor(document, document.members[1]!, [], {}, new Set()).meetings,
    ).toEqual([]);
  });

  it("a link answers on a round trip or a recent handshake, and a round trip moves by a fifth", () => {
    const now = Date.parse("2026-11-22T08:00:00.000Z");
    const link = {
      key: wgKey(2),
      handshake: now / 1000 - 179,
      rx: 0,
      tx: 0,
      endpoint: null,
      ms: null,
    };
    expect(answering(link, now)).toBe(true);
    expect(answering({ ...link, handshake: now / 1000 - 180 }, now)).toBe(
      false,
    );
    expect(answering({ ...link, handshake: null, ms: 2 }, now)).toBe(true);
    expect(msMoved(3.5, 3.9)).toBe(false);
    expect(msMoved(3.5, 4.5)).toBe(true);
    expect(msMoved(50, 59)).toBe(false);
    expect(msMoved(50, 61)).toBe(true);
    expect(msMoved(null, 3)).toBe(true);
    expect(msMoved(null, null)).toBe(false);
  });
});
