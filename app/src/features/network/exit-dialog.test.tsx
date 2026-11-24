import { networkDocumentSchema } from "@krynodes/protocol";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { NetworkView } from "@/types";

import { exitChange } from "./change-dialog";
import { MemberList, memberActions } from "./members";

const S1 = "11111111-1111-4111-8111-111111111111";
const S2 = "22222222-2222-4222-8222-222222222222";
const L1 = "33333333-3333-4333-8333-333333333333";
const AT = "2026-11-22T00:00:00.000Z";
const KEY = "A".repeat(43) + "=";
const SEAL = "s".repeat(87);

type Member = NetworkView["members"][number];

const member = (node: string, name: string, patch: Partial<Member> = {}) =>
  ({
    node,
    name,
    kind: "server",
    state: "in",
    address: "10.88.37.14",
    key: KEY,
    signer: KEY,
    port: 51820,
    mtu: null,
    endpoint: "203.0.113.10:51820",
    nat: false,
    applied: 4,
    failure: null,
    announced: null,
    since: AT,
    joinedAt: AT,
    ...patch,
  }) satisfies Member;

const s1 = member(S1, "server-1");
const s2 = member(S2, "server-2", {
  address: "10.88.37.201",
  endpoint: null,
  nat: true,
});
const l1 = member(L1, "laptop-1", {
  kind: "laptop",
  address: "10.88.37.77",
  endpoint: null,
  nat: true,
});

const labels = (one: Member, exit: string | null | undefined = null) =>
  memberActions(one, exit)
    .filter((item) => !item.disabled)
    .map((item) => item.label);

describe("the exit node", () => {
  it("the Network page's ⋯ offers Exit Node for Laptops", () => {
    expect(labels(s1)).toEqual([
      "Exit Node for Laptops",
      "Test Link",
      "New Keys",
      "Remove from Network",
    ]);
    expect(labels(s2)).toEqual([
      "Test Link",
      "New Keys",
      "Remove from Network",
    ]);
    expect(labels(l1)).toEqual(["Remove from Network"]);
    expect(labels(s2, S2)).toEqual([
      "Exit Node for Laptops",
      "Test Link",
      "New Keys",
      "Remove from Network",
    ]);
    expect(
      memberActions(s1, undefined)
        .filter((item) => !item.disabled)
        .map((item) => item.label),
    ).toEqual(["Test Link", "Remove from Network"]);
    expect(
      memberActions(s1, undefined)
        .filter((item) => item.disabled)
        .map((item) => item.label),
    ).toEqual(["Exit Node for Laptops", "New Keys"]);
    const view: NetworkView = {
      network: {
        range: "10.88.37.0/24",
        port: 51820,
        mtu: 1420,
        version: 4,
        dns: null,
        deleted: false,
      },
      members: [s1, s2, l1],
      requests: [],
      rejected: [],
      allow: [],
      links: [],
    };
    const html = renderToStaticMarkup(
      <MemberList view={view} nodes={[]} exit={S1} onAsk={() => {}} />,
    );
    expect(html).toContain('aria-label="Actions for server-1"');
    expect(html).toContain("Exit Node");
    expect(html).toContain("10.88.37.201");
    expect(html).toContain("Applied");
  });

  it("turning it on signs a document with that server as the only exit", () => {
    const document = networkDocumentSchema.parse({
      v: 1,
      version: 4,
      range: "10.88.37.0/24",
      port: 51820,
      mtu: 1420,
      members: [
        {
          node: S1,
          name: "server-1",
          address: "10.88.37.14",
          key: KEY,
          signer: KEY,
          sealKey: SEAL,
          port: 51820,
          mtu: null,
          endpoint: "203.0.113.10:51820",
          nat: false,
          psk: {},
        },
      ],
      blocked: [],
      allow: [],
    });
    const on = exitChange(s1, true);
    expect(on.confirm).toBe("Turn On");
    expect(on.change).toBe("Make server-1 the exit node for laptops");
    expect(on.edit(document).members[0]!.exit).toBe(true);
    const off = exitChange(s1, false);
    expect(off.confirm).toBe("Turn Off");
    expect(off.edit(on.edit(document)).members[0]!.exit).toBeUndefined();
  });
});
