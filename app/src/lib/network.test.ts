import {
  NETWORK,
  type NetworkDocument,
  type NetworkInspect,
  type NetworkTest,
  type StackNetwork,
} from "@krynodes/protocol";
import { describe, expect, it } from "vitest";

import type {
  ActionRecord,
  NetworkServer,
  NetworkView,
  NodeRecord,
} from "../types";
import { usePrivateAddress } from "./compose";
import { actionLine, historyText } from "./history";
import {
  buildDocument,
  candidateState,
  checkRows,
  checkSuggestions,
  deleteLines,
  firewallRow,
  fixLabel,
  moveBlock,
  moveProblem,
  networkActionText,
  networkHint,
  opensBox,
  parsePlaces,
  placeText,
  privateIpProblem,
  reachedStacks,
  readServes,
  servesArg,
  servesProblem,
  heldNote,
  heldRows,
  hostingOf,
  joinerOf,
  leaveParagraph,
  linkProgress,
  missingSeals,
  mostLikely,
  navNetworkCount,
  networkChecks,
  networkFacts,
  networkText,
  peerRows,
  pickMtu,
  pickRange,
  portLine,
  preparedOf,
  presenceOf,
  probeOf,
  probePlan,
  problemRows,
  progressLinks,
  progressRows,
  rekeyNote,
  removeLines,
  seatOf,
  serverRow,
  testEnd,
  testOthers,
  testPairs,
  testSummary,
  waitingLine,
  testRows,
  testingText,
  type TestEnd,
  baseOf,
  wrongPortRows,
} from "./network";
import { b64url } from "./passkeys";
import { openSealed, sealPair } from "./seal";

const NOW = Date.parse("2026-10-26T12:00:00Z");
const SEC = NOW / 1000;
const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const C = "33333333-3333-4333-8333-333333333333";
const D = "44444444-4444-4444-8444-444444444444";
const E = "55555555-5555-4555-8555-555555555555";

const key = (n: number) => btoa(String.fromCharCode(...new Array(32).fill(n)));

const server = (
  nodeId: string,
  name: string,
  address: string,
  endpoint: string | null,
  extra: Partial<NetworkServer> = {},
): NetworkServer => ({
  nodeId,
  name,
  state: "in",
  address,
  port: Number(endpoint?.split(":")[1] ?? 51820),
  mtu: null,
  key: key(address.length + Number(address.split(".")[3])),
  signer: key(100 + Number(address.split(".")[3])),
  endpoint,
  nat: endpoint === null,
  announced: null,
  since: "2026-10-20T00:00:00Z",
  joinedAt: "2026-10-20T00:00:00Z",
  points: [],
  ...extra,
});

const vps1 = server(A, "vps-1", "10.88.0.1", "141.95.0.21:51820", {
  points: [{ stack: "backup", target: "vps-3.kry" }],
});
const vps2 = server(B, "vps-2", "10.88.0.2", "51.79.0.11:51821");
const vps3 = server(C, "vps-3", "10.88.0.3", "203.0.113.7:51820");
const pivox = server(D, "pivox", "10.88.0.4", null);

const link = (peer: NetworkServer, ago: number, ms: number | null = 4) => ({
  key: peer.key,
  handshake: SEC - ago,
  rx: 310 * 1024 ** 2,
  tx: Math.round(1.2 * 1024 ** 3),
  endpoint: null,
  ms,
});

function view(extra: Partial<NetworkView> = {}): NetworkView {
  return {
    network: {
      range: "10.88.0.0/24",
      port: 51820,
      mtu: 1420,
      version: 4,
      createdAt: "2026-10-20T21:02:00Z",
      createdBy: "owner@example.test",
    },
    version: 4,
    document: null,
    body: null,
    quarantined: [],
    wrongPorts: [],
    members: [vps1, vps2, vps3, pivox],
    waiting: [],
    links: [
      { a: A, b: B, answering: true, since: "2026-10-26T10:00:00Z" },
      { a: A, b: C, answering: true, since: "2026-10-26T10:00:00Z" },
      { a: B, b: C, answering: false, since: "2026-10-26T11:54:00Z" },
    ],
    live: {
      [B]: {
        at: NOW - 20_000,
        links: [link(vps1, 14), link(vps3, 400, null), link(pivox, 7200, null)],
      },
    },
    held: [],
    changes: [],
    ...extra,
  };
}

const presence = {
  [A]: { online: true, seenAt: NOW - 30_000 },
  [B]: { online: true, seenAt: NOW - 20_000 },
  [C]: { online: true, seenAt: NOW - 10_000 },
  [D]: { online: false, seenAt: NOW - 2 * 3_600_000 },
};

describe("the Network page", () => {
  it("lists only a link between two online servers as a problem", () => {
    expect(problemRows(view(), presence, NOW)).toEqual([
      {
        a: B,
        b: C,
        pair: "vps-2 ↔ vps-3",
        text: "No answer for 6 min",
        detail:
          "Both are online and reach the others, so the path between them is the problem.",
      },
    ]);
    expect(navNetworkCount(view(), presence, NOW)).toBe(1);
  });

  it("counts no offline server in anyone's Links and shows -- for it", () => {
    expect(serverRow(vps2, view(), presence, NOW)).toEqual({
      name: "vps-2",
      address: "10.88.0.2 · vps-2.kry",
      endpoint: "51.79.0.11:51821",
      links: "Links 1 of 2",
      short: true,
      offline: null,
    });
    expect(serverRow(vps1, view(), presence, NOW)).toMatchObject({
      links: "Links 2 of 2",
      short: false,
    });
    expect(serverRow(pivox, view(), presence, NOW)).toEqual({
      name: "pivox",
      address: "10.88.0.4 · pivox.kry",
      endpoint: "Behind NAT",
      links: "--",
      short: false,
      offline:
        "Offline 2h. It picks up the last change when it is back; nothing to approve again.",
    });
  });

  it("says how each peer answers, never 0 ms for what was not measured", () => {
    expect(peerRows(vps2, view(), presence, NOW)).toEqual([
      {
        nodeId: A,
        text: "vps-1 · answered 14s ago · 4 ms · ↑ 1.2 GB ↓ 310 MB",
        test: false,
        state: "up",
      },
      {
        nodeId: C,
        text: "vps-3 · no answer for 6 min",
        test: true,
        state: "down",
      },
      {
        nodeId: D,
        text: "pivox · offline, last answer 2h ago · --",
        test: false,
        state: "offline",
      },
    ]);
  });

  it("says two servers behind NAT cannot reach each other instead of no answer", () => {
    const calisto = server(E, "calisto", "10.88.0.5", null);
    const both = view({
      members: [vps1, pivox, calisto],
      links: [
        { a: A, b: D, answering: true, since: "2026-10-26T11:00:00Z" },
        { a: D, b: E, answering: false, since: "2026-10-26T11:00:00Z" },
      ],
      live: {},
    });
    const online = {
      [A]: { online: true, seenAt: NOW },
      [D]: { online: true, seenAt: NOW },
      [E]: { online: true, seenAt: NOW },
    };
    expect(peerRows(pivox, both, online, NOW)).toContainEqual({
      nodeId: E,
      text: "calisto · Both are behind NAT and cannot reach each other",
      test: false,
      state: "nat",
    });
    expect(problemRows(both, online, NOW)).toEqual([]);
    expect(serverRow(pivox, both, online, NOW).links).toBe("Links 1 of 1");
  });

  it("counts no link to a quarantined member, which is cut off on purpose", () => {
    const cut = view({
      quarantined: [C],
      links: [
        { a: A, b: B, answering: true, since: "2026-10-26T10:00:00Z" },
        { a: A, b: C, answering: false, since: "2026-10-26T11:54:00Z" },
        { a: B, b: C, answering: false, since: "2026-10-26T11:54:00Z" },
      ],
    });
    expect(problemRows(cut, presence, NOW)).toEqual([]);
    expect(serverRow(vps2, cut, presence, NOW)).toMatchObject({
      links: "Links 1 of 1",
      short: false,
    });
    expect(serverRow(vps3, cut, presence, NOW)).toMatchObject({
      links: "Cut off",
      short: false,
    });
    expect(peerRows(vps3, cut, presence, NOW)).toEqual([]);
    expect(peerRows(vps2, cut, presence, NOW).map((row) => row.nodeId)).toEqual(
      [A, D],
    );
  });

  it("names a wrong port knocked again and again as a setting mistake", () => {
    const knocked = view({
      wrongPorts: [
        {
          nodeId: B,
          from: "10.88.0.1",
          target: "10.88.0.2:5433/tcp",
          at: "2026-10-26T11:58:00Z",
        },
        {
          nodeId: C,
          from: "10.88.0.9",
          target: "10.88.0.3:53/udp",
          at: "2026-10-26T11:50:00Z",
        },
      ],
    });
    expect(wrongPortRows(knocked)).toEqual([
      {
        nodeId: B,
        text: "vps-1 keeps knocking on vps-2:5433, and nothing serves it there",
        detail:
          "A setting on vps-1 points at a port vps-2 does not give it. Nothing was cut off.",
      },
      {
        nodeId: C,
        text: "10.88.0.9 keeps knocking on vps-3:53/udp, and nothing serves it there",
        detail:
          "A setting on 10.88.0.9 points at a port vps-3 does not give it. Nothing was cut off.",
      },
    ]);
    expect(navNetworkCount(knocked, presence, NOW)).toBe(1);
  });

  it("shows This Network and each held address", () => {
    expect(networkFacts(view(), presence)).toEqual([
      ["Addresses", "10.88.0.0/24"],
      ["Port", "51820/udp"],
      ["MTU", "1420"],
      ["Names", "<server>.kry"],
      ["Servers", "4 · 3 online"],
    ]);
    expect(
      heldRows(
        view({
          held: [
            {
              address: "10.88.0.6",
              nodeId: null,
              nodeName: "vps-6",
              points: [{ nodeId: A, stack: "backup", target: "vps-6.kry" }],
            },
          ],
        }),
      ),
    ).toEqual(["10.88.0.6 · Was vps-6. backup on vps-1 still reaches it."]);
  });
});

const inspect = (extra: Partial<NetworkInspect> = {}): NetworkInspect => ({
  kernel: { ok: true, version: "6.1", reason: null },
  tools: false,
  used: [],
  others: [],
  port: 51820,
  mtu: 1500,
  ...extra,
});

const candidate = {
  name: "vps-3",
  nat: false,
  publicAddress: "203.0.113.7",
  firewall: "ufw" as const,
  docker: true,
  system: "Debian",
};

const plan = { range: "10.88.0.0/24", mtu: 1420 };

describe("before a server joins", () => {
  it("lists every check the way Details shows it", () => {
    expect(
      checkRows(inspect(), candidate, plan, {
        from: ["vps-1", "vps-2"],
        arrived: false,
      }),
    ).toEqual([
      { mark: "✓", text: "Kernel has WireGuard · Linux 6.1" },
      {
        mark: "+",
        text: "WireGuard tools are installed · from Debian's own repository",
      },
      {
        mark: "✓",
        text: "10.88.0.0/24 is not used here · interfaces, Docker networks and Tailscale checked",
      },
      { mark: "✓", text: "Public address 203.0.113.7, not behind NAT" },
      {
        mark: "✕",
        text: "UDP 51820 does not reach vps-3",
        detail:
          "vps-1 and vps-2 sent a test and nothing arrived, though ufw on vps-3 would let it in. Something before the server drops it, usually the provider's firewall. Open UDP 51820 there.",
        action: "again",
      },
      {
        mark: "+",
        text: "ufw gets two rules · allow 51820/udp · allow in on kry0",
      },
      { mark: "+", text: "Docker waits for the network at boot" },
      { mark: "✓", text: "MTU 1500 · the network uses 1420" },
    ]);
  });

  it("notes a hand-made wg0, a server behind NAT and what was not measured", () => {
    const rows = checkRows(
      inspect({
        tools: true,
        port: 51821,
        mtu: null,
        others: [{ name: "wg0", address: "10.0.0.1/24", port: 51820 }],
      }),
      {
        ...candidate,
        name: "vps-2",
        nat: true,
        publicAddress: null,
        firewall: null,
        docker: false,
      },
      plan,
      null,
    );
    expect(rows).toEqual([
      { mark: "✓", text: "Kernel has WireGuard · Linux 6.1" },
      { mark: "✓", text: "WireGuard tools are installed" },
      {
        mark: "✓",
        text: "10.88.0.0/24 is not used here · interfaces, Docker networks and Tailscale checked",
      },
      {
        mark: "✓",
        text: "Behind NAT",
        detail:
          "It dials out to the others and keeps the link open. Two servers both behind NAT cannot reach each other.",
      },
      { mark: "✓", text: "MTU -- · the network uses 1420" },
      {
        mark: "!",
        text: "wg0 at 10.0.0.1/24 on port 51820",
        detail:
          "Krynodes leaves it alone. The network uses kry0 on port 51821, and stays out of 10.0.0.0/24.",
      },
    ]);
  });

  it("says what is the owner's to fix", () => {
    const rows = checkRows(
      inspect({
        kernel: { ok: false, version: null, reason: "OpenVZ" },
        used: ["10.88.0.0/16"],
        port: null,
      }),
      candidate,
      plan,
      { from: ["vps-1"], arrived: true },
    );
    expect(rows.filter((row) => row.mark === "✕")).toEqual([
      { mark: "✕", text: "Kernel has no WireGuard", detail: "OpenVZ" },
      {
        mark: "✕",
        text: "10.88.0.0/24 is used here",
        detail: "10.88.0.0/16 is in use on vps-3.",
      },
      { mark: "✕", text: "No UDP port between 51820 and 51919 is free" },
    ]);
    expect(
      checkRows(inspect(), candidate, plan, { from: ["vps-1"], arrived: true }),
    ).toContainEqual({
      mark: "✓",
      text: "UDP 51820 reaches vps-3 · from vps-1",
    });
  });

  it("names each candidate's state", () => {
    const ok = checkRows(inspect(), candidate, plan, null);
    expect(candidateState("0.7.0", ok)).toEqual({
      text: "Ready",
      details: false,
      joinable: true,
    });
    expect(
      candidateState("0.7.0", [...ok, { mark: "!", text: "wg0" }]),
    ).toEqual({ text: "Ready · 1 note", details: true, joinable: true });
    expect(
      candidateState("0.7.0", [...ok, { mark: "✕", text: "port" }]),
    ).toEqual({ text: "1 to fix", details: true, joinable: true });
    expect(candidateState("0.6.14", ok)).toEqual({
      text: "Needs agent 0.7.0 or newer",
      details: false,
      joinable: false,
    });
    expect(candidateState("0.7.0", null)).toEqual({
      text: "Checking",
      details: false,
      joinable: false,
    });
  });

  it("picks a range no candidate uses and Private Addresses does not hold", () => {
    expect(
      pickRange([["10.88.0.0/24"], ["172.17.0.0/16"]], ["10.88.1.0/24"]),
    ).toBe("10.88.2.0/24");
    expect(pickRange([["10.88.0.9/32", "fd7a::/48"]], [])).toBe("10.88.1.0/24");
    expect(pickRange([["10.88.0.0/16"]], [])).toBeNull();
    expect(pickRange([["10.0.0.0/8"]], [])).toBeNull();
  });

  it("takes the smallest uplink less WireGuard's overhead", () => {
    expect(pickMtu([1500, 1492, null])).toBe(1412);
    expect(pickMtu([])).toBe(1420);
    expect(pickMtu([1300])).toBe(1280);
  });
});

describe("while servers join", () => {
  it("says what each did and how long it took", () => {
    expect(
      progressRows([
        {
          name: "vps-1",
          address: "10.88.0.1",
          port: 51820,
          tools: true,
          status: "up",
          seconds: 14,
        },
        {
          name: "vps-2",
          address: "10.88.0.2",
          port: 51821,
          tools: false,
          status: "up",
          seconds: 9,
        },
        {
          name: "vps-3",
          address: "10.88.0.3",
          port: 51820,
          tools: false,
          status: "waiting",
          seconds: null,
          waiting: "UDP 51820 to open",
        },
      ]),
    ).toEqual([
      {
        mark: "✓",
        name: "vps-1",
        text: "Tools installed · key made · up as 10.88.0.1",
        time: "14s",
        again: false,
      },
      {
        mark: "✓",
        name: "vps-2",
        text: "Key made · up as 10.88.0.2 on port 51821",
        time: "9s",
        again: false,
      },
      {
        mark: "…",
        name: "vps-3",
        text: "Up as 10.88.0.3 · waiting for UDP 51820 to open",
        time: null,
        again: true,
      },
    ]);
    expect(progressLinks([{ a: "vps-1", b: "vps-2", ms: 4 }], 3)).toBe(
      "Links 1 of 3 up · vps-1 ↔ vps-2 answered in 4 ms",
    );
    expect(progressLinks([], 3)).toBe("Links 0 of 3 up");
  });

  it("counts the joined servers' links and names the fastest", () => {
    expect(linkProgress(view(), presence, [A, B, C], NOW)).toBe(
      "Links 2 of 3 up · vps-2 ↔ vps-1 answered in 4 ms",
    );
    expect(linkProgress(view(), presence, [A, D], NOW)).toBe("Links 0 of 1 up");
  });
});

describe("reading the candidates", () => {
  const node = (
    id: string,
    name: string,
    address: string | null,
    extra: Partial<NodeRecord> = {},
  ): NodeRecord =>
    ({
      id,
      name,
      last_seen_at: new Date(NOW - 30_000).toISOString(),
      enrolled_at: "2026-09-01T00:00:00Z",
      disabled_at: null,
      interval_seconds: 60,
      addresses: address
        ? [
            {
              label: "IPv4",
              family: 4,
              address,
              router: false,
              network: null,
              owner: null,
            },
          ]
        : [],
      ...extra,
    }) as NodeRecord;

  it("knows who is online and since when each was last seen", () => {
    expect(
      presenceOf(
        [
          node(A, "vps-1", "141.95.0.21"),
          node(D, "pivox", null, {
            last_seen_at: new Date(NOW - 7_200_000).toISOString(),
          }),
        ],
        NOW,
      ),
    ).toEqual({
      [A]: { online: true, seenAt: NOW - 30_000 },
      [D]: { online: false, seenAt: NOW - 7_200_000 },
    });
  });

  it("reads a server's address, firewall, Docker and system", () => {
    expect(
      seatOf(node(C, "vps-3", "203.0.113.7"), {
        docker: "ready",
        security: {
          checkedAt: "",
          findings: [],
          recipes: ["firewall"],
          lockdown: false,
          rebootHour: null,
          platform: {
            family: "debian",
            name: "Debian 12",
            verified: true,
            checked: "",
          },
        },
      }),
    ).toEqual({
      nodeId: C,
      name: "vps-3",
      publicAddress: "203.0.113.7",
      nat: false,
      firewall: "ufw",
      docker: true,
      system: "Debian",
    });
    const home = node(D, "pivox", "36.80.0.9", {
      addresses: [
        {
          label: "IPv4",
          family: 4,
          address: "36.80.0.9",
          router: true,
          network: null,
          owner: "router",
        },
      ],
    });
    expect(seatOf(home, undefined)).toMatchObject({
      nat: true,
      publicAddress: "36.80.0.9",
      firewall: null,
      docker: false,
      system: null,
    });
    expect(seatOf(node(E, "io", null), undefined).nat).toBe(true);
  });

  it("sends each probe to the servers that listen, and reads who got through", () => {
    const seats = [
      {
        nodeId: A,
        name: "vps-1",
        publicAddress: "141.95.0.21",
        nat: false,
        port: 51820,
      },
      {
        nodeId: B,
        name: "vps-2",
        publicAddress: "51.79.0.11",
        nat: false,
        port: 51821,
      },
      {
        nodeId: C,
        name: "vps-3",
        publicAddress: "203.0.113.7",
        nat: false,
        port: 51820,
      },
      {
        nodeId: D,
        name: "pivox",
        publicAddress: "36.80.0.9",
        nat: true,
        port: 51820,
      },
    ];
    const plan = probePlan(seats);
    expect(plan).toEqual([
      {
        nodeId: A,
        args: { port: "51820", peers: "51.79.0.11:51821 203.0.113.7:51820" },
      },
      {
        nodeId: B,
        args: { port: "51821", peers: "141.95.0.21:51820 203.0.113.7:51820" },
      },
      {
        nodeId: C,
        args: { port: "51820", peers: "141.95.0.21:51820 51.79.0.11:51821" },
      },
      {
        nodeId: D,
        args: {
          port: "51820",
          peers: "141.95.0.21:51820 51.79.0.11:51821 203.0.113.7:51820",
        },
      },
    ]);
    const answers = {
      [A]: { arrived: ["36.80.0.9", "51.79.0.11"] },
      [C]: { arrived: [] },
    };
    expect(probeOf(seats[0]!, seats, plan, answers)).toEqual({
      from: ["vps-2", "pivox"],
      arrived: true,
    });
    expect(probeOf(seats[2]!, seats, plan, answers)).toEqual({
      from: ["vps-1", "vps-2", "pivox"],
      arrived: false,
    });
    expect(probeOf(seats[1]!, seats, plan, answers)).toBeNull();
    expect(probeOf(seats[3]!, seats, plan, answers)).toBeNull();
    expect(probePlan([seats[3]!])).toEqual([]);
  });

  it("names a server on another port and what holds the network's", () => {
    expect(
      portLine(51820, [
        { name: "vps-1", port: 51820, others: [] },
        {
          name: "vps-2",
          port: 51821,
          others: [{ name: "wg0", address: "10.0.0.1/24", port: 51820 }],
        },
        { name: "vps-3", port: 51822, others: [] },
      ]),
    ).toEqual({
      port: "51820/udp",
      note: "vps-2 uses 51821, its wg0 holds 51820 · vps-3 uses 51822",
    });
    expect(
      portLine(51820, [{ name: "vps-1", port: null, others: [] }]),
    ).toEqual({
      port: "51820/udp",
      note: null,
    });
  });

  it("explains a held address under Add Server's list", () => {
    expect(
      heldNote(
        view({
          held: [
            {
              address: "10.88.0.3",
              nodeId: C,
              nodeName: "vps-3",
              points: [{ nodeId: A, stack: "backup", target: "vps-3.kry" }],
            },
          ],
        }),
      ),
    ).toBe(
      "10.88.0.3 is held for backup on vps-1. Freed addresses are given out last.",
    );
    expect(heldNote(view())).toBeNull();
  });

  it("turns a prepared server into a member, with no endpoint behind NAT", () => {
    const prepared = { key: key(7), signer: key(8), port: 51821, mtu: 1500 };
    expect(
      joinerOf(
        { nodeId: B, name: "vps-2", publicAddress: "51.79.0.11", nat: false },
        prepared,
        "10.88.0.2",
      ),
    ).toEqual({
      node: B,
      name: "vps-2",
      address: "10.88.0.2",
      key: key(7),
      signer: key(8),
      port: 51821,
      endpoint: "51.79.0.11:51821",
      nat: false,
    });
    expect(
      joinerOf(
        { nodeId: D, name: "pivox", publicAddress: "36.80.0.9", nat: true },
        prepared,
        "10.88.0.4",
      ).endpoint,
    ).toBeNull();
    expect(
      preparedOf({
        status: "done",
        output: JSON.stringify(prepared),
      } as ActionRecord),
    ).toEqual(prepared);
    expect(
      preparedOf({ status: "failed", output: "no" } as ActionRecord),
    ).toBeNull();
  });
});

describe("changing and ending", () => {
  it("says what Remove takes away and what stops working", () => {
    expect(
      removeLines(vps3, view(), {
        firewall: "ufw",
        docker: true,
        tools: true,
      }),
    ).toEqual([
      {
        mark: "−",
        text: "vps-1, vps-2 and pivox drop vps-3 and stop accepting its key",
        short: "vps-1, vps-2 and pivox drop it",
      },
      {
        mark: "−",
        text: "On vps-3, kry0 goes down and its key is deleted",
        short: "kry0, its key and its ufw rules come off",
      },
      {
        mark: "−",
        text: "The two ufw rules and the boot wait come off",
        detail: "allow 51820/udp · allow in on kry0",
        short: "",
      },
      {
        mark: "−",
        text: "WireGuard tools come off · Krynodes installed them for this, and nothing else uses them",
        short: "WireGuard tools come off",
      },
      {
        mark: "·",
        text: "10.88.0.3 is held while a stack still points to it · backup on vps-1",
        short: "10.88.0.3 is held while in use",
      },
      {
        mark: "✕",
        text: "backup on vps-1 reaches vps-3.kry",
        detail: "It fails until you change it.",
        short: "backup on vps-1 stops reaching vps-3.kry",
        action: "edit",
        nodeId: A,
      },
    ]);
    expect(
      removeLines(vps2, view(), {
        firewall: null,
        docker: false,
        tools: false,
      }),
    ).toEqual([
      {
        mark: "−",
        text: "vps-1, vps-3 and pivox drop vps-2 and stop accepting its key",
        short: "vps-1, vps-3 and pivox drop it",
      },
      {
        mark: "−",
        text: "On vps-2, kry0 goes down and its key is deleted",
        short: "kry0 and its key come off",
      },
      {
        mark: "·",
        text: "10.88.0.2 is let go and given out again last",
        short: "10.88.0.2 is let go",
      },
    ]);
  });

  it("finds the checks that go through the network", () => {
    const checks = [
      {
        id: "1",
        name: "umami to vps-2 db",
        node_id: A,
        target: "vps-2.kry:5432",
        enabled: 1,
      },
      {
        id: "2",
        name: "web",
        node_id: B,
        target: "http://10.88.0.3:3000/",
        enabled: 1,
      },
      {
        id: "3",
        name: "site",
        node_id: A,
        target: "https://example.com",
        enabled: 1,
      },
      {
        id: "4",
        name: "paused",
        node_id: A,
        target: "10.88.0.4:22",
        enabled: 0,
      },
      { id: "5", name: "lan", node_id: A, target: "10.88.1.4:22", enabled: 1 },
    ];
    expect(
      networkChecks(checks, "10.88.0.0/24").map((check) => check.id),
    ).toEqual(["1", "2"]);
  });

  it("says what Delete Network takes away, what breaks and which checks it turns off", () => {
    expect(
      deleteLines(view(), presence, { keep: ["vps-2"] }, [
        {
          id: "1",
          name: "umami to vps-2 db",
          node_id: A,
          target: "vps-2.kry:5432",
          enabled: 1,
        },
      ]),
    ).toEqual([
      {
        mark: "−",
        text: "kry0 comes off every server, with its key, its two firewall rules and the boot wait",
        short: "kry0, keys and firewall rules come off",
      },
      {
        mark: "−",
        text: "WireGuard tools come off where Krynodes installed them",
        detail: "vps-2 keeps them; Krynodes did not install them there.",
        short: "",
      },
      {
        mark: "−",
        text: "The range leaves Settings, Private Addresses, and held addresses are let go",
        short: "The range leaves Private Addresses",
      },
      {
        mark: "·",
        text: "pivox is offline and cleans itself up when it is back",
      },
      {
        mark: "✕",
        text: "backup on vps-1 reaches vps-3.kry",
        detail: "It fails until you change it.",
        short: "backup on vps-1 stops reaching vps-3.kry",
        action: "edit",
        nodeId: A,
      },
      {
        mark: "✓",
        text: "Turn off 1 check that goes through the network",
        detail: "umami to vps-2 db, on vps-1. Turn it on again from Checks.",
        short: "Turn off 1 check through the network",
      },
    ]);
  });

  it("words every change the way History lists it", () => {
    expect(networkText.create(["vps-1", "vps-2", "io", "pivox"])).toBe(
      "Create the private network with vps-1, vps-2, io and pivox",
    );
    expect(networkText.add(["vps-4"])).toBe("Add vps-4 to the private network");
    expect(networkText.remove("vps-3")).toBe(
      "Remove vps-3 from the private network",
    );
    expect(networkText.delete).toBe("Delete the private network");
    expect(networkText.rekey).toBe("Make new network keys");
    expect(networkText.test("vps-2", "pivox")).toBe("Test vps-2 ↔ pivox");
    expect(networkText.again).toBe("Send the private network again");
    expect(networkText.rule("vps-3")).toBe(
      "Put the firewall rule back on vps-3",
    );
    expect(networkText.mtu("pivox", 1380)).toBe("Use MTU 1380 on pivox");
    expect(testingText("vps-2", "vps-3", 12_400)).toBe(
      "Testing vps-2 ↔ vps-3 · 12s",
    );
    const action = (verb: "prepare" | "unprepare" | "rekey") =>
      ({ kind: "network", name: "kry0", action: verb, output: null }) as Pick<
        ActionRecord,
        "kind" | "name" | "action" | "output"
      > as ActionRecord;
    expect(historyText(action("prepare"))).toBe(
      "Get the server ready for the private network",
    );
    expect(historyText(action("unprepare"))).toBe(
      "Undo the private network preparation",
    );
    expect(historyText(action("rekey"))).toBe("Make a new network key");
  });
});

const result = (extra: Partial<NetworkTest> = {}): NetworkTest => ({
  up: true,
  hasKey: true,
  version: 4,
  clock: SEC,
  publicAddress: null,
  firewall: { lets: true, rule: true },
  handshakes: { sent: 1480, received: 1480, answered: 1, third: true },
  small: { sent: 10, lost: 0, ms: 38 },
  large: { passed: 1420, tried: [1420] },
  ...extra,
});

const end = (
  member: NetworkServer,
  age: number | null,
  extra: Partial<NetworkTest> = {},
  firewall: "ufw" | "firewalld" | null = "ufw",
): TestEnd => ({
  nodeId: member.nodeId,
  name: member.name,
  age,
  address: member.endpoint?.split(":")[0] ?? null,
  port: member.port,
  firewall,
  result:
    age === null
      ? null
      : result({
          publicAddress: member.endpoint?.split(":")[0] ?? null,
          ...extra,
        }),
});

const network = { version: 4, mtu: 1420 };

describe("Test Link", () => {
  it("finds a filter in front of one server that lets the others in", () => {
    const blocked = {
      handshakes: { sent: 1480, received: 0, answered: 0, third: true },
    };
    const a = end(vps2, 12, {
      handshakes: { sent: 1480, received: 0, answered: 0, third: null },
    });
    const b = end(vps3, 20, blocked);
    expect(testRows(a, b, network)).toEqual([
      {
        mark: "✓",
        text: "Both agents answer · vps-2 12s ago · vps-3 20s ago",
        short: "Both agents answer",
      },
      {
        mark: "✓",
        text: "kry0 is up on both, each with the other's key",
        short: "kry0 up, keys match",
      },
      {
        mark: "✓",
        text: "Clocks agree · under 1s apart",
        short: "Clocks agree",
      },
      {
        mark: "✓",
        text: "vps-2 still has 51.79.0.11",
        short: "vps-2: address unchanged",
      },
      {
        mark: "✓",
        text: "vps-3 still has 203.0.113.7",
        short: "vps-3: address unchanged",
      },
      {
        mark: "✓",
        text: "ufw on vps-2 lets in 51821/udp · the rule from Krynodes is there",
        short: "vps-2: ufw lets in 51821/udp",
      },
      {
        mark: "✓",
        text: "ufw on vps-3 lets in 51820/udp · the rule from Krynodes is there",
        short: "vps-3: ufw lets in 51820/udp",
      },
      {
        mark: "✕",
        text: "Handshakes do not get through",
        detail:
          "vps-2 sent 1.4 KB to vps-3 and got nothing back. vps-3 sent 1.4 KB to vps-2 and got nothing back. Other servers' handshakes reach vps-3.",
      },
      { mark: "–", text: "Large packets · tested once the link is up" },
    ]);
    expect(mostLikely(a, b, network, ["vps-1"])).toEqual({
      text: "Something in front of vps-3 lets UDP 51820 in from vps-1 but not from vps-2 (51.79.0.11). This is often a provider firewall rule limited by source. Add 51.79.0.11 to it.",
      detail: "Krynodes cannot change a provider's firewall.",
      fix: null,
    });
  });

  it("offers Use 1380 when large packets stop on the way", () => {
    const a = end(vps1, 5);
    const b = end(
      pivox,
      8,
      { large: { passed: 1380, tried: [1420, 1400, 1380] } },
      null,
    );
    const rows = testRows(a, b, network);
    expect(rows.slice(-4)).toEqual([
      { mark: "✓", text: "Handshakes get through" },
      { mark: "✓", text: "Small packets · 38 ms, none lost" },
      {
        mark: "✕",
        text: "Packets of 1420 bytes do not get through",
        short: "Large packets lost",
      },
      { mark: "✓", text: "Packets of 1380 bytes get through" },
    ]);
    expect(rows.map((row) => row.short)).toContain("Address unchanged");
    expect(rows.map((row) => row.text)).not.toContain("pivox still has --");
    expect(mostLikely(a, b, network, [])).toEqual({
      text: "The way to pivox carries at most 1380 bytes, likely because of its home connection. Small requests work, but a large reply stalls.",
      detail:
        "pivox gets MTU 1380 and the others keep 1420. Connections to pivox then use the smaller size from both ends.",
      fix: { kind: "mtu", nodeId: D, size: 1380 },
    });
    expect(testSummary(rows, { kind: "mtu", nodeId: D, size: 1380 })).toBe(
      "Large packets lost · Use 1380 was offered",
    );
    expect(testSummary(testRows(a, end(vps2, 3), network), null)).toBe(
      "The link answers",
    );
  });

  it("names each fix the way its button does", () => {
    expect(fixLabel({ kind: "again" })).toBe("Send Again");
    expect(fixLabel({ kind: "rule", nodeId: C })).toBe("Put Rule Back");
    expect(fixLabel({ kind: "mtu", nodeId: D, size: 1380 })).toBe("Use 1380");
  });

  it("pairs the servers to test and names who else gets through", () => {
    expect(testPairs(view()).map(([a, b]) => `${a.name}-${b.name}`)).toEqual([
      "vps-1-vps-2",
      "vps-1-vps-3",
      "vps-1-pivox",
      "vps-2-vps-3",
      "vps-2-pivox",
      "vps-3-pivox",
    ]);
    expect(testPairs(view(), C).map(([a, b]) => `${a.name}-${b.name}`)).toEqual(
      ["vps-1-vps-3", "vps-2-vps-3", "vps-3-pivox"],
    );
    expect(testOthers(view(), B, C)).toEqual(["vps-1"]);
  });

  it("stops at a server that does not answer", () => {
    const a = end(vps2, 12);
    const b = end(vps3, null);
    expect(testRows(a, b, network)).toEqual([
      {
        mark: "✕",
        text: "vps-3 does not answer",
        detail: "vps-3 is offline, so there is nothing to test.",
      },
    ]);
    expect(mostLikely(a, b, network, []).fix).toBeNull();
  });

  it("sends the network again, puts the rule back, or names the clock", () => {
    const a = end(vps2, 12);
    expect(
      mostLikely(a, end(vps3, 20, { hasKey: false }), network, []),
    ).toEqual({
      text: "vps-3 does not have the current network.",
      detail: "Send Again sends the same network to it; no new keys are made.",
      fix: { kind: "again" },
    });
    expect(testRows(a, end(vps3, 20, { up: false }), network)).toContainEqual({
      mark: "✕",
      text: "kry0 is down on vps-3",
    });
    const gone = end(vps3, 20, { firewall: { lets: false, rule: false } });
    expect(testRows(a, gone, network)).toContainEqual({
      mark: "✕",
      text: "ufw on vps-3 does not let in 51820/udp · the rule from Krynodes is gone",
      short: "ufw on vps-3 drops 51820/udp",
    });
    expect(mostLikely(a, gone, network, []).fix).toEqual({
      kind: "rule",
      nodeId: C,
    });
    const late = end(vps3, 20, { clock: SEC - 95 });
    expect(testRows(a, late, network)).toContainEqual({
      mark: "✕",
      text: "Clocks are 95s apart",
      detail:
        "WireGuard refuses handshakes from a clock that went back. Fix time sync on the server that is off.",
    });
    expect(mostLikely(a, late, network, []).fix).toBeNull();
    const moved = end(vps3, 20, { publicAddress: "203.0.113.9" });
    expect(testRows(a, moved, network)).toContainEqual({
      mark: "✕",
      text: "vps-3 now has 203.0.113.9",
      detail: "Krynodes updates it on the others by itself.",
    });
  });
});

describe("the network document", () => {
  const ends = async (names: string[]) => {
    const pairs = await Promise.all(names.map(() => sealPair()));
    return {
      pairs: Object.fromEntries(names.map((id, index) => [id, pairs[index]!])),
      keys: Object.fromEntries(
        names.map((id, index) => [id, pairs[index]!.public]),
      ),
    };
  };
  const joiner = (member: NetworkServer) => ({
    node: member.nodeId,
    name: member.name,
    address: member.address!,
    key: member.key,
    signer: member.signer,
    port: member.port,
    endpoint: member.endpoint,
    nat: member.nat,
  });
  const opened = async (
    pair: Awaited<ReturnType<typeof sealPair>>,
    sealed: string,
  ) => b64url(new TextEncoder().encode(await openSealed(pair, sealed)));

  it("seals each pair's key twice, to its two ends only, and keeps every other member", async () => {
    const { pairs, keys } = await ends([A, B, C]);
    const first = await buildDocument(
      null,
      {
        kind: "create",
        range: "10.88.0.0/24",
        port: 51820,
        mtu: 1420,
        join: [joiner(vps1), joiner(vps2)],
      },
      keys,
    );
    expect(first).toMatchObject({
      v: 1,
      version: 1,
      range: "10.88.0.0/24",
      blocked: [],
    });
    const [one, two] = first.members;
    expect(Object.keys(one!.psk)).toEqual([B]);
    expect(Object.keys(two!.psk)).toEqual([A]);
    expect(await opened(pairs[A]!, one!.psk[B]!)).toBe(
      await opened(pairs[B]!, two!.psk[A]!),
    );
    await expect(openSealed(pairs[C]!, one!.psk[B]!)).rejects.toThrow();
    const next = await buildDocument(
      first,
      { kind: "add", join: [joiner(vps3)] },
      keys,
    );
    expect(next.version).toBe(2);
    expect(next.members[0]).toEqual({
      ...one,
      psk: { ...one!.psk, [C]: next.members[0]!.psk[C] },
    });
    expect(next.members[2]!.psk[A]).toBeDefined();
    expect(Object.keys(next.members[2]!.psk).sort()).toEqual([A, B].sort());
  });

  it("blocks a removed key and never lets it back", async () => {
    const { keys } = await ends([A, B, C]);
    const start = await buildDocument(
      null,
      {
        kind: "create",
        range: "10.88.0.0/24",
        port: 51820,
        mtu: 1420,
        join: [joiner(vps1), joiner(vps2), joiner(vps3)],
      },
      keys,
    );
    const removed = await buildDocument(
      start,
      { kind: "remove", nodeId: C },
      keys,
    );
    expect(removed.members.map((member) => member.node)).toEqual([A, B]);
    expect(removed.blocked).toEqual([vps3.key]);
    expect(removed.members[0]!.psk).toEqual({ [B]: start.members[0]!.psk[B] });
    await expect(
      buildDocument(removed, { kind: "add", join: [joiner(vps3)] }, keys),
    ).rejects.toThrow("vps-3's key was taken out of the network");
  });

  it("makes new keys, marks an offline server, sets one MTU and sends again", async () => {
    const { pairs, keys } = await ends([A, B, C]);
    const start = await buildDocument(
      null,
      {
        kind: "create",
        range: "10.88.0.0/24",
        port: 51820,
        mtu: 1420,
        join: [joiner(vps1), joiner(vps2), joiner(vps3)],
      },
      keys,
    );
    const fresh = await buildDocument(
      start,
      { kind: "rekey", keys: { [A]: key(201), [B]: key(202) } },
      keys,
    );
    expect(fresh.members.map((member) => [member.key, member.rekey])).toEqual([
      [key(201), undefined],
      [key(202), undefined],
      [vps3.key, true],
    ]);
    expect(fresh.blocked).toEqual([vps1.key, vps2.key]);
    expect(await opened(pairs[A]!, fresh.members[0]!.psk[B]!)).not.toBe(
      await opened(pairs[A]!, start.members[0]!.psk[B]!),
    );
    const small = await buildDocument(
      fresh,
      { kind: "mtu", nodeId: C, mtu: 1380 },
      keys,
    );
    expect(small.members[2]!.mtu).toBe(1380);
    expect(small.members.slice(0, 2)).toEqual(fresh.members.slice(0, 2));
    const again: NetworkDocument = await buildDocument(
      small,
      { kind: "again" },
      keys,
    );
    expect(again).toEqual({ ...small, version: small.version + 1 });
    const gone = await buildDocument(again, { kind: "delete" }, keys);
    expect(gone).toMatchObject({ deleted: true, members: [] });
    expect(gone.blocked).toEqual(
      expect.arrayContaining([key(201), key(202), vps3.key]),
    );
  });

  it("builds on the body it hashed, names it as the parent and keeps quarantined members cut", async () => {
    const { keys } = await ends([A, B]);
    const start = await buildDocument(
      null,
      {
        kind: "create",
        range: "10.88.0.0/24",
        port: 51820,
        mtu: 1420,
        join: [joiner(vps1), joiner(vps2)],
      },
      keys,
    );
    expect(start.parent).toBeUndefined();
    const bytes = new TextEncoder().encode(JSON.stringify(start));
    const base = await baseOf(
      view({
        document: { ...start, members: [] },
        body: b64url(bytes),
        quarantined: [B],
      }),
    );
    expect(base!.parent).toBe(
      b64url(await crypto.subtle.digest("SHA-256", bytes)),
    );
    expect(
      base!.document.members.map((entry) => [entry.node, entry.cut]),
    ).toEqual([
      [A, undefined],
      [B, true],
    ]);
    const next = await buildDocument(
      base!.document,
      { kind: "again" },
      keys,
      base!.parent,
    );
    expect(next.parent).toBe(base!.parent);
    expect(next.members[1]!.cut).toBe(true);
    expect(await baseOf(view())).toBeNull();
  });

  it("releases a cut member with its new keys and keeps the old one blocked", async () => {
    const { keys } = await ends([A, B]);
    const start = await buildDocument(
      null,
      {
        kind: "create",
        range: "10.88.0.0/24",
        port: 51820,
        mtu: 1420,
        join: [joiner(vps1), joiner(vps2)],
      },
      keys,
    );
    const cut = {
      ...start,
      members: [
        start.members[0]!,
        { ...start.members[1]!, cut: true as const },
      ],
    };
    const released = await buildDocument(
      cut,
      { kind: "release", nodeId: B, key: key(212), signer: key(213) },
      keys,
    );
    expect(released.members[1]).toMatchObject({
      key: key(212),
      signer: key(213),
    });
    expect(released.members[1]!.cut).toBeUndefined();
    expect(released.blocked).toEqual([vps2.key]);
  });

  it("renames one member and changes nothing else", async () => {
    const { keys } = await ends([A, B]);
    const start = await buildDocument(
      null,
      {
        kind: "create",
        range: "10.88.0.0/24",
        port: 51820,
        mtu: 1420,
        join: [joiner(vps1), joiner(vps2)],
      },
      keys,
    );
    const renamed = await buildDocument(
      start,
      { kind: "rename", nodeId: B, name: "db-1" },
      keys,
    );
    expect(renamed).toEqual({
      ...start,
      version: start.version + 1,
      members: [start.members[0], { ...start.members[1], name: "db-1" }],
    });
  });
});

describe("the ends of a member", () => {
  it("says what Delete Node does to the network first", () => {
    expect(leaveParagraph(vps3, view())).toBe(
      "vps-3 is in the private network. Krynodes takes it out first: vps-1, vps-2 and pivox drop it, and 10.88.0.3 is held while a stack still points to it. backup on vps-1 reaches vps-3.kry and stops working.",
    );
    expect(leaveParagraph(vps2, view({ members: [vps1, vps2] }))).toBe(
      "vps-2 is in the private network. Krynodes takes it out first: vps-1 drops it, and 10.88.0.2 is let go.",
    );
    expect(leaveParagraph(vps3, view(), true)).toBe(
      "That also takes kry0 off. Until then it can do no harm: vps-1, vps-2 and pivox drop vps-3 now and no longer accept its key.",
    );
  });

  it("names the members whose seal key is missing before any key changes", () => {
    const sealed = { [A]: "a", [B]: "b", [C]: "c", [D]: "d" };
    expect(missingSeals(view(), sealed)).toBeNull();
    expect(missingSeals(view(), { [A]: "a", [B]: "b" })).toBe(
      "vps-3 and pivox have not reported their seal keys yet. Refresh their services and try again.",
    );
    expect(missingSeals(view(), { [A]: "a", [B]: "b", [C]: "c" })).toBe(
      "pivox has not reported its seal key yet. Refresh its services and try again.",
    );
  });

  it("names the offline servers that make their keys later", () => {
    expect(rekeyNote(view(), presence)).toBe(
      "pivox is offline. It gets its new key when it is back, and cannot connect with the old one meanwhile.",
    );
    expect(
      rekeyNote(view(), { ...presence, [C]: { online: false, seenAt: null } }),
    ).toBe(
      "vps-3 and pivox are offline. They get their new keys when they are back, and cannot connect with the old ones meanwhile.",
    );
    expect(rekeyNote(view(), { ...presence, [D]: presence[A]! })).toBeNull();
  });

  it("describes each end of a test from what the page knows", () => {
    expect(testEnd(vps3, presence, NOW, { firewall: "ufw" }, null)).toEqual({
      nodeId: C,
      name: "vps-3",
      age: 10,
      address: "203.0.113.7",
      port: 51820,
      firewall: "ufw",
      result: null,
    });
    expect(
      testEnd(pivox, presence, NOW, { firewall: null }, null),
    ).toMatchObject({ address: null, age: 7200 });
  });

  it("says who waits to join and what it gets", () => {
    expect(
      waitingLine(
        { name: "vps-4", since: new Date(2026, 9, 26, 14, 2).toISOString() },
        "10.88.0.5",
      ),
    ).toEqual({
      title: "vps-4 wants to join · ready since 14:02",
      state: "Ready · gets 10.88.0.5",
    });
    expect(
      waitingLine(
        { name: "vps-4", since: new Date(2026, 9, 26, 14, 2).toISOString() },
        null,
      ).state,
    ).toBe("Ready · gets --");
  });
});

const onIt = (
  project: string,
  access: "contained" | "full",
  network: StackNetwork,
  extra: { public?: string[] } = {},
) => ({ project, access, network, ...extra });

const servers = [
  {
    id: A,
    name: "vps-1",
    stacks: [
      onIt("backup", "contained", {
        serves: [],
        reaches: ["10.88.0.3:9000/tcp"],
        private: [],
      }),
      onIt("umami", "contained", {
        serves: [],
        reaches: ["10.88.0.2:5432/tcp"],
        private: [],
      }),
    ],
  },
  {
    id: B,
    name: "vps-2",
    stacks: [
      onIt(
        "grafana",
        "full",
        { serves: [], reaches: [], private: ["3000/tcp"] },
        { public: [] },
      ),
      onIt("db", "contained", {
        serves: [{ port: "5432/tcp", to: [A] }],
        reaches: [],
        private: ["5432/tcp"],
      }),
    ],
  },
  {
    id: C,
    name: "vps-3",
    stacks: [
      onIt("minio", "contained", {
        serves: [{ port: "9000/tcp", all: true }],
        reaches: [],
        private: ["9000/tcp"],
      }),
    ],
  },
];

const placed = () =>
  view({
    members: [
      {
        ...vps1,
        points: [
          { stack: "backup", target: "10.88.0.3:9000/tcp" },
          { stack: "umami", target: "10.88.0.2:5432/tcp" },
        ],
      },
      vps2,
      vps3,
      pivox,
    ],
  });

const grafanaOpen = `services:
  grafana:
    image: grafana/grafana:11.3.0
    ports:
      - "3000:3000"
`;

describe("stacks on the private network", () => {
  it("reads places by name, by .kry name or by address, and says what is wrong", () => {
    expect(
      parsePlaces(
        "vps-2:5432/tcp, vps-3.kry:9000/tcp,10.88.0.9:22/tcp, vps-2:5432/tcp",
        view(),
        A,
      ),
    ).toEqual({
      places: ["10.88.0.2:5432/tcp", "10.88.0.3:9000/tcp", "10.88.0.9:22/tcp"],
      problem: null,
    });
    expect(parsePlaces(" ", view(), A)).toEqual({ places: [], problem: null });
    const problem = (text: string) => parsePlaces(text, view(), A).problem;
    expect(problem("vps-9:5432/tcp")).toBe(
      "vps-9 is not in the private network.",
    );
    expect(problem("10.99.0.2:5432/tcp")).toBe(
      "10.99.0.2 is not in the private network.",
    );
    expect(problem("vps-1:5432/tcp")).toBe(
      "That is vps-1 itself; use Reach This Server On.",
    );
    expect(problem("10.88.0.1:5432/tcp")).toBe(
      "That is vps-1 itself; use Reach This Server On.",
    );
    expect(problem("vps-2:5432")).toBe(
      "vps-2:5432 is not a place such as vps-2:5432/tcp.",
    );
    expect(problem("vps-2")).toBe(
      "vps-2 is not a place such as vps-2:5432/tcp.",
    );
    expect(
      problem(
        Array.from({ length: 33 }, (_, port) => `vps-2:${port + 1}/tcp`).join(
          ",",
        ),
      ),
    ).toBe("A stack may reach at most 32 places.");
  });

  it("shows a place by its server's name, and a held address as it is", () => {
    expect(placeText(view(), "10.88.0.2:5432/tcp")).toBe("vps-2:5432/tcp");
    expect(placeText(view(), "10.88.0.9:5432/tcp")).toBe("10.88.0.9:5432/tcp");
  });

  it("reads and writes who may reach each port", () => {
    const rows = readServes(
      [
        { port: "5432/tcp", to: [B, C] },
        { port: "9090/tcp", all: true },
        { port: "7000/tcp", all: true },
      ],
      ["5432/tcp", "9090/tcp", "3000/tcp"],
    );
    expect(rows).toEqual([
      { port: "5432/tcp", choice: "chosen", to: [B, C] },
      { port: "9090/tcp", choice: "all", to: [] },
      { port: "3000/tcp", choice: "self", to: [] },
    ]);
    expect(servesArg(rows)).toBe(`5432/tcp=${B} ${C},9090/tcp=all`);
    expect(servesProblem(rows)).toBeNull();
    expect(
      servesProblem([{ port: "5432/tcp", choice: "chosen", to: [] }]),
    ).toBe("Tick at least one server, or choose This Server Only.");
    expect(readServes(undefined, ["80/tcp"])).toEqual([
      { port: "80/tcp", choice: "self", to: [] },
    ]);
  });

  it("tells the Full access box about the network", () => {
    const member = { name: "vps-2", address: "10.88.0.2" };
    expect(opensBox(grafanaOpen, member)).toEqual({
      lines: [
        "Opens to the internet and every server: 3000/tcp",
        "Reaches every server on the private network",
      ],
      notes: [
        "Docker opens these ports past ufw, so a firewall does not close them.",
      ],
      offer:
        "Only your servers need 3000/tcp? Open it on the private address instead.",
      warn: true,
    });
    expect(opensBox(usePrivateAddress(grafanaOpen), member)).toEqual({
      lines: [
        "Opens to every server on the private network: 3000/tcp",
        "Reaches every server on the private network",
      ],
      notes: [
        "Krynodes fills in KRY_PRIVATE_IP with the server's own private address, 10.88.0.2 here.",
      ],
      offer: null,
      warn: false,
    });
    expect(opensBox(grafanaOpen, null)).toEqual({
      lines: ["Opens to the internet: 3000/tcp"],
      notes: [
        "Docker opens these ports past ufw, so a firewall does not close them.",
      ],
      offer: null,
      warn: true,
    });
    expect(opensBox("services:\n  web:\n    image: nginx\n", null)).toEqual({
      lines: [],
      notes: [],
      offer: null,
      warn: false,
    });
    expect(
      privateIpProblem(usePrivateAddress(grafanaOpen), "vps-4", false),
    ).toBe(
      "vps-4 is not in the private network, so KRY_PRIVATE_IP has no value.",
    );
    expect(
      privateIpProblem(usePrivateAddress(grafanaOpen), "vps-2", true),
    ).toBeNull();
    expect(privateIpProblem(grafanaOpen, "vps-4", false)).toBeNull();
  });

  it("points Security's public line at the private address, and keeps the firewall's network row", () => {
    const stacks = [
      { project: "grafana", access: "full" as const, public: ["3000/tcp"] },
      { project: "prometheus", access: "full" as const, public: [] },
      { project: "db", access: "contained" as const, public: ["5432/tcp"] },
    ];
    expect(networkHint(stacks, true)).toBe(
      "grafana is on the private network too. If only your servers need it, use the private address in Edit Compose.",
    );
    expect(
      networkHint(
        [...stacks, { project: "web", access: "full", public: ["80/tcp"] }],
        true,
      ),
    ).toBe(
      "grafana and web are on the private network too. If only your servers need them, use the private address in Edit Compose.",
    );
    expect(networkHint(stacks, false)).toBeNull();
    expect(firewallRow(vps2)).toEqual({
      port: "51821/udp",
      detail: "the private network, while vps-2 is in it",
    });
  });

  it("says what Remove does to the stacks that serve or reach the server", () => {
    expect(
      removeLines(
        vps3,
        placed(),
        { firewall: "ufw", docker: true, tools: true },
        servers,
      ).slice(4),
    ).toEqual([
      {
        mark: "·",
        text: "10.88.0.3 is held while a stack still points to it · backup on vps-1",
        short: "10.88.0.3 is held while in use",
      },
      {
        mark: "✕",
        text: "backup on vps-1 reaches vps-3:9000/tcp",
        detail: "It fails until you change it.",
        short: "backup on vps-1 stops reaching vps-3:9000",
        action: "edit",
        nodeId: A,
      },
      {
        mark: "✕",
        text: "minio on vps-3 serves 9000 to All Servers",
        detail: "It goes back to This Server Only.",
        short: "minio goes back to This Server Only",
      },
    ]);
  });

  it("says what Delete Network does to every stack on it", () => {
    expect(
      deleteLines(placed(), presence, { keep: [] }, [], servers).slice(4),
    ).toEqual([
      {
        mark: "✕",
        text: "grafana on vps-2 opens 3000 on KRY_PRIVATE_IP",
        detail:
          "Nobody can reach it, and it fails on its next start until you change it.",
        short: "grafana on vps-2 uses KRY_PRIVATE_IP",
      },
      {
        mark: "✕",
        text: "db on vps-2 serves 5432 to vps-1",
        detail: "It goes back to This Server Only.",
        short: "db goes back to This Server Only",
      },
      {
        mark: "✕",
        text: "minio on vps-3 serves 9000 to All Servers",
        detail: "It goes back to This Server Only.",
        short: "minio goes back to This Server Only",
      },
      {
        mark: "✕",
        text: "umami on vps-1 reaches vps-2:5432/tcp",
        detail: "It fails until you change it.",
        short: "umami on vps-1 stops reaching vps-2:5432",
        action: "edit",
        nodeId: A,
      },
      {
        mark: "✕",
        text: "backup on vps-1 reaches vps-3:9000/tcp",
        detail: "It fails until you change it.",
        short: "backup on vps-1 stops reaching vps-3:9000",
        action: "edit",
        nodeId: A,
      },
    ]);
  });

  it("carries what a moved stack serves and changes the places that reach it", () => {
    const shop = {
      id: C,
      name: "vps-3",
      stacks: [
        onIt("shop", "contained", {
          serves: [],
          reaches: ["10.88.0.2:6379/tcp", "10.88.0.4:22/tcp"],
          private: [],
        }),
      ],
    };
    const cache = {
      project: "cache",
      network: {
        serves: [{ port: "6379/tcp", to: [C] }],
        reaches: [],
        private: ["6379/tcp"],
      },
    };
    const from = { nodeId: B, name: "vps-2" };
    expect(
      moveBlock(cache, from, { nodeId: A, name: "vps-1" }, view(), [shop]),
    ).toEqual({
      red: null,
      lines: ["On vps-1, cache serves 6379/tcp to vps-3 only, as it does now."],
      changes: [
        {
          nodeId: C,
          project: "shop",
          text: "Change shop's reach on vps-3 from vps-2:6379/tcp to vps-1:6379/tcp",
          reaches: ["10.88.0.1:6379/tcp", "10.88.0.4:22/tcp"],
        },
      ],
      note: "shop's own settings may still name vps-2.kry, such as a secret. Change them after the move.",
      serves: [{ port: "6379/tcp", to: [C] }],
      reaches: [],
    });
    expect(
      moveBlock(cache, from, { nodeId: E, name: "vps-4" }, view(), [shop]),
    ).toEqual({
      red: "vps-4 is not in the private network, so vps-3 cannot reach cache there.",
      lines: [],
      changes: [],
      note: null,
      serves: [],
      reaches: [],
    });
    const everyone = {
      project: "cache",
      network: {
        serves: [{ port: "6379/tcp", all: true as const }],
        reaches: ["10.88.0.3:9000/tcp", "10.88.0.1:8080/tcp"],
        private: ["6379/tcp"],
      },
    };
    expect(
      moveBlock(everyone, from, { nodeId: A, name: "vps-1" }, view(), []),
    ).toMatchObject({
      lines: [
        "On vps-1, cache serves 6379/tcp to All Servers, as it does now.",
      ],
      changes: [],
      note: null,
      reaches: ["10.88.0.3:9000/tcp"],
    });
    expect(
      moveBlock(
        {
          project: "app",
          network: {
            serves: [],
            reaches: ["10.88.0.3:9000/tcp"],
            private: [],
          },
        },
        from,
        { nodeId: E, name: "vps-4" },
        view(),
        [],
      )?.red,
    ).toBe(
      "vps-4 is not in the private network, so app cannot reach vps-3:9000/tcp there.",
    );
    expect(
      moveBlock(
        { project: "web", network: null },
        from,
        { nodeId: A, name: "vps-1" },
        view(),
        [shop],
      ),
    ).toBeNull();
  });

  it("leaves the server it moves to out of who may reach it", () => {
    const cache = {
      project: "cache",
      network: {
        serves: [
          { port: "6379/tcp", to: [A, C] },
          { port: "9090/tcp", to: [A] },
        ],
        reaches: [],
        private: ["6379/tcp", "9090/tcp"],
      },
    };
    expect(
      moveBlock(
        cache,
        { nodeId: B, name: "vps-2" },
        { nodeId: A, name: "vps-1" },
        view(),
        [],
      ),
    ).toMatchObject({
      lines: ["On vps-1, cache serves 6379/tcp to vps-3 only, as it does now."],
      serves: [{ port: "6379/tcp", to: [C] }],
    });
  });

  it("says when a move would change more stacks than one move may", () => {
    const change = (index: number) => ({
      nodeId: C,
      project: `shop-${index}`,
      text: "",
      reaches: [],
    });
    expect(
      moveProblem(
        Array.from({ length: NETWORK.moveReaches }, (_, at) => change(at)),
      ),
    ).toBeNull();
    expect(
      moveProblem(
        Array.from({ length: NETWORK.moveReaches + 1 }, (_, at) => change(at)),
      ),
    ).toBe(
      "One move changes at most 8 other stacks. Untick some and change them after the move.",
    );
  });

  it("names each server's stacks from the server list", () => {
    expect(
      hostingOf(
        [
          { id: A, stacks: servers[0]!.stacks },
          { id: E, stacks: [] },
        ],
        [{ id: A, name: "vps-1" }],
      ),
    ).toEqual([{ id: A, name: "vps-1", stacks: servers[0]!.stacks }]);
  });

  it("names the stacks other servers reach on a server", () => {
    expect(reachedStacks(servers[1]!)).toEqual(["grafana", "db"]);
    expect(reachedStacks(servers[0]!)).toEqual([]);
    expect(reachedStacks(undefined)).toEqual([]);
  });

  it("suggests a check for each place a Contained stack reaches, until it is put aside", () => {
    expect(checkSuggestions(servers, view(), [], [])).toEqual([
      {
        nodeId: A,
        project: "backup",
        reaches: ["10.88.0.3:9000/tcp"],
        text: "backup reaches vps-3:9000/tcp over the private network. Watch that path from vps-1?",
        check: {
          nodeId: A,
          name: "backup to vps-3 minio",
          kind: "TCP",
          target: "vps-3.kry:9000",
          timeoutSeconds: 10,
        },
      },
      {
        nodeId: A,
        project: "umami",
        reaches: ["10.88.0.2:5432/tcp"],
        text: "umami reaches vps-2:5432/tcp over the private network. Watch that path from vps-1?",
        check: {
          nodeId: A,
          name: "umami to vps-2 db",
          kind: "TCP",
          target: "vps-2.kry:5432",
          timeoutSeconds: 10,
        },
      },
    ]);
    const watched = [
      {
        id: "1",
        name: "db",
        node_id: A,
        target: "10.88.0.2:5432",
        enabled: 1,
      },
    ];
    const aside = [
      { nodeId: A, project: "backup", reaches: ["10.88.0.3:9000/tcp"] },
    ];
    expect(checkSuggestions(servers, view(), watched, aside)).toEqual([]);
    expect(
      checkSuggestions(servers, view(), watched, [
        { ...aside[0]!, reaches: ["10.88.0.3:8000/tcp"] },
      ]).map((suggestion) => suggestion.project),
    ).toEqual(["backup"]);
  });
});

describe("the link a test checks", () => {
  it("names both servers when the peer is known", () => {
    const test = {
      kind: "network",
      name: "kry0",
      action: "test",
      nodeId: "n1",
      peer: "n2",
      output: null,
    } as unknown as ActionRecord;
    const names = { n1: "io", n2: "pivox" };
    expect(networkActionText(test, names)).toBe("Test the link io ↔ pivox");
    expect(networkActionText({ ...test, peer: "n9" }, names)).toBe(
      "Test a private network link",
    );
    expect(networkActionText({ ...test, peer: null }, names)).toBe(
      "Test a private network link",
    );
    expect(historyText(test, [], "io", names)).toBe("Test the link io ↔ pivox");
    expect(
      actionLine(
        { ...test, requestedAt: "2026-10-28T03:00:00.000Z" },
        { nodeName: "io", names },
      ).text,
    ).toBe("Test the link io ↔ pivox");
  });
});
