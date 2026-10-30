import type { TailscaleReport } from "@krynodes/protocol";
import { describe, expect, it } from "vitest";

import type { TailnetConnected, TailnetServer } from "../types";
import {
  addRuleEffect,
  alarmRows,
  applied,
  beforeConnect,
  brokenLines,
  changedLines,
  connectSteps,
  disconnectSteps,
  dnsLine,
  dnsText,
  exitNodeLine,
  exitNodeText,
  joinedLines,
  joinSteps,
  keepChange,
  losesAccess,
  notApplied,
  outsideRows,
  proposals,
  readSteps,
  removeSteps,
  removeText,
  ruleForm,
  ruleRows,
  ruleText,
  saveSteps,
  serverLines,
  startRules,
  tailnetActionText,
} from "./tailscale";

const SET = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a22";
const P = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a93";
const I = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a91";
const V1 = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a10";
const V2 = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a12";
const V4 = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a13";
const LAPTOP = "100.101.7.30";
const PHONE = "100.101.7.31";
const TABLET = "100.101.7.32";
const IPAD = "100.101.7.40";
const TV = "100.101.7.41";
const NAME: Record<string, string> = {
  [P]: "server-1",
  [I]: "server-2",
  [V1]: "vps-1",
  [V2]: "vps-2",
  [V4]: "vps-4",
};
const ADDRESS: Record<string, string> = {
  [P]: "100.101.7.20",
  [I]: "100.101.7.11",
  [V1]: "100.101.7.10",
  [V2]: "100.101.7.12",
  [V4]: "100.101.7.13",
};
const DEVICES = [{ id: "dev-1", name: "Laptop" }];

const server = (
  nodeId: string,
  over: Partial<TailscaleReport> = {},
): TailnetServer => ({
  nodeId,
  name: NAME[nodeId]!,
  report: {
    state: "running",
    addresses: [ADDRESS[nodeId]!],
    name: `${NAME[nodeId]}.tail0000.ts.net`,
    keyExpiry: null,
    id: `n${NAME[nodeId]!.replace("-", "")}CNTRL`,
    tailnet: "tail0000.ts.net",
    tags: ["tag:kry"],
    peers: 8,
    reach: [{ from: [LAPTOP, PHONE], ports: ["22/tcp"] }],
    names: { [IPAD]: "ipad", [TV]: "tv", [ADDRESS[I]!]: "server-2" },
    ...over,
  },
  vault: { set: SET, holders: 4 },
  signedIn: false,
});

const SERVER_ONE_REACH = [
  { from: [LAPTOP, PHONE, TABLET], ports: ["22/tcp", "53", "80/tcp"] },
  { from: [ADDRESS[I]!], ports: ["53/udp"] },
  { from: [IPAD, TV], ports: ["80/tcp"] },
];

const SERVERS = [
  server(P, { reach: SERVER_ONE_REACH }),
  server(I),
  server(V1),
  server(V2),
];

const CONNECTED: TailnetConnected = {
  tailnet: "tail0000.ts.net",
  clientId: "kT9xQ2hN4CNTRL",
  setId: SET,
  rules: [
    { from: "devices", to: "rest" },
    { from: "devices", to: "servers", ports: ["22/tcp"] },
    { from: "devices", to: P, ports: ["53", "80/tcp"] },
    { from: I, to: P, ports: ["53/udp"] },
  ],
  block: "b10c",
  lines: [],
  members: [LAPTOP, PHONE],
  savedAt: "2026-10-27T07:21:00Z",
  savedBy: "dev-1",
  connectedAt: "2026-10-27T07:20:00Z",
};

const OPEN = [P, I, V1, V2].map((id) =>
  server(id, { tags: undefined, reach: [{ from: ["*"], ports: ["*"] }] }),
);

const listener = (
  address: string,
  port: number,
  protocol: "tcp" | "udp",
  process: string,
) => ({ address, port, protocol, process });

const LISTENERS = {
  [P]: [
    listener("0.0.0.0", 22, "tcp", "sshd"),
    listener("0.0.0.0", 53, "tcp", "Resolver"),
    listener("0.0.0.0", 53, "udp", "Resolver"),
    listener("::", 80, "tcp", "Resolver"),
    listener("0.0.0.0", 3000, "tcp", "Resolver"),
    listener("0.0.0.0", 41641, "udp", "tailscaled"),
    listener("127.0.0.1", 5353, "udp", "resolved"),
    listener("10.88.0.4", 9000, "tcp", "app"),
  ],
  [I]: [
    listener("0.0.0.0", 22, "tcp", "sshd"),
    listener("100.101.7.11", 8080, "tcp", "app"),
  ],
  [V1]: [listener("0.0.0.0", 22, "tcp", "sshd")],
  [V2]: [listener("::", 22, "tcp", "sshd")],
};

const IN_USE = {
  [P]: [
    { from: LAPTOP, port: "22/tcp" },
    { from: LAPTOP, port: "53/udp" },
    { from: PHONE, port: "80/tcp" },
    { from: ADDRESS[I]!, port: "53/udp" },
  ],
};

async function serverKey() {
  const pair = (await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  )) as CryptoKeyPair;
  const raw = new Uint8Array(
    await crypto.subtle.exportKey("raw", pair.publicKey),
  );
  return btoa(String.fromCharCode(...raw))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

describe("before Connect", () => {
  it("is amber only when some server lets every device reach every port", () => {
    expect(beforeConnect(OPEN)).toEqual({
      heading: "Tailscale tail0000.ts.net",
      title:
        "Every device on your tailnet can reach every port on your servers",
      note: "Each server reads this from its own Tailscale. It comes from the default rule in your policy file.",
      rows: [
        {
          nodeId: P,
          name: "server-1",
          address: "100.101.7.20",
          devices: "8 devices",
          ports: "All ports",
        },
        {
          nodeId: I,
          name: "server-2",
          address: "100.101.7.11",
          devices: "8 devices",
          ports: "All ports",
        },
        {
          nodeId: V1,
          name: "vps-1",
          address: "100.101.7.10",
          devices: "8 devices",
          ports: "All ports",
        },
        {
          nodeId: V2,
          name: "vps-2",
          address: "100.101.7.12",
          devices: "8 devices",
          ports: "All ports",
        },
      ],
      offer: {
        title: "Krynodes can keep these rules for your servers",
        note: "Rules for your laptop, phone and other people stay yours, in Tailscale's admin console.",
      },
    });
    expect(
      beforeConnect([
        server(P, { reach: [{ from: ["*"], ports: ["22/tcp"] }] }),
      ]),
    ).toBeNull();
    expect(beforeConnect([server(P, { reach: null })])).toBeNull();
    expect(
      beforeConnect([
        server(P, {
          peers: undefined,
          reach: [{ from: ["*"], ports: ["*"] }],
        }),
      ])?.rows[0]?.devices,
    ).toBe("--");
  });
});

describe("Start With These Rules", () => {
  const rows = proposals(OPEN, LISTENERS, IN_USE);

  it("proposes what listens, ticks what is in use, collapses a port on every server and locks the way back last", () => {
    expect(
      rows.map((row) => [row.from, row.to, row.ports, row.ticked, row.locked]),
    ).toEqual([
      ["Your devices", "All servers", "22/tcp", true, false],
      ["Your devices", "server-1", "53 · 80/tcp", true, false],
      ["Your devices", "server-1", "3000/tcp", false, false],
      ["Your devices", "server-2", "8080/tcp", false, false],
      ["server-2", "server-1", "53/udp", true, false],
      ["Your servers", "your devices", "Never", false, true],
    ]);
    expect(rows.map((row) => row.inUse)).toEqual([
      true,
      true,
      false,
      false,
      true,
      false,
    ]);
    expect(rows.map((row) => row.rule)).toEqual([
      { from: "devices", to: "servers", ports: ["22/tcp"] },
      { from: "devices", to: P, ports: ["53", "80/tcp"] },
      { from: "devices", to: P, ports: ["3000/tcp"] },
      { from: "devices", to: I, ports: ["8080/tcp"] },
      { from: I, to: P, ports: ["53/udp"] },
      null,
    ]);
    expect(new Set(rows.map((row) => row.id)).size).toBe(rows.length);
  });

  it("saves the open rule's replacement only when the read found one, then what is ticked", () => {
    const ticked = rows.filter((row) => row.ticked).map((row) => row.id);
    expect(startRules(true, rows, ticked)).toEqual([
      { from: "devices", to: "rest" },
      { from: "devices", to: "servers", ports: ["22/tcp"] },
      { from: "devices", to: P, ports: ["53", "80/tcp"] },
      { from: I, to: P, ports: ["53/udp"] },
    ]);
    expect(startRules(false, rows, [rows[2]!.id, "back"])).toEqual([
      { from: "devices", to: P, ports: ["3000/tcp"] },
    ]);
  });

  it("says who loses access", () => {
    const ticked = rows.filter((row) => row.ticked).map((row) => row.id);
    expect(losesAccess(OPEN, rows, ticked)).toEqual([
      "Every server → your devices",
      "Servers → each other, except server-2 → server-1 53/udp",
      "Your devices → server-1 3000/tcp, server-2 8080/tcp, and every other port",
    ]);
    expect(losesAccess(OPEN, rows, [])).toEqual([
      "Every server → your devices",
      "Servers → each other",
      "Your devices → all servers 22/tcp, server-1 53 · 80/tcp, server-1 3000/tcp, server-2 8080/tcp, and every other port",
    ]);
  });
});

describe("the Network page once connected", () => {
  it("lists Krynodes' rules, then the locked way back", () => {
    expect(ruleRows(CONNECTED, SERVERS)).toEqual([
      {
        index: 1,
        route: "Your devices → All servers",
        ports: "22/tcp",
        locked: false,
        editable: true,
      },
      {
        index: 2,
        route: "Your devices → server-1",
        ports: "53 · 80/tcp",
        locked: false,
        editable: true,
      },
      {
        index: 3,
        route: "server-2 → server-1",
        ports: "53/udp",
        locked: false,
        editable: true,
      },
      {
        index: null,
        route: "Your servers → your devices",
        ports: "Never",
        locked: true,
        editable: false,
      },
    ]);
  });

  it("offers no Edit for a rule kept as it was written", () => {
    const kept = {
      ...CONNECTED,
      rules: [
        ...CONNECTED.rules,
        {
          raw: '{"src":["autogroup:member"],"dst":["100.101.7.20"],"ip":["tcp:3000"]}',
        },
      ],
    };
    expect(ruleRows(kept, SERVERS).map((row) => row.editable)).toEqual([
      true,
      true,
      true,
      false,
      false,
    ]);
  });

  it("shows what lets someone else in, and nothing Krynodes' rules explain", () => {
    expect(outsideRows(CONNECTED, SERVERS)).toEqual([
      {
        id: `${P}:${IPAD},${TV}`,
        route: "ipad, tv → server-1",
        ports: "80/tcp",
      },
    ]);
    expect(
      outsideRows(CONNECTED, [
        server(P, {
          reach: [...SERVER_ONE_REACH, { from: ["*"], ports: ["*"] }],
        }),
        ...SERVERS.slice(1),
      ]).map((row) => `${row.route} · ${row.ports}`),
    ).toEqual([
      "ipad, tv → server-1 · 80/tcp",
      "Everyone → server-1 · every port",
    ]);
  });

  it("names who may reach a server, one source per line", () => {
    expect(serverLines(SERVERS[0]!, CONNECTED, SERVERS)).toEqual({
      tag: "tag:kry · key never expires",
      sources: [
        {
          source: "Your devices",
          ports: "22/tcp · 53 · 80/tcp",
          outside: false,
        },
        { source: "server-2", ports: "53/udp", outside: false },
        { source: "ipad, tv", ports: "80/tcp", outside: true },
      ],
    });
    expect(serverLines(server(V4, { tags: [] }), null, SERVERS)).toEqual({
      tag: null,
      sources: [],
    });
  });

  it("reads Applied as a superset of the saved rules", () => {
    expect(applied(SERVERS[0]!, CONNECTED, SERVERS)).toBe(true);
    expect(applied(SERVERS[1]!, CONNECTED, SERVERS)).toBe(true);
    expect(
      applied(
        server(P, {
          reach: [...SERVER_ONE_REACH, { from: ["*"], ports: ["*"] }],
        }),
        CONNECTED,
        SERVERS,
      ),
    ).toBe(false);
    expect(
      applied(
        server(P, {
          reach: [
            { from: [LAPTOP, PHONE], ports: ["22/tcp", "53"] },
            ...SERVER_ONE_REACH.slice(1),
          ],
        }),
        CONNECTED,
        SERVERS,
      ),
    ).toBe(false);
    expect(applied(server(P, { reach: null }), CONNECTED, SERVERS)).toBeNull();
  });

  it("says Rules not applied yet only five minutes after the save", () => {
    const servers = [SERVERS[0]!, server(I, { reach: [] })];
    const saved = Date.parse(CONNECTED.savedAt!);
    expect(notApplied(CONNECTED, servers, saved + 4 * 60_000)).toEqual([]);
    expect(notApplied(CONNECTED, servers, saved + 6 * 60_000)).toEqual([
      {
        nodeId: I,
        title: "Tailscale Rules not applied yet",
        text: "server-2's Tailscale has not taken the rules saved 6 minutes ago. Is tailscaled running?",
      },
    ]);
  });

  it("reads a grant line, and keeps a line it cannot read", () => {
    expect(
      ruleText(
        '{"src":["autogroup:member"],"dst":["100.101.7.20","fd7a:115c:a1e0::20"],"ip":["tcp:53","udp:53","tcp:80"]}',
        [server(P, { addresses: ["100.101.7.20", "fd7a:115c:a1e0::20"] })],
      ),
    ).toBe("Your devices → server-1 · 53 · 80/tcp");
    expect(
      ruleText(
        `{"src":["100.101.7.44"],"dst":["100.101.7.10","100.101.7.11","100.101.7.12","100.101.7.20"],"ip":["*"]}`,
        SERVERS,
      ),
    ).toBe("100.101.7.44 → All servers · every port");
    expect(ruleText('{"src":["*"],"app":{"x":[]}}', SERVERS)).toBe(
      '{"src":["*"],"app":{"x":[]}}',
    );
    expect(ruleText("not a grant", SERVERS)).toBe("not a grant");
    expect(ruleText({ from: I, to: P, ports: ["53/udp"] }, SERVERS)).toBe(
      "server-2 → server-1 · 53/udp",
    );
    expect(ruleText({ from: "devices", to: "rest" }, SERVERS)).toBe(
      "Your devices → everything except your servers",
    );
    expect(
      ruleText({ from: "devices", to: V4, ports: ["22/tcp"] }, SERVERS),
    ).toBe("Your devices → -- · 22/tcp");
  });

  it("raises the two alarms in red, in the browser's time", () => {
    expect(
      alarmRows(
        [
          {
            id: "a",
            kind: "device",
            at: "2026-10-26T20:12:00Z",
            device: { name: "nas-7.tail0000.ts.net", tag: "tag:kry" },
          },
          {
            id: "b",
            kind: "policy",
            at: "2026-10-26T20:14:00Z",
            change: {
              block: true,
              added: 1,
              removed: 0,
              lines: [
                '+ {"src":["100.101.7.44"],"dst":["100.101.7.10","100.101.7.11","100.101.7.12","100.101.7.20"],"ip":["*"]}',
              ],
            },
          },
        ],
        SERVERS,
      ),
    ).toEqual([
      {
        id: "a",
        title: "nas-7",
        detail: "nas-7.tail0000.ts.net",
        tag: "tag:kry",
        text: "Joined at 03:12 with your servers' tag, but Krynodes never signed it in. Your rules give it nothing. Enroll it, or remove it in Tailscale's admin console.",
        lines: [],
        link: "https://login.tailscale.com/admin/machines",
      },
      {
        id: "b",
        title:
          "Your policy was changed with Krynodes' credential at 03:14, without your passkey",
        detail: null,
        tag: null,
        text: "Someone else has the credential. Delete it in Tailscale's admin console, then connect a new one. Krynodes cannot undo the change on its own.",
        lines: ["+ 100.101.7.44 → All servers · every port"],
        link: "https://login.tailscale.com/admin/machines",
      },
    ]);
  });

  it("says what a new rule does and what a removed one stops", () => {
    expect(
      addRuleEffect({ from: "devices", to: P, ports: ["3000/tcp"] }, SERVERS),
    ).toBe("Your devices can now reach server-1 on 3000/tcp.");
    expect(
      addRuleEffect(
        { from: I, to: "servers", ports: ["22/tcp", "9100/tcp"] },
        SERVERS,
      ),
    ).toBe("server-2 can now reach all servers on 22/tcp and 9100/tcp.");
    expect(
      removeText({ from: I, to: P, ports: ["53/udp"] }, SERVERS, [P, V1, V2]),
    ).toEqual({
      title: "Remove server-2 → server-1?",
      body: "server-2 can no longer reach server-1 on 53/udp over Tailscale. server-2 is not on your private network, so its DNS lookups to server-1 stop.",
    });
    expect(
      removeText({ from: P, to: I, ports: ["8080/tcp"] }, SERVERS, [I]).body,
    ).toBe(
      "server-1 can no longer reach server-2 on 8080/tcp over Tailscale. server-1 is not on your private network, so its connections to server-2 on 8080/tcp stop.",
    );
    expect(
      removeText({ from: I, to: P, ports: ["53/udp"] }, SERVERS, [I, P]).body,
    ).toBe("server-2 can no longer reach server-1 on 53/udp over Tailscale.");
    expect(
      removeText(
        { from: "devices", to: "servers", ports: ["22/tcp"] },
        SERVERS,
        [],
      ),
    ).toEqual({
      title: "Remove Your devices → All servers?",
      body: "Your devices can no longer reach all servers on 22/tcp over Tailscale.",
    });
  });

  it("says a server signed in with a one-time key is on the tailnet", () => {
    const joined = server(V4, {
      addresses: ["100.101.7.13"],
      name: "vps-4.tail0000.ts.net",
    });
    expect(
      joinedLines(joined.report!, "vps-4", CONNECTED, [...SERVERS, joined]),
    ).toEqual({
      title: "vps-4 is on your tailnet",
      intro:
        "It joined with a one-time key tagged kry. There was nothing to approve in Tailscale.",
      lines: [
        {
          mark: "✓",
          title: "100.101.7.13 · vps-4.tail0000.ts.net",
          detail: [],
        },
        {
          mark: "✓",
          title: "Your rules apply to it: your devices on 22/tcp",
          detail: [],
        },
        {
          mark: "·",
          title: "Key never expires · keeps its own DNS · Tailscale SSH off",
          detail: [],
        },
      ],
    });
    expect(
      joinedLines(
        joined.report!,
        "vps-4",
        { ...CONNECTED, rules: [{ from: "devices", to: "rest" }] },
        [joined],
      ).lines[1]!.title,
    ).toBe("Your rules give it nothing yet");
  });
});

describe("the steps", () => {
  const KEY = { [P]: "key-p", [I]: "key-i", [V4]: "key-4" };
  const USE = { assembler: P, releaser: I };

  it("refuses Connect with fewer than two holders, and splits the secret otherwise", async () => {
    const one = [{ nodeId: P, sealKey: await serverKey() }];
    const input = {
      secret: "tskey-client-k1",
      set: SET,
      tailnet: "tail0000.ts.net",
      clientId: "kT9xQ2hN4CNTRL",
      webhookSecret: "whsec",
    };
    expect(await connectSteps({ ...input, holders: one })).toEqual({
      ok: false,
      reason:
        "Connect needs two servers with agent 0.7.0 that your passkey reaches; 1 is.",
    });
    const two = await connectSteps({
      ...input,
      holders: [...one, { nodeId: I, sealKey: await serverKey() }],
    });
    expect(two.ok && two.tailscale).toEqual({
      tailnet: "tail0000.ts.net",
      clientId: "kT9xQ2hN4CNTRL",
      webhookSecret: "whsec",
    });
    expect(
      two.ok &&
        two.steps.map((step) => [
          step.nodeId,
          step.name,
          step.action,
          step.args,
        ]),
    ).toEqual([
      [P, "tailscale", "store", { set: SET, holders: "2" }],
      [I, "tailscale", "store", { set: SET, holders: "2" }],
    ]);
  });

  it("reads, saves, signs in and removes through one release", () => {
    const release = {
      nodeId: I,
      kind: "vault",
      name: "tailscale",
      action: "release",
      args: { to: P, key: "key-p", set: SET },
    };
    const job = (action: string, args: Record<string, string>) => ({
      nodeId: P,
      kind: "vault",
      name: "tailscale",
      action,
      args: { client: "kT9xQ2hN4CNTRL", ...args },
      attachFrom: 0,
    });
    expect(readSteps(USE, KEY, CONNECTED)).toEqual([
      release,
      job("policy", {}),
    ]);
    expect(
      saveSteps({
        use: USE,
        keyOf: KEY,
        connected: CONNECTED,
        rules: CONNECTED.rules,
        servers: [
          ...SERVERS,
          server(V4, { tags: [], id: "nvps4CNTRL" }),
          { ...server(V2), nodeId: "gone", report: null },
        ],
        expected: "b10c",
        tag: true,
        label: "Start With These Rules",
      }),
    ).toEqual([
      release,
      job("save", {
        rules: JSON.stringify(CONNECTED.rules),
        servers: JSON.stringify({
          [P]: ["100.101.7.20"],
          [I]: ["100.101.7.11"],
          [V1]: ["100.101.7.10"],
          [V2]: ["100.101.7.12"],
          [V4]: ["100.101.7.13"],
        }),
        expected: "b10c",
        tag: "nvps4CNTRL",
        label: "Start With These Rules",
      }),
    ]);
    expect(joinSteps(USE, KEY, CONNECTED, V4)).toEqual([
      release,
      job("key", { to: V4, key: "key-4" }),
      {
        nodeId: V4,
        kind: "host",
        name: "tailscale",
        action: "join",
        attachFrom: 1,
      },
    ]);
    expect(removeSteps(USE, KEY, CONNECTED, "nvps1CNTRL", V1)).toEqual([
      release,
      job("remove", { device: "nvps1CNTRL", node: V1 }),
    ]);
    expect(disconnectSteps(SERVERS)).toEqual(
      [P, I, V1, V2].map((nodeId) => ({
        nodeId,
        kind: "vault",
        name: "tailscale",
        action: "forget",
      })),
    );
  });
});

describe("History", () => {
  const text = (kind: string, action: string, nodeName?: string) =>
    tailnetActionText(
      { kind, name: "tailscale", action } as Parameters<
        typeof tailnetActionText
      >[0],
      nodeName,
    );

  it("names each Tailscale step in sentence case", () => {
    expect(text("vault", "store")).toBe("Connect Tailscale");
    expect(text("vault", "policy")).toBe("Read the Tailscale policy file");
    expect(text("vault", "save")).toBe("Save Tailscale rules");
    expect(text("vault", "key")).toBe("Make a one-time Tailscale key");
    expect(text("vault", "remove")).toBe("Remove a server from your tailnet");
    expect(text("vault", "reshare")).toBe("Reshare the Tailscale credential");
    expect(text("host", "join", "vps-2")).toBe("Sign in vps-2 to Tailscale");
    expect(text("host", "join")).toBe("Sign in to Tailscale");
    expect(text("host", "inspect")).toBe("Read what is in use on Tailscale");
    expect(text("vault", "release")).toBeNull();
    expect(
      tailnetActionText({ kind: "vault", name: "cloudflare", action: "store" }),
    ).toBeNull();
  });
});

describe("a changed Krynodes rule", () => {
  const ALL = [V1, V2, P, I].sort().map((id) => ADDRESS[id]!);
  const REST =
    '{"src":["autogroup:member"],"dst":["autogroup:member","autogroup:internet"],"ip":["*"]}';
  const SSH = `{"src":["autogroup:member"],"dst":${JSON.stringify(ALL)},"ip":["tcp:22"]}`;
  const DNS =
    '{"src":["autogroup:member"],"dst":["100.101.7.20"],"ip":["tcp:53","udp:53","tcp:80"]}';
  const IO = '{"src":["100.101.7.11"],"dst":["100.101.7.20"],"ip":["udp:53"]}';
  const WIDER =
    '{"src":["autogroup:member"],"dst":["100.101.7.20"],"ip":["tcp:53","udp:53","tcp:80","tcp:3000"]}';
  const SAVED = { ...CONNECTED, lines: [REST, SSH, DNS, IO] };
  const NOW = [REST, SSH, WIDER, IO];

  it("shows what was taken out and put in, in words", () => {
    expect(changedLines(SAVED, NOW, SERVERS)).toEqual([
      "- Your devices → server-1 · 53 · 80/tcp",
      "+ Your devices → server-1 · 53 · 80/tcp · 3000/tcp",
    ]);
  });

  it("keeps the change as a rule of its own, then adds yours", () => {
    const added = { from: "devices" as const, to: I, ports: ["8080/tcp"] };
    expect(keepChange(SAVED, NOW, [...CONNECTED.rules, added])).toEqual([
      CONNECTED.rules[0],
      CONNECTED.rules[1],
      { raw: WIDER },
      CONNECTED.rules[3],
      added,
    ]);
  });

  it("names a changed line that is not one grant on one line", () => {
    const split = [
      '{"src":["autogroup:member"]',
      '"dst":["100.101.7.20"]',
      '"ip":["tcp:3000"]}',
    ];
    expect(brokenLines(SAVED, [REST, SSH, ...split, IO])).toEqual(split);
    expect(brokenLines(SAVED, NOW)).toEqual([]);
  });

  it("still takes out the rule you removed", () => {
    expect(keepChange(SAVED, NOW, CONNECTED.rules.slice(0, 3))).toEqual([
      CONNECTED.rules[0],
      CONNECTED.rules[1],
      { raw: WIDER },
    ]);
  });
});

describe("Add Rule and Edit Rule", () => {
  const form = (over: Partial<Parameters<typeof ruleForm>[0]>) =>
    ruleForm({
      connected: CONNECTED,
      index: null,
      servers: SERVERS,
      listeners: LISTENERS,
      from: "devices",
      to: P,
      ticked: [],
      other: "",
      ...over,
    });

  it("offers what listens on the target with its process, apart from what is allowed already", () => {
    expect(form({ ticked: ["3000/tcp"], other: " 9100/tcp " })).toEqual({
      options: [{ port: "3000/tcp", process: "Resolver" }],
      allowed: ["22/tcp", "53", "80/tcp"],
      rule: { from: "devices", to: P, ports: ["3000/tcp", "9100/tcp"] },
      problem: null,
      readable: true,
      ready: true,
    });
  });

  it("keeps the edited rule's own ports on offer, even one nothing listens on", () => {
    expect(
      form({ index: 2, ticked: ["53", "80/tcp", "9100/tcp"] }),
    ).toMatchObject({
      options: [
        { port: "53", process: "Resolver" },
        { port: "80/tcp", process: "Resolver" },
        { port: "3000/tcp", process: "Resolver" },
        { port: "9100/tcp", process: null },
      ],
      allowed: ["22/tcp"],
      ready: true,
    });
  });

  it("offers for All servers only what listens on every server", () => {
    expect(form({ to: "servers" })).toMatchObject({
      options: [],
      allowed: ["22/tcp"],
      ready: false,
    });
  });

  it("refuses an unreadable port and a server reaching itself", () => {
    expect(form({ ticked: ["3000/tcp"], other: "abc" })).toMatchObject({
      problem:
        "Other Port takes one port or a range, like 9100/tcp or 6000-6010.",
      readable: false,
      ready: false,
    });
    expect(form({ from: P, ticked: ["3000/tcp"] })).toMatchObject({
      problem: "A server always reaches itself. Pick another one.",
      ready: false,
    });
  });
});

describe("Exit Node and Tailscale DNS rows", () => {
  const running: TailscaleReport = {
    state: "running",
    addresses: ["100.101.7.20"],
    name: "server-1.tail0000.ts.net",
    keyExpiry: null,
  };

  it("says what an agent before 0.7.4 cannot do yet", () => {
    for (const line of [exitNodeLine, dnsLine]) {
      expect(line(running, "0.7.3")).toEqual({
        text: "Needs agent 0.7.4 or newer",
        warn: false,
        changes: false,
      });
    }
  });

  it("shows -- when the server could not read it", () => {
    for (const line of [exitNodeLine, dnsLine]) {
      expect(line(running, "0.7.4")).toEqual({
        text: "--",
        warn: false,
        changes: true,
      });
      expect(
        line({ ...running, exitNode: null, acceptDNS: null }, "0.7.4").text,
      ).toBe("--");
    }
  });

  it("names off, on and waiting for Tailscale's approval", () => {
    const exit = (advertised: boolean, approved: boolean) =>
      exitNodeLine({ ...running, exitNode: { advertised, approved } }, "0.7.4");
    expect(exit(false, false)).toEqual({
      text: "Off",
      warn: false,
      changes: true,
    });
    expect(exit(true, true)).toEqual({
      text: "On",
      warn: false,
      changes: true,
    });
    expect(exit(true, false)).toEqual({
      text: "Waiting for approval in Tailscale",
      warn: true,
      changes: true,
    });
    expect(dnsLine({ ...running, acceptDNS: true }, "0.7.4").text).toBe("On");
    expect(dnsLine({ ...running, acceptDNS: false }, "0.7.4").text).toBe("Off");
  });

  it("explains the exit node before turning it on or off", () => {
    expect(exitNodeText("server-1", true, true)).toEqual([
      "Devices on your tailnet can send all their internet traffic through server-1.",
      "Their traffic counts against server-1's bandwidth. A device using it loses internet while server-1 is down, until it picks no exit node.",
      "Tailscale approves it through the rules Krynodes keeps for tag:kry.",
    ]);
    expect(exitNodeText("server-1", true, false)[2]).toBe(
      "Approve it in Tailscale's admin console (Machines → server-1 → Edit route settings).",
    );
    expect(exitNodeText("server-1", false, true)).toEqual([
      "server-1 stops offering itself as an exit node. A device using it loses internet until it picks another exit node or none.",
    ]);
  });

  it("explains Tailscale DNS before turning it on or off", () => {
    expect(dnsText("server-1", true)).toEqual([
      "server-1 looks names up through Tailscale, so it finds your devices and servers by their tailnet names.",
      "A DNS server running on server-1 keeps working, but server-1's own lookups go through Tailscale.",
      "If server-1 cannot find Krynodes by name this way, Tailscale DNS is turned back off.",
    ]);
    expect(dnsText("server-1", false)).toEqual([
      "server-1 looks names up with its own DNS settings again.",
    ]);
  });

  it("names both steps in History", () => {
    const step = (action: "exitnode" | "dns") =>
      tailnetActionText({ kind: "host", name: "tailscale", action }, "vps-2");
    expect(step("exitnode")).toBe("Change Exit Node on vps-2");
    expect(step("dns")).toBe("Change Tailscale DNS on vps-2");
  });
});
