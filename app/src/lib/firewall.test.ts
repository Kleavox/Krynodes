import { describe, expect, it } from "vitest";

import type { SecurityReport } from "../types";
import {
  addressesOf,
  closedText,
  closingPorts,
  firewallActionText,
  firewallStatus,
  fromText,
  listensText,
  openPortProblem,
  portsArg,
  turnOnRows,
} from "./firewall";
import { recipeChoices } from "./security";

const report = (over: Partial<SecurityReport> = {}): SecurityReport => ({
  checkedAt: "2026-10-29T10:00:00.000Z",
  findings: [],
  recipes: [],
  lockdown: false,
  rebootHour: null,
  ...over,
});

const listeners: NonNullable<SecurityReport["listeners"]> = [
  { address: "0.0.0.0", port: 443, protocol: "tcp", process: "caddy" },
  { address: "::", port: 443, protocol: "tcp", process: "caddy" },
  { address: "0.0.0.0", port: 3000, protocol: "tcp", process: "grafana-1" },
  { address: "0.0.0.0", port: 51820, protocol: "udp", process: "WireGuard" },
];

const stacks = [
  { project: "grafana", access: "full" as const, public: ["3000/tcp"] },
  { project: "notes", access: "contained" as const, public: [] },
];

const firewallOf = (choices: ReturnType<typeof recipeChoices>) =>
  choices.find((choice) => choice.id === "firewall")!;

describe("the firewall row in Protections", () => {
  it("says closed with its open ports and offers Turn Off", () => {
    const closed = report({
      recipes: ["firewall"],
      firewall: {
        closed: true,
        open: [{ port: 443, protocol: "tcp", from: "everyone" }],
        other: [],
      },
    });
    expect(firewallStatus(closed, firewallOf(recipeChoices(closed)))).toEqual({
      text: "Closed · 1 open port",
      actions: ["off"],
    });
    const none = report({
      recipes: ["firewall"],
      firewall: { closed: true, open: [], other: [] },
    });
    expect(firewallStatus(none, firewallOf(recipeChoices(none))).text).toBe(
      "Closed · no open ports",
    );
  });

  it("offers Close Everything Else to a firewall Krynodes does not manage", () => {
    const old = report({
      recipes: ["firewall"],
      firewall: { closed: false, open: [], other: [] },
    });
    expect(firewallStatus(old, firewallOf(recipeChoices(old)))).toEqual({
      text: "On · open ports are not managed by Krynodes",
      actions: ["close", "off"],
    });
    const theirs = report({ firewall: { closed: false, open: [], other: [] } });
    expect(firewallStatus(theirs, firewallOf(recipeChoices(theirs)))).toEqual({
      text: "On · open ports are not managed by Krynodes",
      actions: ["close"],
    });
  });

  it("keeps the old states for an agent that reports no firewall", () => {
    const off = report({
      findings: [
        {
          id: "firewall-off",
          severity: "warning",
          detail: "No firewall is active",
        },
      ],
    });
    expect(firewallStatus(off, firewallOf(recipeChoices(off)))).toEqual({
      text: "Off",
      actions: ["on"],
    });
    const on = report({ recipes: ["firewall"] });
    expect(firewallStatus(on, firewallOf(recipeChoices(on)))).toEqual({
      text: "On",
      actions: ["off"],
    });
    const outside = report();
    expect(firewallStatus(outside, firewallOf(recipeChoices(outside)))).toEqual(
      { text: "On · Set up outside Krynodes", actions: [] },
    );
  });
});

describe("what a closed firewall does, in its dialogs", () => {
  it("says what turning on, closing and turning off do", () => {
    expect(closedText("ufw", "on")).toBe(
      "Turns on ufw and lets in only SSH, the private network and the ports you tick. Ports Docker publishes close too, unless you tick them.",
    );
    expect(closedText("firewalld", "close")).toBe(
      "Krynodes takes over firewalld. The open ports below stay open; untick one to close it. Everything else closes, ports Docker publishes too.",
    );
    expect(closedText("ufw", "off")).toBe(
      "Puts ufw back as Krynodes found it, and opens the ports Docker publishes again.",
    );
  });
});

describe("a firewall change in History", () => {
  it("says what changed in the firewall", () => {
    const row = (action: "open" | "close" | "putback" | "apply") =>
      firewallActionText({ kind: "host", name: "firewall", action });
    expect(row("open")).toBe("Open a port in the firewall");
    expect(row("close")).toBe("Close a port in the firewall");
    expect(row("putback")).toBe("Take a rule out of the firewall");
    expect(row("apply")).toBeNull();
    expect(
      firewallActionText({ kind: "host", name: "tailscale", action: "open" }),
    ).toBeNull();
  });
});

describe("an open port's row", () => {
  it("names who it is open to", () => {
    expect(fromText({ from: "everyone" })).toBe("Everyone");
    expect(fromText({ from: "tailscale" })).toBe("Tailscale");
    expect(
      fromText({
        from: "addresses",
        addresses: ["203.0.113.0/24", "2001:db8::/32"],
      }),
    ).toBe("203.0.113.0/24, 2001:db8::/32");
    expect(fromText({ from: "addresses" })).toBe("--");
  });

  it("names the stack that publishes it, else what listens", () => {
    const seen = report({ listeners });
    expect(listensText("3000/tcp", seen, stacks)).toEqual({
      text: "grafana",
      idle: false,
    });
    expect(listensText("443/tcp", seen, stacks)).toEqual({
      text: "caddy",
      idle: false,
    });
    expect(listensText("8443/tcp", seen, stacks)).toEqual({
      text: "Nothing listens",
      idle: true,
    });
    expect(listensText("8443/tcp", report(), [])).toEqual({
      text: "--",
      idle: true,
    });
  });
});

describe("the firewall dialogs", () => {
  it("lists what listens on a public address for Turn On, without the private network's port", () => {
    expect(turnOnRows(report({ listeners }), stacks, "51820/udp")).toEqual([
      {
        opening: { port: 443, protocol: "tcp", from: "everyone" },
        listens: { text: "caddy", idle: false },
      },
      {
        opening: { port: 3000, protocol: "tcp", from: "everyone" },
        listens: { text: "grafana", idle: false },
      },
    ]);
    expect(turnOnRows(report(), stacks, null)).toEqual([
      {
        opening: { port: 3000, protocol: "tcp", from: "everyone" },
        listens: { text: "grafana", idle: false },
      },
    ]);
  });

  it("names every port Docker publishes that closes, with its stack", () => {
    expect(closingPorts(stacks, ["443/tcp"])).toEqual(["3000/tcp · grafana"]);
    expect(closingPorts(stacks, ["3000/tcp"])).toEqual([]);
    const outside = [
      ...stacks,
      { project: "wiki", access: null, public: ["8080/tcp"] },
    ];
    expect(closingPorts(outside, ["3000/tcp"])).toEqual(["8080/tcp · wiki"]);
  });

  it("writes the open ports as the recipe reads them", () => {
    expect(
      portsArg([
        { port: 443, protocol: "tcp", from: "everyone" },
        { port: 8443, protocol: "udp", from: "tailscale" },
        {
          port: 9000,
          protocol: "tcp",
          from: "addresses",
          addresses: ["203.0.113.0/24", "2001:db8::/32"],
        },
      ]),
    ).toBe(
      "443/tcp@everyone,8443/udp@tailscale,9000/tcp@203.0.113.0/24+2001:db8::/32",
    );
    expect(portsArg([])).toBe("");
  });

  it("checks a port before it is opened", () => {
    const open = [
      { port: 443, protocol: "tcp" as const, from: "everyone" as const },
    ];
    expect(openPortProblem("", "tcp", open, null)).toBe(
      "Type a port from 1 to 65535.",
    );
    expect(openPortProblem("70000", "tcp", open, null)).toBe(
      "Type a port from 1 to 65535.",
    );
    expect(openPortProblem("443", "tcp", open, null)).toBe(
      "443/tcp is open already. Change who reaches it from its row.",
    );
    expect(openPortProblem("51820", "udp", open, "51820/udp")).toBe(
      "The private network's port is always open.",
    );
    expect(openPortProblem("443", "udp", open, null)).toBeNull();
  });

  it("takes one to eight addresses or ranges, one per line", () => {
    expect(addressesOf("203.0.113.0/24\n 2001:db8::/32 \n\n")).toEqual({
      addresses: ["203.0.113.0/24", "2001:db8::/32"],
      problem: null,
    });
    expect(addressesOf("").problem).toBe("Type at least one address or range.");
    expect(addressesOf("203.0.113.300").problem).toBe(
      "203.0.113.300 is not an IPv4 or IPv6 address or range.",
    );
    expect(addressesOf("203.0.113.0/33").problem).toBe(
      "203.0.113.0/33 is not an IPv4 or IPv6 address or range.",
    );
    expect(
      addressesOf(
        Array.from({ length: 9 }, (_, index) => `203.0.113.${index}`).join(
          "\n",
        ),
      ).problem,
    ).toBe("Up to 8 addresses or ranges.");
  });
});
