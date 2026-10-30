import type {
  ActionRecord,
  FirewallOpening,
  SecurityReport,
  StackEntry,
} from "../types";

import { rangeLines, type RecipeChoice } from "./security";

type Stack = Pick<StackEntry, "project" | "access" | "public">;

export const MAX_ADDRESSES = 8;

export const openingKey = (
  opening: Pick<FirewallOpening, "port" | "protocol">,
) => `${opening.port}/${opening.protocol}`;

const ACTION_TEXT: Partial<Record<ActionRecord["action"], string>> = {
  open: "Open a port in the firewall",
  close: "Close a port in the firewall",
  putback: "Take a rule out of the firewall",
};

export const firewallActionText = (
  action: Pick<ActionRecord, "kind" | "name" | "action">,
) =>
  action.kind === "host" && action.name === "firewall"
    ? (ACTION_TEXT[action.action] ?? null)
    : null;

export function firewallStatus(
  report: SecurityReport,
  choice: RecipeChoice,
): { text: string; actions: ("on" | "close" | "off")[] } {
  const wall = report.firewall;
  if (wall?.closed) {
    const count = wall.open.length;
    return {
      text: `Closed · ${count === 0 ? "no open ports" : `${count} open port${count === 1 ? "" : "s"}`}`,
      actions: ["off"],
    };
  }
  if (wall) {
    return {
      text: "On · open ports are not managed by Krynodes",
      actions: choice.applied ? ["close", "off"] : ["close"],
    };
  }
  if (choice.applied) return { text: "On", actions: ["off"] };
  if (choice.outside) {
    return { text: "On · Set up outside Krynodes", actions: [] };
  }
  return { text: "Off", actions: choice.blocked ? [] : ["on"] };
}

export function closedText(name: string, step: "on" | "close" | "off") {
  if (step === "on") {
    return `Turns on ${name} and lets in only SSH, the private network and the ports you tick. Ports Docker publishes close too, unless you tick them.`;
  }
  if (step === "close") {
    return `Krynodes takes over ${name}. The open ports below stay open; untick one to close it. Everything else closes, ports Docker publishes too.`;
  }
  return `Puts ${name} back as Krynodes found it, and opens the ports Docker publishes again.`;
}

export function fromText(
  opening: Pick<FirewallOpening, "from" | "addresses">,
): string {
  if (opening.from === "everyone") return "Everyone";
  if (opening.from === "tailscale") return "Tailscale";
  return opening.addresses?.join(", ") || "--";
}

const published = (stacks: Stack[]) =>
  stacks.flatMap((stack) =>
    stack.access === "contained"
      ? []
      : (stack.public ?? []).map((key) => ({ key, project: stack.project })),
  );

export function listensText(
  key: string,
  report: SecurityReport,
  stacks: Stack[],
): { text: string; idle: boolean } {
  const projects = published(stacks)
    .filter((entry) => entry.key === key)
    .map((entry) => entry.project);
  const processes = (report.listeners ?? [])
    .filter((listener) => openingKey(listener) === key)
    .map((listener) => listener.process || "--");
  const names = [...new Set(projects.length > 0 ? projects : processes)];
  if (names.length > 0) return { text: names.join(", "), idle: false };
  return {
    text:
      report.listeners === undefined && projects.length === 0
        ? "--"
        : "Nothing listens",
    idle: true,
  };
}

const portNumber = (key: string) => Number(key.split("/")[0]);

export function turnOnRows(
  report: SecurityReport,
  stacks: Stack[],
  networkPort: string | null,
) {
  const keys = new Set([
    ...(report.listeners ?? []).map(openingKey),
    ...published(stacks).map((entry) => entry.key),
  ]);
  return [...keys]
    .filter((key) => key !== networkPort)
    .sort((a, b) => portNumber(a) - portNumber(b) || a.localeCompare(b))
    .map((key) => ({
      opening: {
        port: portNumber(key),
        protocol: key.endsWith("/udp") ? "udp" : "tcp",
        from: "everyone",
      } satisfies FirewallOpening,
      listens: listensText(key, report, stacks),
    }));
}

export const closingPorts = (stacks: Stack[], kept: string[]) =>
  published(stacks)
    .filter((entry) => !kept.includes(entry.key))
    .map((entry) => `${entry.key} · ${entry.project}`);

export const fromArg = (
  opening: Pick<FirewallOpening, "from" | "addresses">,
) =>
  opening.from === "addresses"
    ? (opening.addresses ?? []).join("+")
    : opening.from;

export const portsArg = (open: FirewallOpening[]) =>
  open.map((opening) => `${openingKey(opening)}@${fromArg(opening)}`).join(",");

export function openPortProblem(
  port: string,
  protocol: FirewallOpening["protocol"],
  open: FirewallOpening[],
  networkPort: string | null,
): string | null {
  const number = Number(port);
  if (!/^\d{1,5}$/u.test(port) || number < 1 || number > 65_535) {
    return "Type a port from 1 to 65535.";
  }
  const key = `${number}/${protocol}`;
  if (key === networkPort) return "The private network's port is always open.";
  if (open.some((opening) => openingKey(opening) === key)) {
    return `${key} is open already. Change who reaches it from its row.`;
  }
  return null;
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/u;
const IPV6 = /^[\dA-Fa-f:]{2,39}(?:\/(\d{1,3}))?$/u;

function addressFits(text: string): boolean {
  const four = IPV4.exec(text);
  if (four) {
    return (
      four.slice(1, 5).every((part) => Number(part) <= 255) &&
      Number(four[5] ?? 32) <= 32
    );
  }
  const six = IPV6.exec(text);
  return six !== null && text.includes(":") && Number(six[1] ?? 128) <= 128;
}

export function addressesOf(text: string): {
  addresses: string[];
  problem: string | null;
} {
  const addresses = rangeLines(text);
  const wrong = addresses.find((address) => !addressFits(address));
  return {
    addresses,
    problem:
      addresses.length === 0
        ? "Type at least one address or range."
        : addresses.length > MAX_ADDRESSES
          ? `Up to ${MAX_ADDRESSES} addresses or ranges.`
          : wrong
            ? `${wrong} is not an IPv4 or IPv6 address or range.`
            : null,
  };
}
