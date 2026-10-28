import {
  portSchema,
  TAILSCALE,
  type TailnetRule,
  type TailscaleReport,
} from "@krynodes/protocol";
import { MIN_AGENT_VERSION } from "@krynodes/protocol/versions";

import type {
  ActionRecord,
  ActionVerb,
  TailnetAlarm,
  TailnetConnected,
  TailnetServer,
} from "../types";
import { clockTime, parseTimestamp } from "./format";
import { listOf } from "./network";
import type { Line } from "./packages";
import { TAILSCALE_CONSOLE } from "./quarantine";
import {
  release,
  splitSteps,
  type Holder,
  type OperationTarget,
} from "./vault";

type PortRule = Extract<TailnetRule, { ports: string[] }>;

interface Listening {
  address: string;
  port: number;
  protocol: "tcp" | "udp";
  process: string;
}

interface Seen {
  from: string;
  port: string;
}

export interface Proposal {
  id: string;
  from: string;
  to: string;
  ports: string;
  ticked: boolean;
  locked: boolean;
  inUse: boolean;
  rule: PortRule | null;
}

const SPAN = /^(\d+)(?:-(\d+))?(?:\/(tcp|udp))?$/u;

function span(port: string) {
  const match = SPAN.exec(port);
  return match
    ? {
        first: Number(match[1]),
        last: Number(match[2] ?? match[1]),
        protocol: match[3] ?? null,
      }
    : null;
}

function covers(outer: string, inner: string) {
  if (outer === "*") return true;
  const a = span(outer);
  const b = span(inner);
  return (
    !!a &&
    !!b &&
    a.first <= b.first &&
    b.last <= a.last &&
    (a.protocol === null || a.protocol === b.protocol)
  );
}

const pieces = (port: string) =>
  port === "*" || port.includes("/") ? [port] : [`${port}/tcp`, `${port}/udp`];

const portsText = (ports: string[]) =>
  ports.includes("*") ? "every port" : ports.join(" · ");

const portsList = (ports: string[]) =>
  ports.includes("*") ? "every port" : listOf(ports);

const nameOf = (servers: TailnetServer[], id: string) =>
  servers.find((server) => server.nodeId === id)?.name ?? "--";

const serverAt = (servers: TailnetServer[], address: string) =>
  servers.find((server) => server.report?.addresses.includes(address));

const sourceText = (servers: TailnetServer[], from: string) =>
  from === "devices"
    ? "Your devices"
    : from === "servers"
      ? "All servers"
      : nameOf(servers, from);

const targetText = (servers: TailnetServer[], to: string) =>
  to === "servers"
    ? "All servers"
    : to === "rest"
      ? "everything except your servers"
      : nameOf(servers, to);

const reachText = (servers: TailnetServer[], to: string) =>
  to === "servers" ? "all servers" : nameOf(servers, to);

const isRest = (rule: TailnetRule) => "to" in rule && rule.to === "rest";

const BACK = {
  route: "Your servers → your devices",
  ports: "Never",
};

export function beforeConnect(servers: TailnetServer[]) {
  const open = servers.filter((server) =>
    server.report?.reach?.some(
      (entry) => entry.from.includes("*") && entry.ports.includes("*"),
    ),
  );
  if (open.length === 0) return null;
  const tailnet =
    servers.find((server) => server.report?.tailnet)?.report?.tailnet ?? "--";
  return {
    heading: `Tailscale ${tailnet}`,
    title: "Every device on your tailnet can reach every port on your servers",
    note: "Each server reads this from its own Tailscale. It comes from the default rule in your policy file.",
    rows: open.map((server) => {
      const peers = server.report!.peers;
      return {
        nodeId: server.nodeId,
        name: server.name,
        address: server.report!.addresses[0] ?? "--",
        devices:
          peers === undefined
            ? "--"
            : `${peers} device${peers === 1 ? "" : "s"}`,
        ports: "All ports",
      };
    }),
    offer: {
      title: "Krynodes can keep these rules for your servers",
      note: "Rules for your laptop, phone and other people stay yours, in Tailscale's admin console.",
    },
  };
}

function listeningOn(server: TailnetServer, listeners: Listening[] = []) {
  const own = server.report?.addresses ?? [];
  const found = new Map<number, { protocols: Set<string>; process: string }>();
  for (const item of listeners) {
    if (item.process === "tailscaled") continue;
    if (!["0.0.0.0", "::", "*"].includes(item.address)) {
      if (!own.includes(item.address)) continue;
    }
    const entry = found.get(item.port) ?? {
      protocols: new Set<string>(),
      process: item.process,
    };
    entry.protocols.add(item.protocol);
    found.set(item.port, entry);
  }
  return [...found]
    .sort(([a], [b]) => a - b)
    .map(([port, { protocols, process }]) => ({
      port:
        protocols.size === 2 ? String(port) : `${port}/${[...protocols][0]}`,
      process,
    }));
}

const listening = (server: TailnetServer, listeners: Listening[] = []) =>
  listeningOn(server, listeners).map((entry) => entry.port);

const allowedAlready = (rules: TailnetRule[], from: string, to: string) =>
  rules.flatMap((rule) =>
    "ports" in rule &&
    rule.from === from &&
    (rule.to === to || rule.to === "servers")
      ? rule.ports
      : [],
  );

export function proposals(
  servers: TailnetServer[],
  listeners: Record<string, Listening[]>,
  inUse: Record<string, Seen[]>,
): Proposal[] {
  const on = servers.filter((server) => server.report);
  const ports = new Map(
    on.map((server) => [
      server.nodeId,
      listening(server, listeners[server.nodeId]),
    ]),
  );
  const everywhere =
    on.length > 1
      ? [...ports.values()].reduce((a, b) =>
          a.filter((port) => b.includes(port)),
        )
      : [];
  const used = (server: TailnetServer, port: string) =>
    (inUse[server.nodeId] ?? []).some(
      (seen) => !serverAt(servers, seen.from) && covers(port, seen.port),
    );
  const rows: Proposal[] = [];
  const push = (
    id: string,
    from: string,
    to: string,
    rule: PortRule,
    ticked: boolean,
  ) =>
    rows.push({
      id,
      from,
      to,
      ports: rule.ports.join(" · "),
      ticked,
      locked: false,
      inUse: ticked,
      rule,
    });
  const offer = (
    to: string,
    name: string,
    list: string[],
    isUsed: (port: string) => boolean,
  ) => {
    const yes = list.filter(isUsed);
    if (yes.length > 0) {
      push(
        `${to}:in`,
        "Your devices",
        name,
        { from: "devices", to, ports: yes },
        true,
      );
    }
    for (const port of list.filter((item) => !isUsed(item))) {
      push(
        `${to}:${port}`,
        "Your devices",
        name,
        { from: "devices", to, ports: [port] },
        false,
      );
    }
  };
  offer("servers", "All servers", everywhere, (port) =>
    on.some((server) => used(server, port)),
  );
  for (const server of on) {
    offer(
      server.nodeId,
      server.name,
      ports.get(server.nodeId)!.filter((port) => !everywhere.includes(port)),
      (port) => used(server, port),
    );
  }
  for (const server of on) {
    const by = new Map<string, string[]>();
    for (const seen of inUse[server.nodeId] ?? []) {
      const source = serverAt(servers, seen.from);
      if (!source || source.nodeId === server.nodeId) continue;
      const list = by.get(source.nodeId) ?? [];
      if (!list.includes(seen.port))
        by.set(source.nodeId, [...list, seen.port]);
    }
    for (const [from, list] of by) {
      push(
        `${from}>${server.nodeId}`,
        nameOf(servers, from),
        server.name,
        { from, to: server.nodeId, ports: list },
        true,
      );
    }
  }
  rows.push({
    id: "back",
    from: "Your servers",
    to: "your devices",
    ports: BACK.ports,
    ticked: false,
    locked: true,
    inUse: false,
    rule: null,
  });
  return rows;
}

export const startRules = (
  open: boolean,
  rows: Proposal[],
  ticked: string[],
): TailnetRule[] => [
  ...(open ? [{ from: "devices", to: "rest" } as const] : []),
  ...rows.flatMap((row) =>
    row.rule && ticked.includes(row.id) ? [row.rule] : [],
  ),
];

export function ruleForm(input: {
  connected: TailnetConnected;
  index: number | null;
  servers: TailnetServer[];
  listeners: Record<string, Listening[]>;
  from: string;
  to: string;
  ticked: string[];
  other: string;
}) {
  const on = input.servers.filter((server) => server.report);
  const others = input.connected.rules.filter((_, at) => at !== input.index);
  const allowed = allowedAlready(others, input.from, input.to);
  const lists = on
    .filter((server) => input.to === "servers" || server.nodeId === input.to)
    .map((server) => listeningOn(server, input.listeners[server.nodeId]));
  const heard =
    lists.length === 0
      ? []
      : lists.reduce((a, b) =>
          a.filter((entry) => b.some((each) => each.port === entry.port)),
        );
  const options: { port: string; process: string | null }[] = [
    ...heard.filter((entry) => !allowed.includes(entry.port)),
    ...input.ticked
      .filter((port) => !heard.some((entry) => entry.port === port))
      .map((port) => ({ port, process: null })),
  ];
  const extra = input.other.trim();
  const readable = extra === "" || portSchema.safeParse(extra).success;
  const rule: PortRule = {
    from: input.from as PortRule["from"],
    to: input.to as PortRule["to"],
    ports: [
      ...new Set([...input.ticked, ...(extra && readable ? [extra] : [])]),
    ],
  };
  const problem = !readable
    ? "Other Port takes one port or a range, like 9100/tcp or 6000-6010."
    : input.from === input.to
      ? "A server always reaches itself. Pick another one."
      : null;
  return {
    options,
    allowed,
    rule,
    problem,
    readable,
    ready: problem === null && rule.ports.length > 0,
  };
}

export function losesAccess(
  _servers: TailnetServer[],
  rows: Proposal[],
  ticked: string[],
): string[] {
  const kept = (row: Proposal) => ticked.includes(row.id);
  const except = rows
    .filter((row) => row.rule && row.rule.from !== "devices" && kept(row))
    .map((row) => `${row.from} → ${row.to} ${row.ports}`);
  const lost = rows
    .filter((row) => row.rule?.from === "devices" && !kept(row))
    .map(
      (row) =>
        `${row.to === "All servers" ? "all servers" : row.to} ${row.ports}`,
    );
  return [
    "Every server → your devices",
    `Servers → each other${except.length > 0 ? `, except ${except.join(", ")}` : ""}`,
    `Your devices → ${lost.length > 0 ? `${lost.join(", ")}, and every other port` : "every other port"}`,
  ];
}

function who(src: string[], servers: TailnetServer[]) {
  return [
    ...new Set(
      src.map((item) =>
        item === "autogroup:member"
          ? "Your devices"
          : item === "*"
            ? "Everyone"
            : (serverAt(servers, item)?.name ?? item),
      ),
    ),
  ].join(", ");
}

function where(dst: string[], servers: TailnetServer[]) {
  const on = servers.filter((server) => server.report);
  const all =
    on.length > 1 &&
    dst.every((item) => serverAt(on, item)) &&
    on.every((server) =>
      server.report!.addresses.some((address) => dst.includes(address)),
    );
  if (all) return "All servers";
  return [
    ...new Set(dst.map((item) => serverAt(servers, item)?.name ?? item)),
  ].join(", ");
}

function ipPorts(ip: string[]) {
  if (ip.includes("*")) return "every port";
  const found = new Map<string, Set<string>>();
  for (const item of ip) {
    const [protocol, port] = item.includes(":")
      ? item.split(":", 2)
      : ["", item];
    found.set(port!, (found.get(port!) ?? new Set()).add(protocol!));
  }
  return [...found]
    .map(([port, protocols]) =>
      protocols.has("") || (protocols.has("tcp") && protocols.has("udp"))
        ? port
        : `${port}/${[...protocols].join("+")}`,
    )
    .join(" · ");
}

const strings = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((item) => typeof item === "string");

function grant(line: string, servers: TailnetServer[]) {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return null;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const { src, dst, ip, ...rest } = value as Record<string, unknown>;
  if (Object.keys(rest).length > 0 || !strings(src) || !strings(dst)) {
    return null;
  }
  if (!strings(ip)) return null;
  return {
    from: who(src, servers),
    to: where(dst, servers),
    ports: ipPorts(ip),
  };
}

function parts(rule: TailnetRule | string, servers: TailnetServer[]) {
  if (typeof rule === "string") return grant(rule, servers);
  if ("raw" in rule) return grant(rule.raw, servers);
  return {
    from: sourceText(servers, rule.from),
    to: targetText(servers, rule.to),
    ports: "ports" in rule ? portsText(rule.ports) : "",
  };
}

export function ruleText(
  rule: TailnetRule | string,
  servers: TailnetServer[],
): string {
  const found = parts(rule, servers);
  if (!found)
    return typeof rule === "string" ? rule : "raw" in rule ? rule.raw : "";
  return found.ports
    ? `${found.from} → ${found.to} · ${found.ports}`
    : `${found.from} → ${found.to}`;
}

export function ruleRows(
  connected: TailnetConnected,
  servers: TailnetServer[],
) {
  return [
    ...connected.rules.flatMap((rule, index) => {
      if (isRest(rule)) return [];
      const found = parts(rule, servers);
      return [
        {
          index,
          route: found
            ? `${found.from} → ${found.to}`
            : "raw" in rule
              ? rule.raw
              : "--",
          ports: found?.ports ?? "",
          locked: false,
          editable: "ports" in rule,
        },
      ];
    }),
    {
      index: null,
      route: BACK.route,
      ports: BACK.ports,
      locked: true,
      editable: false,
    },
  ];
}

function sources(
  server: TailnetServer,
  connected: TailnetConnected,
  servers: TailnetServer[],
) {
  const members = connected.members;
  return (server.report?.reach ?? []).map((entry) => {
    const devices =
      members.length > 0 &&
      members.every((member) => entry.from.includes(member));
    const peers = entry.from.map((address) => serverAt(servers, address));
    return {
      from: entry.from,
      source: devices
        ? "Your devices"
        : entry.from.includes("*")
          ? "Everyone"
          : [
              ...new Set(
                entry.from.map(
                  (address, index) =>
                    peers[index]?.name ??
                    server.report?.names?.[address] ??
                    address,
                ),
              ),
            ].join(", "),
      ports: portsText(entry.ports),
      outside: !devices && !(entry.from.length > 0 && peers.every(Boolean)),
    };
  });
}

export function outsideRows(
  connected: TailnetConnected,
  servers: TailnetServer[],
) {
  return servers.flatMap((server) =>
    sources(server, connected, servers)
      .filter((entry) => entry.outside)
      .map((entry) => ({
        id: `${server.nodeId}:${entry.from.join(",")}`,
        route: `${entry.source} → ${server.name}`,
        ports: entry.ports,
      })),
  );
}

export function serverLines(
  server: TailnetServer,
  connected: TailnetConnected | null,
  servers: TailnetServer[],
) {
  return {
    tag: server.report?.tags?.includes(TAILSCALE.tag)
      ? `${TAILSCALE.tag} · key never expires`
      : null,
    sources: connected
      ? sources(server, connected, servers).map(
          ({ source, ports, outside }) => ({ source, ports, outside }),
        )
      : [],
  };
}

export function applied(
  server: TailnetServer,
  connected: TailnetConnected,
  servers: TailnetServer[],
): boolean | null {
  const reach = server.report?.reach;
  if (!reach) return null;
  const allows = (address: string, port: string) =>
    pieces(port).every((piece) =>
      reach.some(
        (entry) =>
          (entry.from.includes(address) || entry.from.includes("*")) &&
          entry.ports.some((allowed) => covers(allowed, piece)),
      ),
    );
  const groups = (from: string): string[][] =>
    from === "devices"
      ? connected.members.map((member) => [member])
      : from === "servers"
        ? servers
            .filter((other) => other.nodeId !== server.nodeId && other.report)
            .map((other) => other.report!.addresses)
        : [
            servers.find((other) => other.nodeId === from)?.report?.addresses ??
              [],
          ];
  const kept = connected.rules.every((rule) => {
    if (!("ports" in rule)) return true;
    if (rule.to !== "servers" && rule.to !== server.nodeId) return true;
    return groups(rule.from).every(
      (addresses) =>
        addresses.length === 0 ||
        addresses.some((address) =>
          rule.ports.every((port) => allows(address, port)),
        ),
    );
  });
  const open = reach.some(
    (entry) => entry.from.includes("*") && entry.ports.includes("*"),
  );
  return kept && !(connected.rules.some(isRest) && open);
}

export function notApplied(
  connected: TailnetConnected,
  servers: TailnetServer[],
  now: number,
) {
  if (!connected.savedAt) return [];
  const minutes = Math.floor(
    (now - parseTimestamp(connected.savedAt)) / 60_000,
  );
  if (minutes < TAILSCALE.appliedMinutes) return [];
  return servers
    .filter((server) => applied(server, connected, servers) === false)
    .map((server) => ({
      nodeId: server.nodeId,
      title: "Tailscale Rules not applied yet",
      text: `${server.name}'s Tailscale has not taken the rules saved ${minutes} minutes ago. Is tailscaled running?`,
    }));
}

export function alarmRows(alarms: TailnetAlarm[], servers: TailnetServer[]) {
  return alarms.map((alarm) =>
    alarm.kind === "device"
      ? {
          id: alarm.id,
          title: alarm.device.name.split(".")[0] || "--",
          detail: alarm.device.name,
          tag: alarm.device.tag,
          text: `Joined at ${clockTime(alarm.at)} with your servers' tag, but Krynodes never signed it in. Your rules give it nothing. Enroll it, or remove it in Tailscale's admin console.`,
          lines: [] as string[],
          link: TAILSCALE_CONSOLE,
        }
      : {
          id: alarm.id,
          title: `Your policy was changed with Krynodes' credential at ${clockTime(alarm.at)}, without your fingerprint`,
          detail: null,
          tag: null,
          text: "Someone else has the credential. Delete it in Tailscale's admin console, then connect a new one. Krynodes cannot undo the change on its own.",
          lines: alarm.change.lines.map((line) =>
            /^[+-] /u.test(line)
              ? `${line.slice(0, 2)}${ruleText(line.slice(2), servers)}`
              : line,
          ),
          link: TAILSCALE_CONSOLE,
        },
  );
}

export const addRuleEffect = (rule: PortRule, servers: TailnetServer[]) =>
  `${sourceText(servers, rule.from)} can now reach ${reachText(servers, rule.to)} on ${portsList(rule.ports)}.`;

export function removeText(
  rule: PortRule,
  servers: TailnetServer[],
  network: string[],
) {
  const from = sourceText(servers, rule.from);
  const to = reachText(servers, rule.to);
  const ports = portsList(rule.ports);
  const single =
    rule.from !== "devices" && rule.from !== "servers" && rule.to !== "servers";
  const away = single
    ? [rule.from, rule.to].find((id) => !network.includes(id))
    : undefined;
  const dns = rule.ports.some((port) => span(port)?.first === 53);
  const after =
    away === undefined
      ? ""
      : ` ${nameOf(servers, away)} is not on your private network, so ${away === rule.from ? "its" : `${from}'s`} ${dns ? `DNS lookups to ${to}` : `connections to ${to} on ${ports}`} stop.`;
  return {
    title: `Remove ${from} → ${targetText(servers, rule.to)}?`,
    body: `${from} can no longer reach ${to} on ${ports} over Tailscale.${after}`,
  };
}

export const changedLines = (
  connected: TailnetConnected,
  now: string[],
  servers: TailnetServer[],
) => [
  ...connected.lines
    .filter((line) => !now.includes(line))
    .map((line) => `- ${ruleText(line, servers)}`),
  ...now
    .filter((line) => !connected.lines.includes(line))
    .map((line) => `+ ${ruleText(line, servers)}`),
];

const oneGrant = (line: string) => {
  try {
    const value: unknown = JSON.parse(line);
    return !!value && typeof value === "object" && !Array.isArray(value);
  } catch {
    return false;
  }
};

export const brokenLines = (connected: TailnetConnected, now: string[]) =>
  now.filter((line) => !connected.lines.includes(line) && !oneGrant(line));

const same = (a: TailnetRule, b: TailnetRule) =>
  JSON.stringify(a) === JSON.stringify(b);

export function keepChange(
  connected: TailnetConnected,
  now: string[],
  wanted: TailnetRule[],
): TailnetRule[] {
  const kept = now.map((line): TailnetRule => {
    const index = connected.lines.indexOf(line);
    return connected.rules[index] ?? { raw: line };
  });
  const dropped = connected.rules.filter(
    (rule) => !wanted.some((other) => same(rule, other)),
  );
  const added = wanted.filter(
    (rule) => !connected.rules.some((other) => same(rule, other)),
  );
  return [
    ...kept.filter((rule) => !dropped.some((other) => same(rule, other))),
    ...added,
  ];
}

export function joinedLines(
  report: TailscaleReport,
  nodeName: string,
  connected: TailnetConnected,
  servers: TailnetServer[],
): { title: string; intro: string; lines: Line[] } {
  const nodeId = servers.find(
    (server) =>
      server.report === report ||
      (!!report.id && server.report?.id === report.id),
  )?.nodeId;
  const said = connected.rules
    .filter(
      (rule): rule is PortRule =>
        "ports" in rule && (rule.to === "servers" || rule.to === nodeId),
    )
    .map(
      (rule) =>
        `${rule.from === "devices" ? "your devices" : reachText(servers, rule.from)} on ${portsText(rule.ports)}`,
    );
  return {
    title: `${nodeName} is on your tailnet`,
    intro:
      "It joined with a one-time key tagged kry. There was nothing to approve in Tailscale.",
    lines: [
      {
        mark: "✓",
        title: `${report.addresses[0] ?? "--"} · ${report.name ?? "--"}`,
        detail: [] as string[],
      },
      said.length > 0
        ? {
            mark: "✓",
            title: `Your rules apply to it: ${said.join(", ")}`,
            detail: [] as string[],
          }
        : { mark: "·", title: "Your rules give it nothing yet", detail: [] },
      {
        mark: "·",
        title: "Key never expires · keeps its own DNS · Tailscale SSH off",
        detail: [],
      },
    ],
  };
}

export async function connectSteps(input: {
  secret: string;
  set: string;
  tailnet: string;
  clientId: string;
  webhookSecret: string;
  holders: Holder[];
}) {
  if (input.holders.length < 2) {
    return {
      ok: false as const,
      reason: `Connect needs two servers with agent ${MIN_AGENT_VERSION} that this device reaches; ${input.holders.length} is.`,
    };
  }
  return {
    ok: true as const,
    steps: await splitSteps(
      input.secret,
      input.holders,
      input.set,
      null,
      "tailscale",
    ),
    tailscale: {
      tailnet: input.tailnet,
      clientId: input.clientId,
      webhookSecret: input.webhookSecret,
    },
  };
}

interface Use {
  assembler: string;
  releaser: string;
}

const opened = (
  use: Use,
  keyOf: Record<string, string>,
  connected: TailnetConnected,
) =>
  release(
    use.releaser,
    use.assembler,
    keyOf[use.assembler] ?? "",
    connected.setId ?? "",
    "tailscale",
  );

const job = (
  use: Use,
  connected: TailnetConnected,
  action: ActionVerb,
  args: Record<string, string> = {},
): OperationTarget => ({
  nodeId: use.assembler,
  kind: "vault",
  name: "tailscale",
  action,
  args: { client: connected.clientId, ...args },
  attachFrom: 0,
});

export const readSteps = (
  use: Use,
  keyOf: Record<string, string>,
  connected: TailnetConnected,
): OperationTarget[] => [
  opened(use, keyOf, connected),
  job(use, connected, "policy"),
];

export function saveSteps(input: {
  use: Use;
  keyOf: Record<string, string>;
  connected: TailnetConnected;
  rules: TailnetRule[];
  servers: TailnetServer[];
  expected: string;
  tag: boolean;
  label: string;
}): OperationTarget[] {
  const reported = input.servers.filter((server) => server.report);
  const untagged = input.tag
    ? reported
        .filter((server) => !server.report!.tags?.includes(TAILSCALE.tag))
        .flatMap((server) => (server.report!.id ? [server.report!.id] : []))
    : [];
  return [
    opened(input.use, input.keyOf, input.connected),
    job(input.use, input.connected, "save", {
      rules: JSON.stringify(input.rules),
      servers: JSON.stringify(
        Object.fromEntries(
          reported.map((server) => [server.nodeId, server.report!.addresses]),
        ),
      ),
      expected: input.expected,
      ...(untagged.length > 0 ? { tag: untagged.join(",") } : {}),
      label: input.label,
    }),
  ];
}

export const joinSteps = (
  use: Use,
  keyOf: Record<string, string>,
  connected: TailnetConnected,
  to: string,
): OperationTarget[] => [
  opened(use, keyOf, connected),
  job(use, connected, "key", { to, key: keyOf[to] ?? "" }),
  {
    nodeId: to,
    kind: "host",
    name: "tailscale",
    action: "join",
    attachFrom: 1,
  },
];

export const removeSteps = (
  use: Use,
  keyOf: Record<string, string>,
  connected: TailnetConnected,
  device: string,
  node: string,
): OperationTarget[] => [
  opened(use, keyOf, connected),
  job(use, connected, "remove", { device, node }),
];

export const disconnectSteps = (servers: TailnetServer[]): OperationTarget[] =>
  servers
    .filter((server) => server.vault)
    .map((server) => ({
      nodeId: server.nodeId,
      kind: "vault",
      name: "tailscale",
      action: "forget",
    }));

const VAULT_TEXT: Partial<Record<string, string>> = {
  store: "Connect Tailscale",
  policy: "Read the Tailscale policy file",
  save: "Save Tailscale rules",
  key: "Make a one-time Tailscale key",
  remove: "Remove a server from your tailnet",
  reshare: "Reshare the Tailscale credential",
};

export function tailnetActionText(
  action: Pick<ActionRecord, "kind" | "name" | "action">,
  nodeName?: string,
): string | null {
  if (action.name !== "tailscale") return null;
  if (action.kind === "vault") return VAULT_TEXT[action.action] ?? null;
  if (action.kind !== "host") return null;
  if (action.action === "join") {
    return nodeName
      ? `Sign in ${nodeName} to Tailscale`
      : "Sign in to Tailscale";
  }
  return action.action === "inspect"
    ? "Read what is in use on Tailscale"
    : null;
}
