import {
  dnsName,
  NETWORK,
  networkDocumentSchema,
  networkPreparedSchema,
  type NetworkDocument,
  type NetworkInspect,
  type NetworkLink,
  type NetworkMember,
  type NetworkTest,
  type StackNetwork,
} from "@krynodes/protocol";

import type {
  ActionRecord,
  CheckKind,
  CheckRecord,
  NetworkServer,
  NetworkView,
  NodeRecord,
  ServicesResponse,
  StackEntry,
} from "../types";
import { summarize, usePrivateAddress, usesPrivateIp } from "./compose";
import { agentGap, FIRST_REPORT } from "./devices";
import {
  capitalize,
  clockTime,
  formatBytes,
  formatDuration,
  nodeState,
  parseTimestamp,
} from "./format";
import { b64url, fromB64url } from "./passkeys";
import { seal } from "./seal";

type ServiceNode = ServicesResponse["nodes"][number];
type NetworkPrepared = ReturnType<typeof networkPreparedSchema.parse>;

export type Mark = "✓" | "+" | "✕" | "!" | "−" | "·" | "…" | "–";

export interface Row {
  mark: Mark;
  text: string;
  detail?: string;
  short?: string;
  action?: "again" | "edit";
  nodeId?: string;
}

export type Serve = StackNetwork["serves"][number];

export interface Hosting {
  id: string;
  name: string;
  stacks?: Pick<StackEntry, "project" | "access" | "network">[];
}

export type Presence = Record<
  string,
  { online: boolean; seenAt: number | null }
>;

type Firewall = "ufw" | "firewalld" | null;

export const LEGEND = "✓ already fine · + Krynodes does it · ✕ yours to fix.";

const plural = (count: number, word: string) =>
  `${count} ${word}${count === 1 ? "" : "s"}`;

export const listOf = (names: string[]) =>
  names.length <= 1
    ? (names[0] ?? "")
    : `${names.slice(0, -1).join(", ")} and ${names.at(-1)}`;

const kryName = (name: string) => `${dnsName(name)}.kry`;

const span = (milliseconds: number) =>
  milliseconds < 3_600_000
    ? `${Math.max(1, Math.floor(milliseconds / 60_000))} min`
    : formatDuration(milliseconds);

export function bounds(cidr: string): [number, number] | null {
  const parts = /^(\d+)\.(\d+)\.(\d+)\.(\d+)(?:\/(\d+))?$/u.exec(cidr);
  if (!parts) return null;
  const [a, b, c, d] = parts.slice(1, 5).map(Number) as [
    number,
    number,
    number,
    number,
  ];
  const size = 2 ** (32 - Number(parts[5] ?? 32));
  const start =
    Math.floor((a * 2 ** 24 + b * 65_536 + c * 256 + d) / size) * size;
  return [start, start + size - 1];
}

export const overlaps = (first: string, second: string) => {
  const one = bounds(first);
  const two = bounds(second);
  return one !== null && two !== null && one[0] <= two[1] && two[0] <= one[1];
};

const ipOf = (value: number) =>
  [24, 16, 8, 0].map((shift) => Math.floor(value / 2 ** shift) % 256).join(".");

export function networkOf(cidr: string): string | null {
  const found = bounds(cidr);
  return found && cidr.includes("/")
    ? `${ipOf(found[0])}/${cidr.split("/")[1]}`
    : null;
}

export interface Candidate {
  name: string;
  nat: boolean;
  publicAddress: string | null;
  firewall: Firewall;
  docker: boolean;
  system: string | null;
}

export type Seat = Candidate & { nodeId: string };

export function presenceOf(
  nodes: (Parameters<typeof nodeState>[0] & { id: string })[],
  now: number,
): Presence {
  return Object.fromEntries(
    nodes.map((node) => [
      node.id,
      {
        online: nodeState(node, now) === "online",
        seenAt: node.last_seen_at ? parseTimestamp(node.last_seen_at) : null,
      },
    ]),
  );
}

export function seatOf(
  node: Pick<NodeRecord, "id" | "name" | "addresses">,
  report: Pick<ServiceNode, "docker" | "security"> | undefined,
): Seat {
  const ipv4 = node.addresses?.find((address) => address.family === 4);
  const platform = report?.security?.platform;
  return {
    nodeId: node.id,
    name: node.name,
    publicAddress: ipv4?.address ?? null,
    nat: !ipv4 || ipv4.router,
    firewall: report?.security?.recipes.includes("firewall")
      ? platform?.family === "rhel"
        ? "firewalld"
        : "ufw"
      : null,
    docker: report?.docker === "ready" || report?.docker === "no-compose",
    system: platform?.name.split(" ")[0] || null,
  };
}

type Listener = Pick<Seat, "nodeId" | "name" | "publicAddress" | "nat"> & {
  port: number | null;
};

const listensAt = (seat: Listener) =>
  !seat.nat && seat.publicAddress && seat.port !== null
    ? `${seat.publicAddress}:${seat.port}`
    : null;

export function probePlan(seats: Listener[]) {
  return seats.flatMap((seat) => {
    const peers = seats
      .filter((other) => other.nodeId !== seat.nodeId)
      .map(listensAt)
      .filter((at) => at !== null);
    return seat.port === null || peers.length === 0
      ? []
      : [
          {
            nodeId: seat.nodeId,
            args: { port: String(seat.port), peers: peers.join(" ") },
          },
        ];
  });
}

export function probeOf(
  target: Listener,
  seats: Listener[],
  plan: ReturnType<typeof probePlan>,
  answers: Record<string, { arrived: string[] } | undefined>,
): { from: string[]; arrived: boolean } | null {
  const at = listensAt(target);
  const answer = answers[target.nodeId];
  if (at === null || !answer) return null;
  const senders = seats.filter((seat) =>
    plan.some(
      (entry) =>
        entry.nodeId === seat.nodeId &&
        entry.nodeId !== target.nodeId &&
        entry.args.peers.split(" ").includes(at),
    ),
  );
  if (senders.length === 0) return null;
  const through = senders.filter(
    (seat) =>
      seat.publicAddress !== null &&
      answer.arrived.includes(seat.publicAddress),
  );
  return through.length > 0
    ? { from: through.map((seat) => seat.name), arrived: true }
    : { from: senders.map((seat) => seat.name), arrived: false };
}

export function portLine(
  port: number,
  seats: {
    name: string;
    port: number | null;
    others: NetworkInspect["others"];
  }[],
): { port: string; note: string | null } {
  const notes = seats
    .filter((seat) => seat.port !== null && seat.port !== port)
    .map((seat) => {
      const holder = seat.others.find((other) => other.port === port);
      return `${seat.name} uses ${seat.port}${holder ? `, its ${holder.name} holds ${port}` : ""}`;
    });
  return {
    port: `${port}/udp`,
    note: notes.length > 0 ? notes.join(" · ") : null,
  };
}

export function preparedOf(
  action: Pick<ActionRecord, "status" | "output">,
): NetworkPrepared | null {
  if (action.status !== "done" || !action.output) return null;
  try {
    const parsed = networkPreparedSchema.safeParse(JSON.parse(action.output));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

export const joinerOf = (
  seat: Pick<Seat, "nodeId" | "name" | "publicAddress" | "nat">,
  prepared: Pick<NetworkPrepared, "key" | "signer" | "port">,
  address: string,
): Joiner => ({
  node: seat.nodeId,
  name: seat.name,
  address,
  key: prepared.key,
  signer: prepared.signer,
  port: prepared.port,
  endpoint:
    seat.nat || !seat.publicAddress
      ? null
      : `${seat.publicAddress}:${prepared.port}`,
  nat: seat.nat,
});

export function checkRows(
  inspect: NetworkInspect,
  server: Candidate,
  plan: { range: string; mtu: number },
  probe: { from: string[]; arrived: boolean } | null,
): Row[] {
  const rows: Row[] = [
    inspect.kernel.ok
      ? {
          mark: "✓",
          text: inspect.kernel.version
            ? `Kernel has WireGuard · Linux ${inspect.kernel.version}`
            : "Kernel has WireGuard",
        }
      : {
          mark: "✕",
          text: "Kernel has no WireGuard",
          detail:
            inspect.kernel.reason ??
            "A WireGuard that runs outside the kernel is not supported.",
        },
    inspect.tools
      ? { mark: "✓", text: "WireGuard tools are installed" }
      : {
          mark: "+",
          text: `WireGuard tools are installed · from ${server.system ? `${server.system}'s` : "the system's"} own repository`,
        },
  ];
  const clash = inspect.used.find((used) => overlaps(used, plan.range));
  rows.push(
    clash
      ? {
          mark: "✕",
          text: `${plan.range} is used here`,
          detail: `${clash} is in use on ${server.name}.`,
        }
      : {
          mark: "✓",
          text: `${plan.range} is not used here · interfaces, Docker networks and Tailscale checked`,
        },
    server.nat
      ? {
          mark: "✓",
          text: "Behind NAT",
          detail:
            "It dials out to the others and keeps the link open. Two servers both behind NAT cannot reach each other.",
        }
      : {
          mark: "✓",
          text: `Public address ${server.publicAddress ?? "--"}, not behind NAT`,
        },
  );
  const port = inspect.port;
  if (port === null) {
    rows.push({
      mark: "✕",
      text: `No UDP port between ${NETWORK.port} and ${NETWORK.lastPort} is free`,
    });
  } else if (!server.nat && probe) {
    rows.push(
      probe.arrived
        ? {
            mark: "✓",
            text: `UDP ${port} reaches ${server.name} · from ${listOf(probe.from)}`,
          }
        : {
            mark: "✕",
            text: `UDP ${port} does not reach ${server.name}`,
            detail: `${listOf(probe.from)} sent a test and nothing arrived, though ${server.firewall ? `${server.firewall} on ${server.name} would let it in` : `nothing on ${server.name} would stop it`}. Something before the server drops it, usually the provider's firewall. Open UDP ${port} there.`,
            action: "again",
          },
    );
  }
  if (server.firewall && port !== null) {
    rows.push({
      mark: "+",
      text: `${server.firewall} gets two rules · allow ${port}/udp · allow in on kry0`,
    });
  }
  if (server.docker) {
    rows.push({ mark: "+", text: "Docker waits for the network at boot" });
  }
  rows.push({
    mark: "✓",
    text: `MTU ${inspect.mtu ?? "--"} · the network uses ${plan.mtu}`,
  });
  for (const other of inspect.others) {
    const range = other.address ? networkOf(other.address) : null;
    rows.push({
      mark: "!",
      text: [
        other.name,
        other.address ? `at ${other.address}` : null,
        other.port ? `on port ${other.port}` : null,
      ]
        .filter(Boolean)
        .join(" "),
      detail: `Krynodes leaves it alone. The network uses kry0 on port ${port ?? "--"}${range ? `, and stays out of ${range}` : ""}.`,
    });
  }
  return rows;
}

export function candidateState(
  agentVersion: string | null,
  rows: Row[] | null,
): { text: string; details: boolean; joinable: boolean } {
  const gap = agentGap(agentVersion);
  if (gap !== null) {
    return {
      text: gap === FIRST_REPORT ? gap : `${gap} or newer`,
      details: false,
      joinable: false,
    };
  }
  if (!rows) return { text: "Checking", details: false, joinable: false };
  const fixes = rows.filter((row) => row.mark === "✕").length;
  const notes = rows.filter((row) => row.mark === "!").length;
  if (fixes > 0) {
    return { text: `${fixes} to fix`, details: true, joinable: true };
  }
  if (notes > 0) {
    return {
      text: `Ready · ${plural(notes, "note")}`,
      details: true,
      joinable: true,
    };
  }
  return { text: "Ready", details: false, joinable: true };
}

export function pickRange(
  used: string[][],
  privateRanges: string[],
): string | null {
  const taken = [...used.flat(), ...privateRanges];
  for (let third = 0; third < 256; third += 1) {
    const range = `10.88.${third}.0/24`;
    if (!taken.some((entry) => overlaps(entry, range))) return range;
  }
  return null;
}

export const pickMtu = (mtus: (number | null)[]) =>
  Math.min(
    1420,
    Math.max(
      1280,
      Math.min(1500, ...mtus.map((mtu) => mtu ?? 1500)) - NETWORK.mtuMargin,
    ),
  );

export interface Joining {
  name: string;
  address: string;
  port: number;
  tools: boolean;
  status: "working" | "up" | "waiting" | "failed";
  seconds: number | null;
  waiting?: string;
  failure?: string;
}

export function progressRows(servers: Joining[]) {
  return servers.map((server) => {
    const port = server.port === NETWORK.port ? "" : ` on port ${server.port}`;
    const time = server.seconds === null ? null : `${server.seconds}s`;
    const base = { name: server.name, time, again: false };
    switch (server.status) {
      case "up":
        return {
          ...base,
          mark: "✓" as Mark,
          text: capitalize(
            [
              server.tools ? "tools installed" : null,
              "key made",
              `up as ${server.address}${port}`,
            ]
              .filter(Boolean)
              .join(" · "),
          ),
        };
      case "waiting":
        return {
          ...base,
          mark: "…" as Mark,
          text: `Up as ${server.address}${port} · waiting for ${server.waiting ?? "its first answer"}`,
          time: null,
          again: true,
        };
      case "failed":
        return { ...base, mark: "✕" as Mark, text: server.failure ?? "Failed" };
      default:
        return {
          ...base,
          mark: "…" as Mark,
          text: "Getting ready",
          time: null,
        };
    }
  });
}

export function progressLinks(
  up: { a: string; b: string; ms: number | null }[],
  total: number,
): string {
  const fastest = up
    .filter((pair) => pair.ms !== null)
    .sort((first, second) => first.ms! - second.ms!)[0];
  return `Links ${up.length} of ${total} up${fastest ? ` · ${fastest.a} ↔ ${fastest.b} answered in ${fastest.ms} ms` : ""}`;
}

export const inside = (view: NetworkView) =>
  view.members.filter(
    (member) => member.state === "in" && member.address !== null,
  );

const isOnline = (presence: Presence, id: string) =>
  presence[id]?.online === true;

function liveLink(
  view: NetworkView,
  from: NetworkServer,
  to: NetworkServer,
): { link: NetworkLink; at: number } | null {
  const entry = view.live[from.nodeId];
  const link = entry?.links.find(
    (item) => item.key === to.key || item.key === to.announced?.key,
  );
  return entry && link ? { link, at: entry.at } : null;
}

export type PairState = "up" | "down" | "offline" | "nat" | "unknown";

function pairOf(
  view: NetworkView,
  presence: Presence,
  a: NetworkServer,
  b: NetworkServer,
  now: number,
): { state: PairState; since: number | null } {
  if (a.nat && b.nat) return { state: "nat", since: null };
  if (!isOnline(presence, a.nodeId) || !isOnline(presence, b.nodeId)) {
    return { state: "offline", since: null };
  }
  const row = view.links.find(
    (link) =>
      (link.a === a.nodeId && link.b === b.nodeId) ||
      (link.a === b.nodeId && link.b === a.nodeId),
  );
  const flipped = row && !row.answering ? parseTimestamp(row.since) : null;
  const seen = [liveLink(view, a, b), liveLink(view, b, a)]
    .filter((entry) => entry !== null)
    .sort((first, second) => second.at - first.at)[0];
  if (seen) {
    const handshake = seen.link.handshake;
    if (handshake !== null && now / 1000 - handshake < NETWORK.answerSeconds) {
      return { state: "up", since: null };
    }
    return {
      state: "down",
      since:
        flipped ??
        (handshake === null
          ? null
          : (handshake + NETWORK.answerSeconds) * 1000),
    };
  }
  if (row) return { state: row.answering ? "up" : "down", since: flipped };
  return { state: "unknown", since: null };
}

const trusted = (view: NetworkView) =>
  inside(view).filter((member) => !view.quarantined.includes(member.nodeId));

const pairsWith = (
  view: NetworkView,
  presence: Presence,
  server: NetworkServer,
  now: number,
) =>
  view.quarantined.includes(server.nodeId)
    ? []
    : trusted(view)
        .filter((peer) => peer.nodeId !== server.nodeId)
        .map((peer) => ({
          peer,
          ...pairOf(view, presence, server, peer, now),
        }));

export function linkProgress(
  view: NetworkView,
  presence: Presence,
  ids: string[],
  now: number,
): string {
  const members = inside(view).filter((member) => ids.includes(member.nodeId));
  const pairs = members.flatMap((a, index) =>
    members
      .slice(index + 1)
      .map((b) => ({ a, b, state: pairOf(view, presence, a, b, now).state })),
  );
  const up = pairs
    .filter((pair) => pair.state === "up")
    .map(({ a, b }) => {
      const seen = liveLink(view, a, b) ?? liveLink(view, b, a);
      const [from, to] = liveLink(view, a, b) ? [a, b] : [b, a];
      return { a: from.name, b: to.name, ms: seen?.link.ms ?? null };
    });
  return progressLinks(up, pairs.filter((pair) => pair.state !== "nat").length);
}

export function problemRows(
  view: NetworkView,
  presence: Presence,
  now: number,
) {
  const members = trusted(view);
  const reaches = (server: NetworkServer, other: NetworkServer) => {
    const counted = pairsWith(view, presence, server, now).filter(
      (pair) =>
        pair.peer.nodeId !== other.nodeId &&
        (pair.state === "up" || pair.state === "down"),
    );
    return counted.length === 0 || counted.some((pair) => pair.state === "up");
  };
  return members.flatMap((a, index) =>
    members.slice(index + 1).flatMap((b) => {
      const pair = pairOf(view, presence, a, b, now);
      if (pair.state !== "down") return [];
      const alone = [a, b].find(
        (server) => !reaches(server, server === a ? b : a),
      );
      return [
        {
          a: a.nodeId,
          b: b.nodeId,
          pair: `${a.name} ↔ ${b.name}`,
          text:
            pair.since === null
              ? "No answer"
              : `No answer for ${span(now - pair.since)}`,
          detail: alone
            ? `${alone.name} reaches none of the others either, so the problem is likely on ${alone.name}.`
            : "Both are online and reach the others, so the path between them is the problem.",
        },
      ];
    }),
  );
}

export function wrongPortRows(view: NetworkView) {
  const names = new Map(
    view.members.map((member) => [member.address, member.name]),
  );
  const named = (address: string | null) =>
    (address !== null && names.get(address)) || (address ?? "--");
  return view.wrongPorts.map((entry) => {
    const knocker = named(entry.from);
    const [address = null, port = "--"] = entry.target?.split(/:(.*)/su) ?? [];
    const server = named(address);
    return {
      nodeId: entry.nodeId,
      text: `${knocker} keeps knocking on ${server}:${port.replace(/\/tcp$/u, "")}, and nothing serves it there`,
      detail: `A setting on ${knocker} points at a port ${server} does not give it. Nothing was cut off.`,
    };
  });
}

export const navNetworkCount = (
  view: NetworkView,
  presence: Presence,
  now: number,
) => problemRows(view, presence, now).length;

export function serverRow(
  server: NetworkServer,
  view: NetworkView,
  presence: Presence,
  now: number,
) {
  const online = isOnline(presence, server.nodeId);
  const seenAt = presence[server.nodeId]?.seenAt ?? null;
  const counted = pairsWith(view, presence, server, now).filter(
    (pair) => pair.state === "up" || pair.state === "down",
  );
  const up = counted.filter((pair) => pair.state === "up").length;
  const cut = view.quarantined.includes(server.nodeId);
  return {
    name: server.name,
    address: `${server.address ?? "--"} · ${kryName(server.name)}`,
    endpoint: server.nat ? "Behind NAT" : (server.endpoint ?? "--"),
    links: cut ? "Cut off" : online ? `Links ${up} of ${counted.length}` : "--",
    short: !cut && online && up < counted.length,
    offline: online
      ? null
      : `Offline${seenAt === null ? "" : ` ${formatDuration(now - seenAt)}`}. It picks up the last change when it is back; nothing to approve again.`,
  };
}

export function peerRows(
  server: NetworkServer,
  view: NetworkView,
  presence: Presence,
  now: number,
): { nodeId: string; text: string; test: boolean; state: PairState }[] {
  const online = isOnline(presence, server.nodeId);
  return pairsWith(view, presence, server, now).map(
    ({ peer, state, since }) => {
      const row = (text: string, test = false) => ({
        nodeId: peer.nodeId,
        text: `${peer.name} · ${text}`,
        test,
        state,
      });
      if (state === "nat") {
        return row("Both are behind NAT and cannot reach each other");
      }
      if (!online || state === "unknown") return row("--");
      const mine = liveLink(view, server, peer)?.link;
      const theirs = liveLink(view, peer, server)?.link;
      if (state === "offline") {
        const last = mine?.handshake ?? theirs?.handshake ?? null;
        return row(
          last === null
            ? "offline · --"
            : `offline, last answer ${formatDuration(now - last * 1000)} ago · --`,
        );
      }
      if (state === "down") {
        return row(
          since === null ? "no answer" : `no answer for ${span(now - since)}`,
          true,
        );
      }
      const seen =
        mine ?? (theirs ? { ...theirs, rx: theirs.tx, tx: theirs.rx } : null);
      if (!seen || seen.handshake === null) return row("answers · --");
      return row(
        [
          `answered ${formatDuration(now - seen.handshake * 1000)} ago`,
          seen.ms === null ? "--" : `${seen.ms} ms`,
          `↑ ${formatBytes(seen.tx)} ↓ ${formatBytes(seen.rx)}`,
        ].join(" · "),
      );
    },
  );
}

export function networkFacts(
  view: NetworkView,
  presence: Presence,
): [string, string][] {
  if (!view.network) return [];
  const members = inside(view);
  return [
    ["Addresses", view.network.range],
    ["Port", `${view.network.port}/udp`],
    ["MTU", String(view.network.mtu)],
    ["Names", "<server>.kry"],
    [
      "Servers",
      `${members.length} · ${members.filter((member) => isOnline(presence, member.nodeId)).length} online`,
    ],
  ];
}

const nameIn = (
  view: NetworkView,
  id: string,
  names: Record<string, string> = {},
) =>
  view.members.find((member) => member.nodeId === id)?.name ??
  names[id] ??
  "a server";

function pointersAt(view: NetworkView, server: NetworkServer) {
  const targets = new Set([server.address, kryName(server.name)]);
  return view.members.flatMap((member) =>
    member.points
      .filter(
        (point) =>
          targets.has(point.target) ||
          (server.address !== null &&
            point.target.startsWith(`${server.address}:`)),
      )
      .map((point) => ({ nodeId: member.nodeId, ...point })),
  );
}

export function placeText(view: NetworkView, place: string): string {
  const at = place.indexOf(":");
  if (at < 0) return place;
  const member = view.members.find(
    (entry) => entry.address === place.slice(0, at),
  );
  return member ? `${member.name}${place.slice(at)}` : place;
}

const portWord = (port: string) => port.replace(/\/tcp$/u, "");

const PLACE = /^([^\s:/]+):(\d{1,5})\/(tcp|udp)$/u;
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/u;

export function parsePlaces(
  text: string,
  view: NetworkView,
  self: string,
): { places: string[]; problem: string | null } {
  const places: string[] = [];
  const members = inside(view);
  const own = members.find((member) => member.nodeId === self);
  const refuse = (problem: string) => ({ places, problem });
  for (const item of text
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean)) {
    const found = PLACE.exec(item);
    const [, host = "", port = "", protocol = ""] = found ?? [];
    if (!found || Number(port) < 1 || Number(port) > 65535) {
      const [name = item, number = ""] = item.split(/[:/]/u);
      return refuse(
        `${item} is not a place such as ${name}:${/^\d{1,5}$/u.test(number) ? number : "5432"}/tcp.`,
      );
    }
    const numeric = IPV4.test(host);
    const member = numeric
      ? members.find((entry) => entry.address === host)
      : members.find(
          (entry) =>
            dnsName(entry.name) === dnsName(host.replace(/\.kry$/u, "")),
        );
    const address = numeric ? host : (member?.address ?? null);
    if (
      address === null ||
      (!member && !(view.network && overlaps(address, view.network.range)))
    ) {
      return refuse(`${host} is not in the private network.`);
    }
    if (member?.nodeId === self || address === own?.address) {
      return refuse(
        `That is ${own?.name ?? host} itself; use Reach This Server On.`,
      );
    }
    const place = `${address}:${Number(port)}/${protocol}`;
    if (!places.includes(place)) places.push(place);
  }
  return places.length > NETWORK.places
    ? refuse(`A stack may reach at most ${NETWORK.places} places.`)
    : { places, problem: null };
}

export type ServeChoice = "self" | "all" | "chosen";

export interface ServeRow {
  port: string;
  choice: ServeChoice;
  to: string[];
}

export const readServes = (
  serves: Serve[] | undefined,
  ports: string[],
): ServeRow[] =>
  ports.map((port) => {
    const serve = serves?.find((entry) => entry.port === port);
    return {
      port,
      choice: !serve ? "self" : serve.all ? "all" : "chosen",
      to: serve?.to ?? [],
    };
  });

export const servesArg = (rows: ServeRow[]) =>
  rows
    .filter((row) => row.choice !== "self")
    .map(
      (row) => `${row.port}=${row.choice === "all" ? "all" : row.to.join(" ")}`,
    )
    .join(",");

export const servesProblem = (rows: ServeRow[]) =>
  rows.some((row) => row.choice === "chosen" && row.to.length === 0)
    ? "Tick at least one server, or choose This Server Only."
    : null;

export function opensBox(
  text: string,
  member: { name: string; address: string | null } | null,
): {
  lines: string[];
  notes: string[];
  offer: string | null;
  warn: boolean;
} | null {
  const summary = summarize(text);
  if (summary.error) return null;
  const list = (items: string[]) => items.join(", ");
  const risks = [
    summary.folders.length > 0 &&
      `Uses server folders: ${list(summary.folders)}`,
    summary.hostNetwork.length > 0 &&
      `Uses the server's network: ${list(summary.hostNetwork)}`,
    summary.devices.length > 0 && `Uses devices: ${list(summary.devices)}`,
    summary.privileged.length > 0 &&
      `Runs privileged: ${list(summary.privileged)}`,
    summary.builds.length > 0 &&
      `Builds on the server: ${list(summary.builds)}`,
    summary.docker.length > 0 &&
      `Controls Docker, which is root on the server: ${list(summary.docker)}`,
  ].filter((line): line is string => Boolean(line));
  const opened = summary.internet.length > 0;
  const shared = member !== null && summary.private.length > 0;
  const moved = member
    ? summarize(usePrivateAddress(text)).private.filter(
        (port) => !summary.private.includes(port),
      )
    : [];
  return {
    lines: [
      ...(opened
        ? [
            `Opens to the internet${member ? " and every server" : ""}: ${list(summary.internet)}`,
          ]
        : []),
      ...(shared
        ? [
            `Opens to every server on the private network: ${list(summary.private)}`,
          ]
        : []),
      ...(member ? ["Reaches every server on the private network"] : []),
      ...risks,
    ],
    notes: [
      ...(opened
        ? [
            "Docker opens these ports past ufw, so a firewall does not close them.",
          ]
        : []),
      ...(summary.internet.some((port) => port.startsWith("53/"))
        ? [
            "Port 53 open to everyone makes an open resolver that others can abuse. Limit it with AdGuard’s Allowed clients, or use DNS-over-TLS.",
          ]
        : []),
      ...(shared
        ? [
            `Krynodes fills in KRY_PRIVATE_IP with the server's own private address, ${member.address ?? "--"} here.`,
          ]
        : []),
    ],
    offer:
      moved.length > 0
        ? `Only your servers need ${list(moved)}? Open ${moved.length === 1 ? "it" : "them"} on the private address instead.`
        : null,
    warn: opened || risks.length > 0,
  };
}

export const privateIpProblem = (
  text: string,
  nodeName: string,
  member: boolean,
) =>
  !member && usesPrivateIp(text)
    ? `${nodeName} is not in the private network, so KRY_PRIVATE_IP has no value.`
    : null;

export function networkHint(
  stacks: Pick<StackEntry, "project" | "access" | "public">[],
  member: boolean,
): string | null {
  const names = stacks
    .filter((stack) => stack.access === "full" && (stack.public ?? []).length)
    .map((stack) => stack.project);
  if (!member || names.length === 0) return null;
  const one = names.length === 1;
  return `${listOf(names)} ${one ? "is" : "are"} on the private network too. If only your servers need ${one ? "it" : "them"}, use the private address in Edit Compose.`;
}

export const firewallRow = (member: Pick<NetworkServer, "name" | "port">) => ({
  port: `${member.port}/udp`,
  detail: `the private network, while ${member.name} is in it`,
});

function stackLines(
  view: NetworkView,
  servers: Hosting[],
  only?: string,
): Row[] {
  return servers
    .filter((server) => only === undefined || server.id === only)
    .flatMap((server) =>
      (server.stacks ?? []).flatMap((stack): Row[] => {
        const network = stack.network;
        if (!network) return [];
        if (stack.access === "full") {
          return network.private.length > 0
            ? [
                {
                  mark: "✕",
                  text: `${stack.project} on ${server.name} opens ${listOf(network.private.map(portWord))} on KRY_PRIVATE_IP`,
                  detail:
                    "Nobody can reach it, and it fails on its next start until you change it.",
                  short: `${stack.project} on ${server.name} uses KRY_PRIVATE_IP`,
                },
              ]
            : [];
        }
        if (stack.access !== "contained" || network.serves.length === 0) {
          return [];
        }
        const chosen = [
          ...new Set(network.serves.flatMap((serve) => serve.to ?? [])),
        ];
        const who = network.serves.every((serve) => serve.all)
          ? "All Servers"
          : network.serves.every((serve) => !serve.all)
            ? listOf(chosen.map((id) => nameIn(view, id)))
            : "other servers";
        return [
          {
            mark: "✕",
            text: `${stack.project} on ${server.name} serves ${listOf(network.serves.map((serve) => portWord(serve.port)))} to ${who}`,
            detail: "It goes back to This Server Only.",
            short: `${stack.project} goes back to This Server Only`,
          },
        ];
      }),
    );
}

export interface MoveBlock {
  red: string | null;
  lines: string[];
  changes: {
    nodeId: string;
    project: string;
    text: string;
    reaches: string[];
  }[];
  note: string | null;
  serves: Serve[];
  reaches: string[];
}

export function moveBlock(
  stack: { project: string; network?: StackNetwork | null },
  source: { nodeId: string; name: string },
  target: { nodeId: string; name: string },
  view: NetworkView,
  servers: Hosting[],
): MoveBlock | null {
  const members = inside(view);
  const addressOf = (id: string) =>
    members.find((member) => member.nodeId === id)?.address ?? null;
  const from = addressOf(source.nodeId);
  const to = addressOf(target.nodeId);
  const serves = (stack.network?.serves ?? []).flatMap((serve) => {
    if (serve.all) return [serve];
    const others = (serve.to ?? []).filter((id) => id !== target.nodeId);
    return others.length > 0 ? [{ ...serve, to: others }] : [];
  });
  const reaches = stack.network?.reaches ?? [];
  const served = stack.network?.private ?? [];
  const reachers = servers
    .filter(
      (server) => server.id !== source.nodeId && server.id !== target.nodeId,
    )
    .flatMap((server) =>
      (server.stacks ?? []).flatMap((other) => {
        const all = other.network?.reaches ?? [];
        const old = all.filter((place) =>
          served.some((port) => place === `${from}:${port}`),
        );
        return from !== null && old.length > 0
          ? [{ server, project: other.project, all, old }]
          : [];
      }),
    );
  if (serves.length === 0 && reaches.length === 0 && reachers.length === 0) {
    return null;
  }
  if (to === null) {
    const chosen = serves.flatMap((serve) =>
      serve.all
        ? members
            .filter((member) => member.nodeId !== source.nodeId)
            .map((member) => member.nodeId)
        : (serve.to ?? []),
    );
    const who = [
      ...new Set([
        ...reachers.map((reacher) => reacher.server.name),
        ...chosen.map((id) => nameIn(view, id)),
      ]),
    ];
    return {
      red:
        who.length > 0
          ? `${target.name} is not in the private network, so ${listOf(who)} cannot reach ${stack.project} there.`
          : `${target.name} is not in the private network, so ${stack.project} cannot reach ${listOf(reaches.map((place) => placeText(view, place)))} there.`,
      lines: [],
      changes: [],
      note: null,
      serves: [],
      reaches: [],
    };
  }
  const swap = (place: string) =>
    from !== null && place.startsWith(`${from}:`)
      ? `${to}${place.slice(from.length)}`
      : place;
  const changes = reachers.map((reacher) => ({
    nodeId: reacher.server.id,
    project: reacher.project,
    text: `Change ${reacher.project}'s reach on ${reacher.server.name} from ${listOf(reacher.old.map((place) => placeText(view, place)))} to ${listOf(reacher.old.map((place) => placeText(view, swap(place))))}`,
    reaches: reacher.all.map((place) =>
      reacher.old.includes(place) ? swap(place) : place,
    ),
  }));
  const named = kryName(source.name);
  return {
    red: null,
    lines: serves.map(
      (serve) =>
        `On ${target.name}, ${stack.project} serves ${serve.port} to ${serve.all ? "All Servers" : `${listOf((serve.to ?? []).map((id) => nameIn(view, id)))} only`}, as it does now.`,
    ),
    changes,
    note:
      changes.length === 0
        ? null
        : `${changes.length === 1 ? `${changes[0]!.project}'s` : "Their"} own settings may still name ${named}, such as a secret. Change them after the move.`,
    serves,
    reaches: reaches.filter((place) => !place.startsWith(`${to}:`)),
  };
}

export const moveProblem = (changes: MoveBlock["changes"]) =>
  changes.length > NETWORK.moveReaches
    ? `One move changes at most ${NETWORK.moveReaches} other stacks. Untick some and change them after the move.`
    : null;

export const hostingOf = (
  reports: { id: string; stacks?: Hosting["stacks"] }[],
  nodes: { id: string; name: string }[],
): Hosting[] =>
  reports.flatMap((report) => {
    const name = nodes.find((node) => node.id === report.id)?.name;
    return name ? [{ id: report.id, name, stacks: report.stacks }] : [];
  });

export const reachedStacks = (server: Hosting | undefined) =>
  (server?.stacks ?? [])
    .filter((stack) => (stack.network?.private ?? []).length > 0)
    .map((stack) => stack.project);

export interface CheckSuggestion {
  nodeId: string;
  project: string;
  reaches: string[];
  text: string;
  check: {
    nodeId: string;
    name: string;
    kind: CheckKind;
    target: string;
    timeoutSeconds: number;
  };
}

export function checkSuggestions(
  servers: Hosting[],
  view: NetworkView,
  checks: Pick<CheckRecord, "node_id" | "target">[],
  dismissals: { nodeId: string; project: string; reaches: string[] }[],
): CheckSuggestion[] {
  const same = (a: string[], b: string[]) =>
    a.length === b.length && a.every((item) => b.includes(item));
  return servers.flatMap((server) =>
    (server.stacks ?? []).flatMap((stack) => {
      const reaches =
        stack.access === "contained" ? (stack.network?.reaches ?? []) : [];
      const aside = dismissals.some(
        (dismissal) =>
          dismissal.nodeId === server.id &&
          dismissal.project === stack.project &&
          same(dismissal.reaches, reaches),
      );
      return (aside ? [] : reaches).flatMap((place): CheckSuggestion[] => {
        const [address = "", rest = ""] = place.split(":");
        const [port = "", protocol = ""] = rest.split("/");
        const member = inside(view).find((entry) => entry.address === address);
        if (!member || protocol !== "tcp") return [];
        const target = `${kryName(member.name)}:${port}`;
        const watched = checks.some(
          (check) =>
            check.node_id === server.id &&
            [target, `${address}:${port}`].includes(check.target),
        );
        if (watched) return [];
        const serving = servers
          .find((entry) => entry.id === member.nodeId)
          ?.stacks?.find((other) =>
            other.network?.private.includes(`${port}/tcp`),
          )?.project;
        return [
          {
            nodeId: server.id,
            project: stack.project,
            reaches,
            text: `${stack.project} reaches ${placeText(view, place)} over the private network. Watch that path from ${server.name}?`,
            check: {
              nodeId: server.id,
              name: `${stack.project} to ${member.name}${serving ? ` ${serving}` : `:${port}`}`,
              kind: "TCP",
              target,
              timeoutSeconds: 10,
            },
          },
        ];
      });
    }),
  );
}

export function heldRows(view: NetworkView): string[] {
  return view.held.map((held) => {
    const who = [
      ...new Set(
        held.points.map(
          (point) => `${point.stack} on ${nameIn(view, point.nodeId)}`,
        ),
      ),
    ];
    return `${held.address} · Was ${held.nodeName ?? "--"}.${who.length > 0 ? ` ${listOf(who)} still ${who.length === 1 ? "reaches" : "reach"} it.` : ""}`;
  });
}

export function heldNote(view: NetworkView): string | null {
  const lines = view.held.map((held) => {
    const who = [
      ...new Set(
        held.points.map(
          (point) => `${point.stack} on ${nameIn(view, point.nodeId)}`,
        ),
      ),
    ];
    return who.length > 0
      ? `${held.address} is held for ${listOf(who)}.`
      : `${held.address} is held.`;
  });
  return lines.length > 0
    ? `${lines.join(" ")} Freed addresses are given out last.`
    : null;
}

const reachLine = (
  view: NetworkView,
  pointer: { nodeId: string; stack: string; target: string },
): Row => {
  const who = `${pointer.stack} on ${nameIn(view, pointer.nodeId)}`;
  const place = placeText(view, pointer.target);
  return {
    mark: "✕",
    text: `${who} reaches ${place}`,
    detail: "It fails until you change it.",
    short: `${who} stops reaching ${portWord(place)}`,
    action: "edit",
    nodeId: pointer.nodeId,
  };
};

export function removeLines(
  server: NetworkServer,
  view: NetworkView,
  facts: { firewall: Firewall; docker: boolean; tools: boolean },
  servers: Hosting[] = [],
): Row[] {
  const others = inside(view)
    .filter((member) => member.nodeId !== server.nodeId)
    .map((member) => member.name);
  const lines: Row[] = [];
  if (others.length > 0) {
    lines.push({
      mark: "−",
      text: `${listOf(others)} drop ${server.name} and stop accepting its key`,
      short: `${listOf(others)} drop it`,
    });
  }
  lines.push({
    mark: "−",
    text: `On ${server.name}, kry0 goes down and its key is deleted`,
    short: facts.firewall
      ? `kry0, its key and its ${facts.firewall} rules come off`
      : "kry0 and its key come off",
  });
  const parts = [
    facts.firewall ? `the two ${facts.firewall} rules` : null,
    facts.docker ? "the boot wait" : null,
  ].filter((part) => part !== null);
  if (parts.length > 0) {
    lines.push({
      mark: "−",
      text: `${capitalize(listOf(parts))} ${parts.length === 1 && !facts.firewall ? "comes" : "come"} off`,
      ...(facts.firewall
        ? { detail: `allow ${server.port}/udp · allow in on kry0` }
        : {}),
      short: "",
    });
  }
  if (facts.tools) {
    lines.push({
      mark: "−",
      text: "WireGuard tools come off · Krynodes installed them for this, and nothing else uses them",
      short: "WireGuard tools come off",
    });
  }
  const pointers = pointersAt(view, server);
  const who = [
    ...new Set(
      pointers.map(
        (pointer) => `${pointer.stack} on ${nameIn(view, pointer.nodeId)}`,
      ),
    ),
  ];
  lines.push(
    pointers.length > 0
      ? {
          mark: "·",
          text: `${server.address} is held while a stack still points to it · ${listOf(who)}`,
          short: `${server.address} is held while in use`,
        }
      : {
          mark: "·",
          text: `${server.address} is let go and given out again last`,
          short: `${server.address} is let go`,
        },
    ...pointers.map((pointer) => reachLine(view, pointer)),
    ...stackLines(view, servers, server.nodeId),
  );
  return lines;
}

type CheckLike = Pick<
  CheckRecord,
  "id" | "name" | "node_id" | "target" | "enabled"
>;

function hostOf(target: string): string {
  if (target.includes("://")) {
    try {
      return new URL(target).hostname;
    } catch {
      return "";
    }
  }
  return target.split(":")[0] ?? "";
}

export function networkChecks<T extends CheckLike>(
  checks: T[],
  range: string,
): T[] {
  return checks.filter((check) => {
    const host = hostOf(check.target);
    return (
      Boolean(check.enabled) &&
      (host.endsWith(".kry") ||
        (/^\d+\.\d+\.\d+\.\d+$/u.test(host) && overlaps(host, range)))
    );
  });
}

export function deleteLines(
  view: NetworkView,
  presence: Presence,
  facts: { keep: string[]; names?: Record<string, string> },
  checks: CheckLike[],
  servers: Hosting[] = [],
): Row[] {
  const members = inside(view);
  const offline = members
    .filter((member) => !isOnline(presence, member.nodeId))
    .map((member) => member.name);
  const lines: Row[] = [
    {
      mark: "−",
      text: "kry0 comes off every server, with its key, its two firewall rules and the boot wait",
      short: "kry0, keys and firewall rules come off",
    },
    {
      mark: "−",
      text: "WireGuard tools come off where Krynodes installed them",
      ...(facts.keep.length > 0
        ? {
            detail: `${listOf(facts.keep)} ${facts.keep.length === 1 ? "keeps" : "keep"} them; Krynodes did not install them there.`,
          }
        : {}),
      short: "",
    },
    {
      mark: "−",
      text: "The range leaves Settings, Private Addresses, and held addresses are let go",
      short: "The range leaves Private Addresses",
    },
  ];
  if (offline.length > 0) {
    lines.push({
      mark: "·",
      text:
        offline.length === 1
          ? `${offline[0]} is offline and cleans itself up when it is back`
          : `${listOf(offline)} are offline and clean themselves up when they are back`,
    });
  }
  lines.push(
    ...stackLines(
      view,
      servers.filter((server) =>
        members.some((member) => member.nodeId === server.id),
      ),
    ),
    ...members.flatMap((member) =>
      pointersAt(view, member).map((pointer) => reachLine(view, pointer)),
    ),
  );
  const through = view.network ? networkChecks(checks, view.network.range) : [];
  if (through.length > 0) {
    lines.push({
      mark: "✓",
      text: `Turn off ${plural(through.length, "check")} that ${through.length === 1 ? "goes" : "go"} through the network`,
      detail: `${through.map((check) => `${check.name}, on ${nameIn(view, check.node_id, facts.names)}`).join("; ")}. Turn ${through.length === 1 ? "it" : "them"} on again from Checks.`,
      short: `Turn off ${plural(through.length, "check")} through the network`,
    });
  }
  return lines;
}

export function leaveParagraph(
  server: NetworkServer,
  view: NetworkView,
  unreachable = false,
): string {
  const others = inside(view)
    .filter((member) => member.nodeId !== server.nodeId)
    .map((member) => member.name);
  if (unreachable) {
    return others.length > 0
      ? `That also takes kry0 off. Until then it can do no harm: ${listOf(others)} ${others.length === 1 ? "drops" : "drop"} ${server.name} now and no longer ${others.length === 1 ? "accepts" : "accept"} its key.`
      : "That also takes kry0 off.";
  }
  const pointers = pointersAt(view, server);
  const drop =
    others.length > 0
      ? `${listOf(others)} ${others.length === 1 ? "drops" : "drop"} it, and `
      : "";
  const address =
    pointers.length > 0
      ? `${server.address} is held while a stack still points to it.`
      : `${server.address} is let go.`;
  const reach =
    pointers.length > 0
      ? ` ${listOf(pointers.map((pointer) => `${pointer.stack} on ${nameIn(view, pointer.nodeId)} reaches ${placeText(view, pointer.target)}`))} and ${pointers.length === 1 ? "stops" : "stop"} working.`
      : "";
  return `${server.name} is in the private network. Krynodes takes it out first: ${drop}${address}${reach}`;
}

export function rekeyNote(
  view: NetworkView,
  presence: Presence,
): string | null {
  const offline = inside(view)
    .filter((member) => !isOnline(presence, member.nodeId))
    .map((member) => member.name);
  if (offline.length === 0) return null;
  return offline.length === 1
    ? `${offline[0]} is offline. It gets its new key when it is back, and cannot connect with the old one meanwhile.`
    : `${listOf(offline)} are offline. They get their new keys when they are back, and cannot connect with the old ones meanwhile.`;
}

export function missingSeals(
  view: NetworkView,
  sealKeys: Record<string, string>,
): string | null {
  const missing = inside(view)
    .filter((member) => !sealKeys[member.nodeId])
    .map((member) => member.name);
  if (missing.length === 0) return null;
  return missing.length === 1
    ? `${missing[0]} has not reported its seal key yet. Refresh its services and try again.`
    : `${listOf(missing)} have not reported their seal keys yet. Refresh their services and try again.`;
}

export const waitingLine = (
  server: { name: string; since: string },
  address: string | null,
) => ({
  title: `${server.name} wants to join · ready since ${clockTime(server.since)}`,
  state: `Ready · gets ${address ?? "--"}`,
});

export const networkText = {
  create: (names: string[]) =>
    `Create the private network with ${listOf(names)}`,
  add: (names: string[]) => `Add ${listOf(names)} to the private network`,
  remove: (name: string) => `Remove ${name} from the private network`,
  delete: "Delete the private network",
  rekey: "Make new network keys",
  test: (a: string, b: string) => `Test ${a} ↔ ${b}`,
  again: "Send the private network again",
  rule: (name: string) => `Put the firewall rule back on ${name}`,
  mtu: (name: string, size: number) => `Use MTU ${size} on ${name}`,
  rename: (from: string, to: string) =>
    `Rename ${from} to ${to} in the private network`,
};

export const testingText = (a: string, b: string, milliseconds: number) =>
  `Testing ${a} ↔ ${b} · ${formatDuration(milliseconds)}`;

const ACTION_TEXT: Partial<Record<ActionRecord["action"], string>> = {
  inspect: "Check the server for the private network",
  probe: "Test the private network's port",
  test: "Test a private network link",
  prepare: "Get the server ready for the private network",
  unprepare: "Undo the private network preparation",
  rekey: "Make a new network key",
};

export function networkActionText(
  action: Pick<ActionRecord, "kind" | "action" | "nodeId" | "peer">,
  names: Record<string, string> = {},
): string | null {
  if (action.kind !== "network") return null;
  const own = names[action.nodeId];
  const peer = action.peer ? names[action.peer] : undefined;
  if (action.action === "test" && own && peer) {
    return `Test the link ${own} ↔ ${peer}`;
  }
  return ACTION_TEXT[action.action] ?? null;
}

export interface TestEnd {
  nodeId: string;
  name: string;
  age: number | null;
  address: string | null;
  port: number;
  firewall: Firewall;
  result: NetworkTest | null;
}

export function testEnd(
  member: NetworkServer,
  presence: Presence,
  now: number,
  facts: { firewall: Firewall },
  result: NetworkTest | null,
): TestEnd {
  const seenAt = presence[member.nodeId]?.seenAt ?? null;
  return {
    nodeId: member.nodeId,
    name: member.name,
    age: seenAt === null ? null : Math.round((now - seenAt) / 1000),
    address: member.endpoint?.split(":")[0] ?? null,
    port: member.port,
    firewall: facts.firewall,
    result,
  };
}

type Answered = TestEnd & { result: NetworkTest };

const through = (a: Answered, b: Answered) =>
  a.result.handshakes.answered > 0 || b.result.handshakes.answered > 0;

const stale = (end: Answered, version: number) =>
  !end.result.up || !end.result.hasKey || end.result.version !== version;

const moved = (end: Answered) =>
  end.address !== null &&
  end.result.publicAddress !== null &&
  end.result.publicAddress !== end.address;

const ruleGone = (end: Answered) =>
  end.address !== null &&
  end.firewall !== null &&
  end.result.firewall.rule === false;

const narrowest = (a: Answered, b: Answered) => {
  const passed = (end: Answered) => end.result.large.passed ?? 0;
  if (passed(a) !== passed(b)) return passed(a) < passed(b) ? a : b;
  return a.address === null ? a : b;
};

export function testRows(
  a: TestEnd,
  b: TestEnd,
  network: { version: number; mtu: number },
): Row[] {
  if (!a.result || !b.result) {
    const gone = a.result ? b : a;
    return [
      {
        mark: "✕",
        text: `${gone.name} does not answer`,
        detail: `${gone.name} is offline, so there is nothing to test.`,
      },
    ];
  }
  const ends = [a, b] as Answered[];
  const ago = (end: TestEnd) =>
    `${end.name} ${end.age === null ? "--" : `${formatDuration(end.age * 1000)} ago`}`;
  const rows: Row[] = [
    {
      mark: "✓",
      text: `Both agents answer · ${ago(a)} · ${ago(b)}`,
      short: "Both agents answer",
    },
  ];
  const down = ends.filter((end) => !end.result.up).map((end) => end.name);
  const behind = ends.filter((end) => stale(end, network.version));
  if (down.length > 0) {
    rows.push({ mark: "✕", text: `kry0 is down on ${listOf(down)}` });
  } else if (behind.length > 0) {
    rows.push(
      ...behind.map((end): Row => ({
        mark: "✕",
        text: `${end.name} does not have the current network`,
      })),
    );
  } else {
    rows.push({
      mark: "✓",
      text: "kry0 is up on both, each with the other's key",
      short: "kry0 up, keys match",
    });
  }
  const apart = Math.abs(a.result.clock - b.result.clock);
  rows.push(
    apart > 60
      ? {
          mark: "✕",
          text: `Clocks are ${apart}s apart`,
          detail:
            "WireGuard refuses handshakes from a clock that went back. Fix time sync on the server that is off.",
        }
      : {
          mark: "✓",
          text: `Clocks agree · ${apart < 1 ? "under 1s" : `${apart}s`} apart`,
          short: "Clocks agree",
        },
  );
  const listening = ends.filter((end) => end.address !== null);
  const whose = (end: TestEnd, text: string) =>
    listening.length > 1 ? `${end.name}: ${text}` : capitalize(text);
  for (const end of listening) {
    rows.push(
      moved(end)
        ? {
            mark: "✕",
            text: `${end.name} now has ${end.result.publicAddress}`,
            detail: "Krynodes updates it on the others by itself.",
          }
        : {
            mark: "✓",
            text: `${end.name} still has ${end.address}`,
            short: whose(end, "address unchanged"),
          },
    );
  }
  for (const end of listening) {
    const wall = end.result.firewall;
    const on = `${end.firewall} on ${end.name}`;
    if (end.firewall === null || wall.rule === null) {
      rows.push({
        mark: "✓",
        text: `${end.name} has no firewall in the way`,
        short: whose(end, "no firewall in the way"),
      });
    } else if (!wall.rule) {
      rows.push({
        mark: "✕",
        text: `${on} does not let in ${end.port}/udp · the rule from Krynodes is gone`,
        short: `${on} drops ${end.port}/udp`,
      });
    } else if (!wall.lets) {
      rows.push({
        mark: "✕",
        text: `${on} does not let in ${end.port}/udp`,
        detail: "Another rule drops it before the one from Krynodes.",
      });
    } else {
      rows.push({
        mark: "✓",
        text: `${on} lets in ${end.port}/udp · the rule from Krynodes is there`,
        short: whose(end, `${end.firewall} lets in ${end.port}/udp`),
      });
    }
  }
  const [first, second] = ends as [Answered, Answered];
  if (!through(first, second)) {
    const sent = (from: Answered, to: Answered) =>
      `${from.name} sent ${formatBytes(from.result.handshakes.sent)} to ${to.name} and got ${from.result.handshakes.received > 0 ? formatBytes(from.result.handshakes.received) : "nothing"} back.`;
    const heard = [second, first].find((end) => end.result.handshakes.third);
    rows.push(
      {
        mark: "✕",
        text: "Handshakes do not get through",
        detail: [
          sent(first, second),
          sent(second, first),
          heard ? `Other servers' handshakes reach ${heard.name}.` : null,
        ]
          .filter(Boolean)
          .join(" "),
      },
      { mark: "–", text: "Large packets · tested once the link is up" },
    );
    return rows;
  }
  rows.push({ mark: "✓", text: "Handshakes get through" });
  const worse = [first, second].sort(
    (x, y) =>
      y.result.small.lost / Math.max(1, y.result.small.sent) -
      x.result.small.lost / Math.max(1, x.result.small.sent),
  )[0]!.result.small;
  if (worse.sent > 0) {
    rows.push(
      worse.lost === 0
        ? {
            mark: "✓",
            text: `Small packets · ${worse.ms === null ? "--" : `${worse.ms} ms`}, none lost`,
          }
        : {
            mark: "✕",
            text: `Small packets · ${worse.lost} of ${worse.sent} lost`,
          },
    );
  }
  const passed = narrowest(first, second).result.large.passed;
  if (passed === null) {
    rows.push({
      mark: "✕",
      text: `Packets of ${Math.min(...ends.flatMap((end) => end.result.large.tried), network.mtu)} bytes and larger do not get through`,
      short: "Large packets lost",
    });
  } else if (passed < network.mtu) {
    rows.push(
      {
        mark: "✕",
        text: `Packets of ${network.mtu} bytes do not get through`,
        short: "Large packets lost",
      },
      { mark: "✓", text: `Packets of ${passed} bytes get through` },
    );
  } else {
    rows.push({ mark: "✓", text: `Packets of ${passed} bytes get through` });
  }
  return rows;
}

export type TestFix =
  | { kind: "again" }
  | { kind: "rule"; nodeId: string }
  | { kind: "mtu"; nodeId: string; size: number };

export const fixLabel = (fix: TestFix) =>
  fix.kind === "again"
    ? "Send Again"
    : fix.kind === "rule"
      ? "Put Rule Back"
      : `Use ${fix.size}`;

export const testSummary = (rows: Row[], fix: TestFix | null) => {
  const failed = rows.find((row) => row.mark === "✕");
  return `${failed ? failed.short || failed.text : "The link answers"}${fix ? ` · ${fixLabel(fix)} was offered` : ""}`;
};

export function testPairs(
  view: NetworkView,
  nodeId?: string,
): [NetworkServer, NetworkServer][] {
  const members = inside(view);
  return members
    .flatMap((a, index) =>
      members
        .slice(index + 1)
        .map((b): [NetworkServer, NetworkServer] => [a, b]),
    )
    .filter(([a, b]) => !nodeId || a.nodeId === nodeId || b.nodeId === nodeId);
}

export const testOthers = (view: NetworkView, a: string, b: string) =>
  inside(view)
    .filter(
      (member) =>
        member.nodeId !== a &&
        member.nodeId !== b &&
        view.links.some(
          (link) =>
            link.answering &&
            [link.a, link.b].includes(member.nodeId) &&
            ([link.a, link.b].includes(a) || [link.a, link.b].includes(b)),
        ),
    )
    .map((member) => member.name);

export function mostLikely(
  a: TestEnd,
  b: TestEnd,
  network: { version: number; mtu: number },
  others: string[],
): { text: string; detail: string | null; fix: TestFix | null } {
  const gone = [a, b].find((end) => !end.result);
  if (gone) {
    return {
      text: `${gone.name} is offline. Test again when it is back.`,
      detail: null,
      fix: null,
    };
  }
  const [first, second] = [a, b] as [Answered, Answered];
  const ends = [first, second];
  const behind = ends.find((end) => stale(end, network.version));
  if (behind) {
    return {
      text: `${behind.name} does not have the current network.`,
      detail: "Send Again sends the same network to it; no new keys are made.",
      fix: { kind: "again" },
    };
  }
  const apart = Math.abs(first.result.clock - second.result.clock);
  if (apart > 60) {
    return {
      text: `The clocks on ${first.name} and ${second.name} are ${apart}s apart.`,
      detail:
        "Turn on time sync on the server that is off (timedatectl set-ntp true).",
      fix: null,
    };
  }
  const shifted = ends.find(moved);
  if (shifted) {
    return {
      text: `${shifted.name} moved to ${shifted.result.publicAddress}.`,
      detail:
        "Krynodes updates it on the others by itself. Test again in a minute.",
      fix: null,
    };
  }
  const missing = ends.find(ruleGone);
  if (missing) {
    return {
      text: `The rule from Krynodes on ${missing.name} is gone, so ${missing.firewall} drops ${missing.port}/udp.`,
      detail: "Put Rule Back adds it again.",
      fix: { kind: "rule", nodeId: missing.nodeId },
    };
  }
  const shut = ends.find(
    (end) =>
      end.address !== null &&
      end.firewall !== null &&
      end.result.firewall.rule === true &&
      !end.result.firewall.lets,
  );
  if (shut) {
    return {
      text: `Another rule on ${shut.name} drops ${shut.port}/udp before the one from Krynodes.`,
      detail: "Krynodes does not change rules it did not add.",
      fix: null,
    };
  }
  if (!through(first, second)) {
    const filtered = [second, first].find((end) => end.result.handshakes.third);
    if (filtered) {
      const other = filtered === second ? first : second;
      return {
        text: `Something in front of ${filtered.name} lets UDP ${filtered.port} in from ${others.length > 0 ? listOf(others) : "the other servers"} but not from ${other.name}${other.address ? ` (${other.address})` : ""}. This is often a provider firewall rule limited by source.${other.address ? ` Add ${other.address} to it.` : ""}`,
        detail: "Krynodes cannot change a provider's firewall.",
        fix: null,
      };
    }
    const target = second.address !== null ? second : first;
    return {
      text: `Nothing reaches ${target.name} on UDP ${target.port}. Something before the server drops it, usually the provider's firewall. Open UDP ${target.port} there.`,
      detail: "Krynodes cannot change a provider's firewall.",
      fix: null,
    };
  }
  const narrow = narrowest(first, second);
  const size = narrow.result.large.passed;
  if (size === null || size < network.mtu) {
    if (size === null) {
      return {
        text: `No large packet reaches ${narrow.name}, even at 1280 bytes.`,
        detail: "Its connection breaks up packets WireGuard cannot split.",
        fix: null,
      };
    }
    return {
      text: `The way to ${narrow.name} carries at most ${size} bytes, likely because of its ${narrow.address === null ? "home connection" : "provider's network"}. Small requests work, but a large reply stalls.`,
      detail: `${narrow.name} gets MTU ${size} and the others keep ${network.mtu}. Connections to ${narrow.name} then use the smaller size from both ends.`,
      fix: { kind: "mtu", nodeId: narrow.nodeId, size },
    };
  }
  const lossy = ends.find((end) => end.result.small.lost > 0);
  if (lossy) {
    return {
      text: `Some small packets are lost between ${first.name} and ${second.name} (${lossy.result.small.lost} of ${lossy.result.small.sent}).`,
      detail: "The path itself is unreliable; Krynodes cannot change it.",
      fix: null,
    };
  }
  return { text: "The link answers. Nothing to fix.", detail: null, fix: null };
}

export interface Joiner {
  node: string;
  name: string;
  address: string;
  key: string;
  signer: string;
  port: number;
  endpoint: string | null;
  nat: boolean;
}

export type DocumentChange =
  | {
      kind: "create";
      range: string;
      port: number;
      mtu: number;
      join: Joiner[];
    }
  | { kind: "add"; join: Joiner[] }
  | { kind: "remove"; nodeId: string }
  | { kind: "delete" }
  | { kind: "rekey"; keys: Record<string, string> }
  | { kind: "mtu"; nodeId: string; mtu: number | null }
  | { kind: "rename"; nodeId: string; name: string }
  | { kind: "release"; nodeId: string; key: string; signer: string }
  | { kind: "again" };

export async function baseOf(
  view: NetworkView,
): Promise<{ document: NetworkDocument; parent: string } | null> {
  if (!view.body) return null;
  const bytes = fromB64url(view.body);
  const document = networkDocumentSchema.parse(
    JSON.parse(new TextDecoder().decode(bytes)),
  );
  return {
    document: {
      ...document,
      members: document.members.map((member) =>
        view.quarantined.includes(member.node)
          ? { ...member, cut: true as const }
          : member,
      ),
    },
    parent: b64url(await crypto.subtle.digest("SHA-256", bytes)),
  };
}

async function pairKey(
  a: NetworkMember,
  b: NetworkMember,
  sealKeys: Record<string, string>,
) {
  const sealFor = (member: NetworkMember) => {
    const key = sealKeys[member.node];
    if (!key) {
      throw new Error(
        `${member.name} has not reported its seal key yet. Refresh its services and try again.`,
      );
    }
    return key;
  };
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const [forA, forB] = await Promise.all([
    seal(sealFor(a), secret),
    seal(sealFor(b), secret),
  ]);
  a.psk[b.node] = forA;
  b.psk[a.node] = forB;
}

export async function buildDocument(
  current: NetworkDocument | null,
  change: DocumentChange,
  sealKeys: Record<string, string>,
  parent?: string,
): Promise<NetworkDocument> {
  const next: NetworkDocument =
    change.kind === "create"
      ? {
          v: 1,
          version: (current?.version ?? 0) + 1,
          range: change.range,
          port: change.port,
          mtu: change.mtu,
          members: [],
          blocked: [],
        }
      : {
          ...current!,
          version: current!.version + 1,
          members: current!.members.map((member) => ({
            ...member,
            psk: { ...member.psk },
          })),
          blocked: [...current!.blocked],
        };
  switch (change.kind) {
    case "create":
    case "add":
      for (const joiner of change.join) {
        if (next.blocked.includes(joiner.key)) {
          throw new Error(
            `${joiner.name}'s key was taken out of the network and cannot come back. Remove and prepare it again for a new key.`,
          );
        }
        const member: NetworkMember = {
          ...joiner,
          endpoint: joiner.nat ? null : joiner.endpoint,
          mtu: null,
          psk: {},
        };
        for (const peer of next.members) await pairKey(peer, member, sealKeys);
        next.members.push(member);
      }
      break;
    case "remove": {
      const gone = next.members.find((member) => member.node === change.nodeId);
      if (gone) next.blocked.push(gone.key);
      next.members = next.members.filter(
        (member) => member.node !== change.nodeId,
      );
      for (const member of next.members) delete member.psk[change.nodeId];
      break;
    }
    case "delete":
      next.deleted = true;
      next.blocked = [
        ...new Set([
          ...next.blocked,
          ...next.members.map((member) => member.key),
        ]),
      ];
      next.members = [];
      break;
    case "rekey":
      for (const member of next.members) {
        const fresh = change.keys[member.node];
        if (fresh) {
          next.blocked.push(member.key);
          member.key = fresh;
          delete member.rekey;
        } else {
          member.rekey = true;
        }
      }
      for (const [index, member] of next.members.entries()) {
        for (const peer of next.members.slice(index + 1)) {
          await pairKey(member, peer, sealKeys);
        }
      }
      break;
    case "mtu":
      for (const member of next.members) {
        if (member.node === change.nodeId) member.mtu = change.mtu;
      }
      break;
    case "rename":
      for (const member of next.members) {
        if (member.node === change.nodeId) member.name = change.name;
      }
      break;
    case "release": {
      const released = next.members.find(
        (member) => member.node === change.nodeId,
      );
      if (!released) break;
      next.blocked.push(released.key);
      released.key = change.key;
      released.signer = change.signer;
      delete released.cut;
      for (const member of next.members) {
        if (member !== released) await pairKey(member, released, sealKeys);
      }
      break;
    }
    case "again":
      break;
  }
  if (parent) next.parent = parent;
  else delete next.parent;
  return networkDocumentSchema.parse(next);
}
