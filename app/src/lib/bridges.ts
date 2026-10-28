import { BRIDGE_NAME, type BridgesReport } from "@krynodes/protocol";

import type { StackEntry } from "../types";
import { serviceShape, sharedNetworksOf } from "./compose";
import { bounds, listOf, networkOf, overlaps } from "./network";

export type Taken = BridgesReport["taken"][number];
export type BridgeNetwork = BridgesReport["networks"][number];
export type Access = "contained" | "full";

interface BridgeServer {
  name: string;
  bridges: BridgesReport | null;
  stacks?: StackEntry[];
}

export interface NetworkBox {
  name: string;
  kind: BridgeNetwork["kind"] | null;
  guest: boolean;
  address: string;
  offers: { service: string; value: string }[];
  reach: { entry: string; guest: boolean; ticked: boolean; gone: boolean }[];
  refusal: string | null;
}

export const KIND_TAG: Record<BridgeNetwork["kind"], string> = {
  contained: "Contained",
  full: "Full Access",
  outside: "Outside Krynodes",
};

const NAME_HINT = "Letters, digits, dots, dashes and underscores.";

export const notReported = (name: string) =>
  `${name} has not reported its networks yet.`;

const TAILSCALE = "100.64.0.0/10";
const PRIVATE_RANGES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
const OCTET = "(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
const CIDR = new RegExp(
  `^${OCTET}\\.${OCTET}\\.${OCTET}\\.${OCTET}/(3[0-2]|[12]?\\d)$`,
  "u",
);
const PEER = /^([^/]+)\/(.+)\.([a-z0-9][a-z0-9_-]*):(\d{1,5}\/(?:tcp|udp))$/u;
const RISKY_CAPS = ["NET_ADMIN", "NET_RAW", "ALL"];

export function pickSubnet(
  taken: Taken[],
  privateRange: string | null,
): string | null {
  const used = [
    ...taken.map((entry) => entry.range),
    ...(privateRange ? [privateRange] : []),
  ];
  for (let index = 0; index < 2048; index += 1) {
    const subnet = `172.${24 + Math.floor(index / 256)}.${index % 256}.0/24`;
    if (!used.some((range) => overlaps(range, subnet))) return subnet;
  }
  return null;
}

const inside = (outer: string, inner: string) => {
  const big = bounds(outer);
  const small = bounds(inner);
  return (
    big !== null && small !== null && big[0] <= small[0] && small[1] <= big[1]
  );
};

function subnetProblem(
  subnet: string,
  name: string,
  taken: Taken[],
  privateRange: string | null,
) {
  const masked = CIDR.test(subnet) ? networkOf(subnet) : null;
  if (!masked) return "Write it as 172.24.0.0/24.";
  if (masked !== subnet) return `Write it as ${masked}.`;
  const docker = taken.find(
    (entry) => !entry.own && overlaps(entry.range, subnet),
  );
  if (docker) return `Overlaps ${docker.by} (${docker.range}) on ${name}.`;
  if (privateRange && overlaps(privateRange, subnet)) {
    return `Overlaps your private network (${privateRange}).`;
  }
  if (overlaps(TAILSCALE, subnet))
    return "Overlaps Tailscale's addresses (100.64.0.0/10).";
  const own = taken.find((entry) => entry.own && overlaps(entry.range, subnet));
  if (own) return `Overlaps ${name}'s own network (${own.range} on ${own.by}).`;
  if (!PRIVATE_RANGES.some((range) => inside(range, subnet))) {
    return "Use a private range: 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16.";
  }
  const bits = Number(subnet.split("/")[1]);
  if (bits < 16 || bits > 28) return "Use a prefix from /16 to /28.";
  return null;
}

export function subnetLine(
  input: string,
  server: BridgeServer,
  privateRange: string | null,
): { ok: boolean; text: string } {
  if (!server.bridges) return { ok: false, text: "--" };
  const typed = input.trim();
  if (typed === "") {
    const picked = pickSubnet(server.bridges.taken, privateRange);
    return picked
      ? { ok: true, text: `Krynodes picks ${picked}, free on ${server.name}.` }
      : {
          ok: false,
          text: `No /24 of 172.24.0.0/13 is free on ${server.name}. Type a subnet.`,
        };
  }
  const problem = subnetProblem(
    typed,
    server.name,
    server.bridges.taken,
    privateRange,
  );
  return problem
    ? { ok: false, text: problem }
    : { ok: true, text: `✓ Free on ${server.name}` };
}

export function nameLine(
  input: string,
  server: BridgeServer,
): { ok: boolean; text: string } {
  const name = input.trim();
  if (!BRIDGE_NAME.test(name)) return { ok: false, text: NAME_HINT };
  if (server.bridges?.networks.some((network) => network.name === name)) {
    return {
      ok: false,
      text: `${server.name} already has a network named ${name}.`,
    };
  }
  if (server.bridges?.claimed.includes(name)) {
    const owner = (server.stacks ?? [])
      .map((stack) => stack.project)
      .filter((project) => name.startsWith(`${project}_`))
      .sort((a, b) => b.length - a.length)[0];
    return {
      ok: false,
      text: `${owner ? `The ${owner} stack makes its own ${name.slice(owner.length + 1)} network` : `A stack on ${server.name} makes its own network`} with this name. Write external: true there, or pick another name.`,
    };
  }
  return { ok: true, text: NAME_HINT };
}

export function composeLines(
  network: BridgeNetwork,
  serviceName: string,
): string {
  const key =
    network.name.slice(network.name.lastIndexOf("_") + 1) || network.name;
  return `services:\n  ${serviceName}:\n    networks:\n      - ${key}\n\nnetworks:\n  ${key}:\n    name: ${network.name}\n    external: true\n`;
}

export const composeNote = (kind: BridgeNetwork["kind"], serverName: string) =>
  kind === "contained"
    ? `Contained stacks on ${serverName} join it; a Full Access stack joins as a guest.`
    : `Only Full Access stacks on ${serverName} can use it.`;

export function networkUsers(
  network: BridgeNetwork,
): { name: string; guest: boolean }[] {
  const users = new Map<string, boolean>();
  for (const member of network.members) {
    users.set(
      member.project,
      (users.get(member.project) ?? true) && member.guest,
    );
  }
  return [...users]
    .map(([name, guest]) => ({ name, guest }))
    .sort(
      (a, b) =>
        Number(a.guest) - Number(b.guest) || a.name.localeCompare(b.name),
    );
}

export function deleteText(network: BridgeNetwork): {
  title: string;
  body: string;
  ok: boolean;
} {
  const users = [...new Set(network.members.map((member) => member.project))];
  const title = `Delete ${network.name}?`;
  if (users.length === 0) {
    return {
      title,
      body: "Nothing uses it now. Its addresses are freed.",
      ok: true,
    };
  }
  return {
    title,
    body: `${listOf(users)} ${users.length === 1 ? "still uses" : "still use"} it. Take it out of their compose files first.`,
    ok: false,
  };
}

function guestProblem(
  text: string,
  service: string,
  guest: boolean,
): string | null {
  const shape = serviceShape(text, service);
  if (guest && shape.privileged) return `${service} is privileged`;
  const cap = guest
    ? shape.caps.find((each) => RISKY_CAPS.includes(each))
    : undefined;
  if (cap) return `${service} adds ${cap}`;
  if (guest && shape.networkMode) return `${service} sets network_mode`;
  return null;
}

export function networkBoxes(
  text: string,
  server: BridgeServer,
  project: string,
  access: Access,
): NetworkBox[] {
  const stack = server.stacks?.find((entry) => entry.project === project);
  const offered = stack?.network?.offers ?? [];
  const peers = stack?.network?.peers ?? [];
  const guest = access === "full";
  return sharedNetworksOf(text).flatMap(({ name, services }): NetworkBox[] => {
    const network = server.bridges?.networks.find(
      (entry) => entry.name === name,
    );
    const refused = (refusal: string): NetworkBox[] => [
      {
        name,
        kind: network?.kind ?? null,
        guest,
        address: "",
        offers: [],
        reach: [],
        refusal,
      },
    ];
    if (network?.kind !== "contained") {
      if (guest || !server.bridges) return [];
      if (!network)
        return refused(
          `${name} is not on ${server.name}. Create it under Docker Networks first.`,
        );
      if (network.kind === "full")
        return refused(
          `A Contained stack cannot join ${name}, a Full Access network.`,
        );
      return refused(
        `${name} on ${server.name} was not made by Krynodes as a Contained network. Create one under Docker Networks.`,
      );
    }
    for (const service of services) {
      const problem = guestProblem(text, service, guest);
      if (problem)
        return refused(
          `${problem}, so it cannot join ${name}, a Contained network.`,
        );
      const copies = serviceShape(text, service).copies;
      if (copies > 1) {
        return refused(
          `${service} runs ${copies} copies; a service on a Contained network runs one, so its address stays fixed.`,
        );
      }
    }
    const pinned = (service: string) =>
      network.members.find(
        (member) => member.project === project && member.service === service,
      )?.address ?? null;
    const where = services.map((service) => {
      const address = pinned(service);
      if (!address)
        return `${service} gets an address from ${network.subnet ?? "the network"} when it starts.`;
      return guest
        ? `${service} is ${address}.`
        : `${project}'s ${service} is ${address} here.`;
    });
    const reach: NetworkBox["reach"] = guest
      ? []
      : network.members
          .filter((member) => member.project !== project)
          .flatMap((member) =>
            member.offers.map((port) => {
              const entry = `${member.service}.${member.project}:${port}`;
              return {
                entry,
                guest: member.guest,
                ticked: peers.includes(`${name}/${entry}`),
                gone: false,
              };
            }),
          );
    if (!guest) {
      for (const peer of peers) {
        const entry = peer.slice(name.length + 1);
        if (
          peer.startsWith(`${name}/`) &&
          !reach.some((each) => each.entry === entry)
        ) {
          reach.push({ entry, guest: false, ticked: true, gone: true });
        }
      }
    }
    return [
      {
        name,
        kind: "contained",
        guest,
        address: [
          ...(guest
            ? [
                `${project} joins as a guest: it answers on the ports it offers and never starts a connection here.`,
              ]
            : []),
          ...where,
        ].join(" "),
        offers: services.map((service) => ({
          service,
          value: offered
            .filter((entry) => entry.startsWith(`${name}/${service}=`))
            .map((entry) => entry.slice(name.length + service.length + 2))
            .join(", "),
        })),
        reach,
        refusal: null,
      },
    ];
  });
}

export function moveLines(
  stack: StackEntry,
  from: BridgeServer,
  to: { name: string; bridges: BridgesReport | null },
): {
  lines: string[];
  refusal: string | null;
  creates: { name: string; kind: BridgeNetwork["kind"]; subnet: string }[];
} {
  const networks = from.bridges?.networks ?? [];
  const used = networks.filter(
    (network) =>
      network.kind !== "outside" &&
      network.members.some((member) => member.project === stack.project),
  );
  const lines: string[] = [];
  const creates: {
    name: string;
    kind: BridgeNetwork["kind"];
    subnet: string;
  }[] = [];
  let refusal: string | null = null;
  const refuse = (text: string) => {
    refusal ??= `${text} Move is off.`;
  };
  for (const network of used) {
    if (!to.bridges) {
      refuse(`${to.name} has not reported its networks yet.`);
      continue;
    }
    const there = to.bridges.networks.find(
      (entry) => entry.name === network.name,
    );
    const subnet = network.subnet ?? "";
    const clash = to.bridges.taken.find((entry) =>
      overlaps(entry.range, subnet),
    );
    if (there?.kind === "outside") {
      refuse(
        `${to.name} already has a network named ${network.name} that Krynodes did not make.`,
      );
    } else if (there && there.kind !== network.kind) {
      refuse(
        `${to.name} already has ${network.name} as a ${KIND_TAG[there.kind]} network.`,
      );
    } else if (!there && clash) {
      refuse(
        `${network.name}'s subnet ${subnet} overlaps ${clash.by} (${clash.range}) on ${to.name}.`,
      );
    } else if (!there) {
      creates.push({ name: network.name, kind: network.kind, subnet });
      lines.push(
        `+ Creates ${network.name} on ${to.name} first · ${KIND_TAG[network.kind]} · ${subnet}`,
      );
    }
  }
  if (creates.length > 4)
    refuse(`${stack.project} needs more than 4 networks ${to.name} lacks.`);
  const offers = (
    net: string,
    service: string,
    project: string,
    port: string,
  ) =>
    networks.some(
      (network) =>
        network.name === net &&
        network.members.some(
          (member) =>
            member.project === project &&
            member.service === service &&
            member.offers.includes(port),
        ),
    );
  const said = new Set<string>();
  const say = (line: string) => {
    if (!said.has(line)) lines.push(line);
    said.add(line);
  };
  for (const peer of stack.network?.peers ?? []) {
    const [, net = "", service = "", project = "", port = ""] =
      PEER.exec(peer) ?? [];
    if (offers(net, service, project, port)) {
      say(
        `${stack.project} reaches ${service}.${project} on ${net}. ${project} stays on ${from.name}, so ${stack.project} loses that after the move.`,
      );
    }
  }
  for (const other of from.stacks ?? []) {
    if (other.project === stack.project) continue;
    for (const peer of other.network?.peers ?? []) {
      const [, net = "", service = "", project = ""] = PEER.exec(peer) ?? [];
      if (project === stack.project) {
        say(
          `${other.project} reaches ${service}.${project} on ${net}. It loses that once ${stack.project} leaves ${from.name}.`,
        );
      }
    }
  }
  return { lines, refusal, creates };
}

const OFFER_PORT = /^(\d{1,5})\/(tcp|udp)$/u;

export function stackNetworkArgs(
  boxes: NetworkBox[],
  offers: Record<string, string>,
  ticks: Record<string, boolean>,
): { args: { offers?: string; peers?: string }; problem: string | null } {
  const refusal = boxes.find((box) => box.refusal)?.refusal ?? null;
  if (refusal) return { args: {}, problem: refusal };
  if (boxes.length === 0) return { args: {}, problem: null };
  const offered: string[] = [];
  for (const box of boxes) {
    for (const offer of box.offers) {
      const typed = offers[`${box.name}/${offer.service}`] ?? offer.value;
      for (const port of typed.split(",").map((each) => each.trim())) {
        if (port === "") continue;
        const match = OFFER_PORT.exec(port);
        const number = Number(match?.[1]);
        if (!match || number < 1 || number > 65535) {
          return {
            args: {},
            problem: `${offer.service} offers ${port}; write a port such as 3001/tcp.`,
          };
        }
        offered.push(`${box.name}/${offer.service}=${number}/${match[2]}`);
      }
    }
  }
  const reaching = boxes.filter((box) => !box.guest);
  const peers = reaching.flatMap((box) =>
    box.reach
      .filter((each) => ticks[`${box.name}/${each.entry}`] ?? each.ticked)
      .map((each) => `${box.name}/${each.entry}`),
  );
  return {
    args: {
      offers: [...new Set(offered)].join(","),
      ...(reaching.length > 0 ? { peers: peers.join(",") } : {}),
    },
    problem: null,
  };
}
