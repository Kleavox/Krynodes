import { CONTAINER_NAME } from "@krynodes/protocol";

import type {
  ActionRecord,
  AttentionItem,
  NodeRecord,
  NodeTrust,
  RemovedStack,
  ServiceEntry,
  ServiceKind,
  ServicesResponse,
  StackEntry,
  WebAddress,
} from "../types";

import { namingOf } from "./compose";
import { agentCurrent, agentGap } from "./devices";
import { nodeState, timeAgo } from "./format";
import {
  displayName,
  failureText,
  groupByServer,
  isRead,
  resting,
  STATE_LABEL,
  toTarget,
  type ServerGroup,
  type ServiceMember,
} from "./services";

const MAX_HOST_PORTS = 16;

export function parseHostPorts(text: string): {
  ports: string[];
  problem: string | null;
} {
  const ports: string[] = [];
  for (const raw of text.split(",")) {
    const entry = raw.trim();
    if (entry === "") continue;
    const match = /^(\d{1,5})\/(tcp|udp)$/u.exec(entry);
    if (!match) {
      return { ports: [], problem: `${entry} is not a port such as 3000/tcp.` };
    }
    const number = Number(match[1]);
    if (number < 1 || number > 65_535) {
      return {
        ports: [],
        problem: `${entry} is not a port between 1 and 65535.`,
      };
    }
    if (!ports.includes(entry)) ports.push(entry);
  }
  return ports.length > MAX_HOST_PORTS
    ? {
        ports: [],
        problem: `A stack may reach at most ${MAX_HOST_PORTS} ports on the server.`,
      }
    : { ports, problem: null };
}

export interface StackMember {
  node: NodeRecord;
  stack: StackEntry;
  trusted: boolean;
  trust: NodeTrust | null;
  action: ActionRecord | null;
  addresses?: WebAddress[];
}

export interface RemovedMember extends RemovedStack {
  node: NodeRecord;
  action: ActionRecord | null;
  blocker: string | null;
}

const KEEP_REMOVED_MS = 7 * 24 * 3_600_000;
const DAY_MS = 24 * 3_600_000;

export interface StackGroup {
  project: string;
  members: StackMember[];
}

const healthy = (group: StackGroup) =>
  group.members.every((member) => member.stack.running === member.stack.total);

function latestCompose(data: ServicesResponse) {
  const latest = new Map<string, ActionRecord>();
  for (const action of data.actions) {
    if (action.kind === "compose" && !isRead(action)) {
      latest.set(`${action.nodeId}|${action.name}`, action);
    }
  }
  return latest;
}

export function removedStacks(
  data: ServicesResponse,
  nodes: NodeRecord[],
  query: string,
): RemovedMember[] {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const latest = latestCompose(data);
  const needle = query.trim().toLowerCase();
  return data.nodes
    .flatMap((entry) => {
      const node = byId.get(entry.id);
      if (!node) return [];
      return (entry.removed ?? [])
        .filter(
          (stack) =>
            !needle ||
            stack.project.includes(needle) ||
            node.name.toLowerCase().includes(needle),
        )
        .map((stack) => ({
          ...stack,
          node,
          action: latest.get(`${node.id}|${stack.project}`) ?? null,
          blocker: newStackBlocker(node, entry),
        }));
    })
    .sort(
      (a, b) =>
        Date.parse(b.removedAt) - Date.parse(a.removedAt) ||
        a.project.localeCompare(b.project),
    );
}

export const daysLeft = (removedAt: string, now: number) =>
  Math.max(
    0,
    Math.ceil((Date.parse(removedAt) + KEEP_REMOVED_MS - now) / DAY_MS),
  );

export const ownFolder = (directory: string) =>
  /^\/var\/lib\/kry-exec\/compose\/[^/]+$/u.test(directory);

export function groupStacks(
  data: ServicesResponse,
  nodes: NodeRecord[],
  query: string,
): StackGroup[] {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const latest = latestCompose(data);
  const needle = query.trim().toLowerCase();
  const groups = new Map<string, StackGroup>();
  for (const entry of data.nodes) {
    const node = byId.get(entry.id);
    if (!node) continue;
    for (const stack of entry.stacks) {
      if (
        needle &&
        !stack.project.includes(needle) &&
        !stack.title?.toLowerCase().includes(needle) &&
        !node.name.toLowerCase().includes(needle)
      ) {
        continue;
      }
      const group = groups.get(stack.project) ?? {
        project: stack.project,
        members: [],
      };
      group.members.push({
        node,
        stack,
        trusted: (entry.trust?.access.length ?? 0) > 0,
        trust: entry.trust,
        action: latest.get(`${node.id}|${stack.project}`) ?? null,
        addresses: (entry.webAddresses ?? []).filter(
          (address) => address.project === stack.project,
        ),
      });
      groups.set(stack.project, group);
    }
  }
  const sorted = [...groups.values()];
  for (const group of sorted) {
    group.members.sort((a, b) => a.node.name.localeCompare(b.node.name));
  }
  return sorted.sort(
    (a, b) =>
      Number(healthy(a)) - Number(healthy(b)) ||
      stackTitle(a.members[0]!.stack).localeCompare(
        stackTitle(b.members[0]!.stack),
      ),
  );
}

export const moveBlocker = (
  addresses: WebAddress[],
  original: "now" | "later" | "keep",
) =>
  addresses.length > 0 && original !== "keep"
    ? "Its web addresses still point here. Close web address… first, or keep the original."
    : null;

export function deployBlocker(member: StackMember): string | null {
  const gap = agentGap(member.node.agent_version);
  if (gap !== null) return gap;
  if (!member.stack.compose) return "Docker Compose is not installed";
  if (!member.trusted) return "Not Trusted Yet";
  return null;
}

export function deployTargets(
  members: StackMember[],
  seen: number,
): StackMember[] {
  return members
    .filter((member) => deployBlocker(member) === null)
    .sort(
      (a, b) =>
        Number(nodeState(a.node, seen) === "offline") -
        Number(nodeState(b.node, seen) === "offline"),
    );
}

const holds = (
  stack: Pick<StackEntry, "project" | "containers">,
  name: string,
) =>
  stack.containers?.length
    ? stack.containers.includes(name)
    : name.startsWith(`${stack.project}-`) ||
      name.startsWith(`${stack.project}_`);

export function containersOf(
  stack: Pick<StackEntry, "project" | "containers">,
  services: ServiceEntry[],
): ServiceEntry[] {
  return services
    .filter(
      (service) => service.kind === "docker" && holds(stack, service.name),
    )
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

export function stackOf(
  stacks: Pick<StackEntry, "project" | "containers">[],
  container: string,
): string | undefined {
  return [...stacks]
    .sort((a, b) => b.project.length - a.project.length)
    .find((stack) => holds(stack, container))?.project;
}

export type StackCommand = "start" | "stop" | "restart" | "remove" | "purge";

export function stackCommands(member: StackMember): StackCommand[] {
  if (!agentCurrent(member.node) || !member.trusted || !member.stack.compose) {
    return [];
  }
  const { running, total } = member.stack;
  return [
    ...(running < total ? (["start"] as const) : []),
    ...(running > 0 ? (["restart", "stop"] as const) : []),
    "remove",
    "purge",
  ];
}

export function newStackBlocker(
  node: NodeRecord,
  entry: ServicesResponse["nodes"][number] | undefined,
): string | null {
  const gap = agentGap(node.agent_version);
  if (gap !== null) return gap;
  if (!entry?.docker) return "Docker Not Reported Yet";
  if (entry.docker === "missing") return "No Docker";
  if (entry.docker === "no-compose") return "Docker without Compose";
  if ((entry.trust?.access.length ?? 0) === 0) return "Not Trusted Yet";
  return null;
}

export const stackSlug = (title: string) =>
  title
    .normalize("NFKD")
    .replace(/\p{M}/gu, "")
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/gu, "-")
    .replace(/^[-_]+/u, "")
    .slice(0, 63)
    .replace(/[-_]+$/u, "");

export const stackTitle = (stack: Pick<StackEntry, "project" | "title">) =>
  stack.title ?? stack.project;

export const titleProblem = (title: string) =>
  !title
    ? "Give the stack a name."
    : [...title].length > 64
      ? "Keep the name to 64 characters."
      : null;

export function stackNameProblem(
  title: string,
  taken: string[],
  waiting: string[] = [],
): string | null {
  const wrong = titleProblem(title);
  if (wrong) return wrong;
  const project = stackSlug(title);
  if (!project) return "Use at least one letter or digit.";
  if (taken.includes(project)) {
    return `This server already runs a stack named ${project}.`;
  }
  if (waiting.includes(project)) {
    return `A stack named ${project} waits in Removed. Restore it or delete it permanently first.`;
  }
  return null;
}

export interface ContainerName {
  service: string;
  suggested: string;
  value: string;
}

export function containerNames(
  text: string,
  project: string,
  saved: Record<string, string> = {},
  typed: Record<string, string> = {},
  original = "",
): ContainerName[] {
  const services = namingOf(text);
  const before = new Map(
    namingOf(original).map((entry) => [entry.service, entry.own]),
  );
  return services
    .filter((entry) => entry.copies <= 1)
    .map(({ service, own }) => {
      const fallback =
        services.length === 1 ? project : `${project}-${service}`;
      const suggested =
        own !== (before.get(service) ?? null)
          ? (own ?? fallback)
          : (saved[service] ?? own ?? fallback);
      return { service, suggested, value: typed[service]?.trim() || suggested };
    });
}

export type NameOwner = (name: string) => string | null;

type ServerEntry = Pick<
  ServicesResponse["nodes"][number],
  "stacks" | "services"
>;

export function nameOwner(
  entry: ServerEntry | undefined,
  project: string,
  server: string,
): NameOwner {
  const stacks = entry?.stacks ?? [];
  const services = entry?.services ?? [];
  return (name) => {
    const suffix = [project, ...stacks.map((stack) => stack.project)].find(
      (owner) => name.endsWith(`.${owner}`),
    );
    if (suffix !== undefined) {
      const owner = stacks.find(
        (stack) => stack.project === suffix && suffix !== project,
      );
      return `Names ending in .${suffix} are kept for the services of ${owner ? stackTitle(owner) : "this stack"}.`;
    }
    for (const stack of stacks) {
      if (stack.project === project) continue;
      if (containersOf(stack, services).some((entry) => entry.name === name)) {
        return `${name} is a container of ${stackTitle(stack)} on ${server}.`;
      }
    }
    for (const stack of stacks) {
      if (stack.project !== project && stack.services?.includes(name)) {
        return `${name} is a service of ${stackTitle(stack)} on ${server}.`;
      }
    }
    return services.some(
      (entry) =>
        entry.kind === "docker" &&
        entry.name === name &&
        stackOf(stacks, name) === undefined,
    )
      ? `${server} already runs a container named ${name}.`
      : null;
  };
}

export function sameTitle(
  title: string,
  stacks: Pick<StackEntry, "project" | "title">[],
  server: string,
  self?: string,
): string | null {
  const other = stacks.find(
    (stack) =>
      stack.project !== self &&
      stackTitle(stack).toLowerCase() === title.trim().toLowerCase(),
  );
  return other
    ? `Another stack on ${server} is called ${stackTitle(other)}.`
    : null;
}

export function moveClash(
  stack: Pick<StackEntry, "project" | "title" | "names">,
  entry: (ServerEntry & { leftovers?: string[] }) | undefined,
  server: string,
): string | null {
  if (!entry) return null;
  if (entry.leftovers?.includes(stack.project)) {
    return `Files left from an earlier ${stack.project} are still on ${server}. Delete them there first.`;
  }
  const owner = nameOwner(entry, stack.project, server);
  for (const name of Object.values(stack.names ?? {})) {
    const found = owner(name);
    if (found) return found;
  }
  return sameTitle(stackTitle(stack), entry.stacks, server, stack.project);
}

export function containerNameProblem(
  rows: ContainerName[],
  index: number,
  owner: NameOwner,
): string | null {
  const { value } = rows[index]!;
  if (!CONTAINER_NAME.test(value)) {
    return "Use letters, digits, dashes, dots and underscores, starting with a letter or digit.";
  }
  if (rows.some((row, other) => other !== index && row.value === value)) {
    return "Another container in this stack has this name.";
  }
  return owner(value);
}

export interface ServerStack {
  member: StackMember;
  containers: ServiceMember[];
  peers: StackMember[];
}

export interface ServerList extends ServerGroup {
  stacks: ServerStack[];
}

const stopped = (member: ServiceMember) =>
  member.entry.state !== "running" && !resting(member.entry.state);

const unhealthy = (item: ServerStack) =>
  item.member.stack.running < item.member.stack.total ||
  item.containers.some(stopped);

export function serverLists(
  data: ServicesResponse,
  nodes: NodeRecord[],
  options: { showSystem: boolean; query: string; notRunning: boolean },
): ServerList[] {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const base = new Map(
    groupByServer(data, nodes, {
      showSystem: options.showSystem,
      query: "",
      notRunning: false,
    }).map((group) => [group.node.id, group]),
  );
  const peers = new Map(
    groupStacks(data, nodes, "").map((group) => [group.project, group.members]),
  );
  const needle = options.query.trim().toLowerCase();
  const lists: ServerList[] = [];
  for (const inventory of data.nodes) {
    const node = byId.get(inventory.id);
    if (!node) continue;
    const everything = base.get(node.id)?.members ?? [];
    const owner = (member: ServiceMember) =>
      member.entry.kind === "docker"
        ? stackOf(inventory.stacks, member.entry.name)
        : undefined;
    const serverMatch = !needle || node.name.toLowerCase().includes(needle);
    const matches = (member: ServiceMember) =>
      serverMatch ||
      displayName(member.entry.kind, member.entry.name)
        .toLowerCase()
        .includes(needle);
    const stacks = inventory.stacks
      .map((stack) => {
        const all = peers.get(stack.project) ?? [];
        return {
          member: all.find((peer) => peer.node.id === node.id)!,
          containers: everything.filter(
            (member) => owner(member) === stack.project,
          ),
          peers: all,
        };
      })
      .filter(
        (item) =>
          (serverMatch ||
            item.member.stack.project.includes(needle) ||
            item.member.stack.title?.toLowerCase().includes(needle) ||
            item.containers.some(matches)) &&
          (!options.notRunning || unhealthy(item)),
      )
      .sort(
        (a, b) =>
          Number(unhealthy(b)) - Number(unhealthy(a)) ||
          stackTitle(a.member.stack).localeCompare(stackTitle(b.member.stack)),
      );
    for (const item of stacks) {
      item.containers.sort((a, b) =>
        a.entry.name < b.entry.name ? -1 : a.entry.name > b.entry.name ? 1 : 0,
      );
    }
    const members = everything.filter(
      (member) =>
        owner(member) === undefined &&
        matches(member) &&
        (!options.notRunning || stopped(member)),
    );
    if (stacks.length === 0 && members.length === 0) continue;
    lists.push({
      node,
      trusted: (inventory.trust?.access.length ?? 0) > 0,
      members,
      stacks,
    });
  }
  const hurt = (list: ServerList) =>
    list.members.some(stopped) || list.stacks.some(unhealthy);
  return lists.sort(
    (a, b) =>
      Number(hurt(b)) - Number(hurt(a)) ||
      a.node.name.localeCompare(b.node.name),
  );
}

export type KindFilter = "all" | "stack" | ServiceKind;

export interface ServerBox extends ServerList {
  count: string;
  folded: number;
}

const COUNTED = ["running", "partly", "starting", "stopped", "failed"];

const stackHealth = (stack: Pick<StackEntry, "running" | "total">) =>
  stack.running === stack.total
    ? "running"
    : stack.running === 0
      ? "stopped"
      : "partly";

function serverCount(inventory: ServicesResponse["nodes"][number]): string {
  const states: string[] = [
    ...inventory.stacks.map(stackHealth),
    ...inventory.services
      .filter(
        (entry) =>
          entry.kind === "systemd" || !stackOf(inventory.stacks, entry.name),
      )
      .map((entry) => entry.state),
  ];
  return COUNTED.map(
    (state) => [state, states.filter((each) => each === state).length] as const,
  )
    .filter(([, count]) => count > 0)
    .map(([state, count]) => `${count} ${state}`)
    .join(" · ");
}

export function serverBoxes(
  data: ServicesResponse,
  nodes: NodeRecord[],
  options: { query: string; kind: KindFilter; showSystem: boolean },
): ServerBox[] {
  const counts = new Map(
    data.nodes.map((inventory) => [inventory.id, serverCount(inventory)]),
  );
  return serverLists(data, nodes, {
    showSystem: true,
    query: options.query,
    notRunning: false,
  })
    .map((list) => {
      const members = list.members.filter(
        (member) =>
          options.kind === "all" || member.entry.kind === options.kind,
      );
      const shown = options.showSystem
        ? members
        : members.filter((member) => !member.entry.system);
      return {
        ...list,
        stacks:
          options.kind === "all" || options.kind === "stack" ? list.stacks : [],
        members: shown,
        folded: members.length - shown.length,
        count: counts.get(list.node.id) ?? "",
      };
    })
    .filter((box) => box.stacks.length + box.members.length + box.folded > 0);
}

export const foldedText = (count: number) =>
  `+ ${count} system ${count === 1 ? "service" : "services"}`;

export const stackState = (
  stack: Pick<StackEntry, "running" | "total" | "access">,
) =>
  `${stack.running} of ${stack.total}${stack.access === "full" ? " · Full access" : ""}`;

export interface ServiceProblem {
  node: NodeRecord;
  kind: "stack" | ServiceKind;
  name: string;
  state: string;
  reason: string;
  primary: "rollback" | "start" | "restart";
  target: {
    nodeId: string;
    nodeName: string;
    kind: "compose" | ServiceKind;
    name: string;
  };
  stack: StackMember | null;
  blocker: string | null;
  latest: ActionRecord | null;
}

const finished = (action: ActionRecord) =>
  action.finishedAt ?? action.requestedAt;

const stateText = (
  entry: Pick<ServiceEntry, "state" | "since">,
  now: number,
) =>
  entry.since
    ? `${STATE_LABEL[entry.state]} ${timeAgo(entry.since, now)}`
    : STATE_LABEL[entry.state];

export function servicesAttention(
  data: ServicesResponse,
  nodes: NodeRecord[],
  items: AttentionItem[],
  now: number,
): ServiceProblem[] {
  const failures = new Map<string, ActionRecord>();
  for (const { action } of items) {
    const inventory = data.nodes.find((entry) => entry.id === action.nodeId);
    if (!inventory) continue;
    const project =
      action.kind === "compose"
        ? action.name
        : action.kind === "docker"
          ? stackOf(inventory.stacks, action.name)
          : undefined;
    const key = project
      ? `${action.nodeId}|stack|${project}`
      : action.kind === "docker" || action.kind === "systemd"
        ? `${action.nodeId}|${action.kind}|${action.name}`
        : null;
    if (!key) continue;
    const known = failures.get(key);
    if (!known || Date.parse(finished(action)) > Date.parse(finished(known))) {
      failures.set(key, action);
    }
  }
  const problems: ServiceProblem[] = [];
  for (const list of serverLists(data, nodes, {
    showSystem: true,
    query: "",
    notRunning: false,
  })) {
    const { node } = list;
    for (const { member, containers } of list.stacks) {
      const { stack } = member;
      const failure = failures.get(`${node.id}|stack|${stack.project}`);
      if (stack.running === stack.total && !failure) continue;
      const down = containers.find(stopped)?.entry;
      problems.push({
        node,
        kind: "stack",
        name: stack.project,
        state: `${stack.running} of ${stack.total} running`,
        reason: failure
          ? failureText(failure, now)
          : down
            ? stateText(down, now)
            : "Not Running",
        primary:
          failure?.action === "deploy" && stack.rollback
            ? "rollback"
            : stack.running === 0
              ? "start"
              : "restart",
        target: {
          nodeId: node.id,
          nodeName: node.name,
          kind: "compose",
          name: stack.project,
        },
        stack: member,
        blocker: deployBlocker(member),
        latest: member.action,
      });
    }
    for (const service of list.members) {
      const { entry } = service;
      const failure = failures.get(`${node.id}|${entry.kind}|${entry.name}`);
      if (entry.state !== "failed" && !failure) continue;
      problems.push({
        node,
        kind: entry.kind,
        name: displayName(entry.kind, entry.name),
        state: STATE_LABEL[entry.state],
        reason: failure ? failureText(failure, now) : stateText(entry, now),
        primary:
          entry.state === "running" || entry.state === "starting"
            ? "restart"
            : "start",
        target: toTarget(service),
        stack: null,
        blocker: list.trusted ? null : "Not Trusted Yet",
        latest: service.action,
      });
    }
  }
  return problems.sort(
    (a, b) =>
      a.node.name.localeCompare(b.node.name) || a.name.localeCompare(b.name),
  );
}

export const moveConfirmed = (
  original: "now" | "later" | "keep",
  typed: string,
  project: string,
) => original !== "now" || typed === project;
