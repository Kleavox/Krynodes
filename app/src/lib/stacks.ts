import type {
  ActionRecord,
  NodeRecord,
  NodeTrust,
  RemovedStack,
  ServiceEntry,
  ServicesResponse,
  StackEntry,
  WebAddress,
} from "../types";
import { MIN_AGENT_VERSION } from "@krynodes/protocol/versions";

import { agentCurrent } from "./devices";
import { nodeState } from "./format";
import {
  displayName,
  groupByServer,
  isRead,
  type ServerGroup,
  type ServiceMember,
} from "./services";

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
      a.project.localeCompare(b.project),
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
  if (!agentCurrent(member.node)) return `Needs agent ${MIN_AGENT_VERSION}`;
  if (!member.stack.compose) return "Docker Compose is not installed";
  if (!member.trusted) return "Not trusted yet";
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

export function containersOf(
  project: string,
  services: ServiceEntry[],
): ServiceEntry[] {
  return services
    .filter(
      (service) =>
        service.kind === "docker" &&
        (service.name.startsWith(`${project}-`) ||
          service.name.startsWith(`${project}_`)),
    )
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
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
  if (!agentCurrent(node)) return `Needs agent ${MIN_AGENT_VERSION}`;
  if (!entry?.docker) return "Docker not reported yet";
  if (entry.docker === "missing") return "No Docker";
  if (entry.docker === "no-compose") return "Docker without Compose";
  if ((entry.trust?.access.length ?? 0) === 0) return "Not trusted yet";
  return null;
}

export function stackNameProblem(
  name: string,
  taken: string[],
  waiting: string[] = [],
): string | null {
  if (!name) return "Give the stack a name.";
  if (!/^[a-z0-9][a-z0-9_-]{0,62}$/u.test(name)) {
    return "Use lowercase letters, digits, - and _, starting with a letter or digit.";
  }
  if (taken.includes(name)) {
    return `This server already runs a stack named ${name}.`;
  }
  if (waiting.includes(name)) {
    return `A stack named ${name} waits in Removed. Restore it or delete it permanently first.`;
  }
  return null;
}

export interface ServerStack {
  member: StackMember;
  containers: ServiceMember[];
  peers: StackMember[];
}

export interface ServerList extends ServerGroup {
  stacks: ServerStack[];
}

const stopped = (member: ServiceMember) => member.entry.state !== "running";

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
    const projects = inventory.stacks
      .map((stack) => stack.project)
      .sort((a, b) => b.length - a.length);
    const owner = (member: ServiceMember) =>
      projects.find(
        (project) => containersOf(project, [member.entry]).length > 0,
      );
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
            item.containers.some(matches)) &&
          (!options.notRunning || unhealthy(item)),
      )
      .sort(
        (a, b) =>
          Number(unhealthy(b)) - Number(unhealthy(a)) ||
          a.member.stack.project.localeCompare(b.member.stack.project),
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

export const moveConfirmed = (
  original: "now" | "later" | "keep",
  typed: string,
  project: string,
) => original !== "now" || typed === project;
