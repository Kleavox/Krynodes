import type {
  ActionRecord,
  AttentionItem,
  HistoryEntry,
  HistoryShow,
  ServiceEntry,
  ServiceKind,
  StackEntry,
} from "../types";
import {
  clockTime,
  formatDuration,
  incidentReason,
  parseTimestamp,
  shortDate,
  stampTime,
} from "./format";
import { networkActionText } from "./network";
import { actorOf } from "./operations";
import { namesServer, outcomeOf, packageText } from "./packages";
import { quarantineActionText } from "./quarantine";
import {
  displayName,
  durationText,
  errorLine,
  objectOf,
  verb,
} from "./services";
import { containersOf, stackOf } from "./stacks";
import { tailnetActionText } from "./tailscale";

type Stacks = Pick<StackEntry, "project" | "containers">[];

const dayOf = (at: number, offset = 0) => {
  const date = new Date(at);
  return new Date(
    date.getFullYear(),
    date.getMonth(),
    date.getDate() + offset,
  ).getTime();
};

const plural = (count: number, word: string) =>
  `${count} ${word}${count === 1 ? "" : "s"}`;

const failed = (action: ActionRecord) =>
  action.status === "failed" || action.status === "expired";

function dayCounts(entries: HistoryEntry[]): string {
  const actions = entries.flatMap((entry) =>
    entry.type === "action" ? [entry.action] : [],
  );
  const incidents = new Set(
    entries.flatMap((entry) =>
      entry.type === "incident" ? [entry.incident.id] : [],
    ),
  ).size;
  const broken = actions.filter(failed).length;
  const changes =
    actions.length + entries.filter((entry) => entry.type === "network").length;
  return [
    changes > 0 ? plural(changes, "action") : null,
    broken > 0 ? `${broken} failed` : null,
    incidents > 0 ? plural(incidents, "incident") : null,
  ]
    .filter(Boolean)
    .join(" · ");
}

export function dayGroups(
  entries: HistoryEntry[],
  now: number,
): { label: string; counts: string; entries: HistoryEntry[] }[] {
  const today = dayOf(now);
  const yesterday = dayOf(now, -1);
  const groups: { label: string; counts: string; entries: HistoryEntry[] }[] =
    [];
  const recovered = new Set(
    entries.flatMap((entry) =>
      entry.type === "incident" && entry.event === "resolved"
        ? [entry.incident.id]
        : [],
    ),
  );
  const owned = new Set(
    entries.flatMap((entry) =>
      entry.type === "network" && entry.change.change.startsWith("It was me:")
        ? [entry.at]
        : [],
    ),
  );
  for (const entry of entries) {
    if (
      (entry.type === "incident" &&
        entry.event === "opened" &&
        recovered.has(entry.incident.id)) ||
      (entry.type === "action" &&
        entry.action.kind === "host" &&
        entry.action.action === "accept" &&
        entry.action.status === "done" &&
        owned.has(entry.action.requestedAt))
    ) {
      continue;
    }
    const day = dayOf(Date.parse(entry.at));
    const label =
      day === today
        ? "Today"
        : day === yesterday
          ? "Yesterday"
          : shortDate(day);
    const last = groups.at(-1);
    if (last?.label === label) last.entries.push(entry);
    else groups.push({ label, counts: "", entries: [entry] });
  }
  for (const group of groups) group.counts = dayCounts(group.entries);
  return groups;
}

export function incidentText(
  entry: Extract<HistoryEntry, { type: "incident" }>,
): string {
  const { incident } = entry;
  return entry.event === "opened" || !incident.resolvedAt
    ? `${incident.checkName} went down`
    : `${incident.checkName} recovered after ${formatDuration(parseTimestamp(incident.resolvedAt) - parseTimestamp(incident.startedAt))}`;
}

export function causedText(
  incident: NonNullable<AttentionItem["incident"]>,
  now: number,
): string {
  return [
    `${incident.checkName} down since ${clockTime(incident.startedAt)}`,
    incidentReason(incident.summary),
    formatDuration(now - parseTimestamp(incident.startedAt)),
  ]
    .filter(Boolean)
    .join(" · ");
}

export function historyPath(params: {
  node?: string;
  show: HistoryShow;
  q: string;
}): string {
  const query = new URLSearchParams();
  if (params.node) query.set("node", params.node);
  if (params.show !== "everything") query.set("show", params.show);
  if (params.q.trim()) query.set("q", params.q.trim());
  return query.size > 0 ? `/api/history?${query}` : "/api/history";
}

const SHOWS: readonly HistoryShow[] = [
  "everything",
  "actions",
  "incidents",
  "failed",
];

export const readShow = (value: string | null): HistoryShow =>
  SHOWS.find((show) => show === value) ?? "everything";

export function logTargets(
  action: Pick<ActionRecord, "kind" | "name">,
  inventory: { stacks: Stacks; services: ServiceEntry[] },
): { kind: ServiceKind; name: string }[] {
  if (action.kind === "compose") {
    const stack = inventory.stacks.find(
      (entry) => entry.project === action.name,
    ) ?? { project: action.name };
    return containersOf(stack, inventory.services).map((entry) => ({
      kind: "docker",
      name: entry.name,
    }));
  }
  return action.kind === "docker" || action.kind === "systemd"
    ? [{ kind: action.kind, name: action.name }]
    : [];
}

export type Retry =
  | { via: "deploy" | "rollback" | "packages" }
  | { via: "run"; action: "start" | "restart" }
  | { via: "confirm"; action: "stop" | "remove" };

export function retryOf(
  action: Pick<ActionRecord, "kind" | "action">,
): Retry | null {
  const service = action.kind === "docker" || action.kind === "systemd";
  if (
    action.kind === "apt" &&
    ["upgrade", "install", "remove", "purge"].includes(action.action)
  ) {
    return { via: "packages" };
  }
  if (action.kind === "compose" && action.action === "deploy") {
    return { via: "deploy" };
  }
  if (action.kind === "compose" && action.action === "rollback") {
    return { via: "rollback" };
  }
  if (action.action === "heal" && service)
    return { via: "run", action: "restart" };
  if (
    (action.action === "start" || action.action === "restart") &&
    (service || action.kind === "compose")
  ) {
    return { via: "run", action: action.action };
  }
  if (
    service &&
    (action.action === "stop" ||
      (action.action === "remove" && action.kind === "docker"))
  ) {
    return { via: "confirm", action: action.action };
  }
  return null;
}

export function lastLines(
  text: string,
  count: number,
): { text: string; hidden: number } {
  const lines = text.replace(/\s+$/u, "").split("\n");
  return {
    text: lines.slice(-count).join("\n"),
    hidden: Math.max(0, lines.length - count),
  };
}

export function historyText(
  action: ActionRecord,
  stacks: Stacks = [],
  nodeName?: string,
  names: Record<string, string> = {},
): string {
  const packages =
    packageText(action, nodeName) ??
    tailnetActionText(action, nodeName) ??
    networkActionText(action, names) ??
    quarantineActionText(action);
  if (packages) return packages;
  const stack =
    action.kind === "docker" ? stackOf(stacks, action.name) : undefined;
  const name = stack ?? displayName(action.kind, action.name);
  if (action.kind === "bridge") {
    return `${action.action === "remove" ? "Delete" : "Create"} network ${action.name}`;
  }
  if (action.action === "uninstall") return "Remove Krynodes from the server";
  if (action.action === "admin") {
    return `Get an admin user command for ${nodeName ?? "the server"}`;
  }
  if (action.action === "reach") return `Change ${action.name}'s reach`;
  if (action.action === "logs") return `Read logs of ${name}`;
  return `${verb(action.action)} ${stack ?? objectOf(action)}`;
}

export function failedLine(
  action: ActionRecord,
  server: { name?: string; stacks?: Stacks },
  now: number,
  devices?: { id: string; name: string }[],
): { text: string; time: string; failure: string | null } {
  const line = actionLine(action, {
    nodeName: server.name,
    showServer: true,
    devices,
    stacks: server.stacks,
    now,
  });
  return {
    text: line.server ? `${line.text} on ${line.server}` : line.text,
    time: line.time,
    failure: line.failure,
  };
}

export function actionLine(
  action: ActionRecord,
  options: {
    nodeName?: string;
    showServer?: boolean;
    devices?: { id: string; name: string }[];
    stacks?: Stacks;
    now?: number;
    names?: Record<string, string>;
  } = {},
) {
  const failure = failed(action)
    ? [
        action.exitCode === null ? null : `Exit ${action.exitCode}`,
        errorLine(
          (action.kind === "apt" ? outcomeOf(action)?.failed : undefined) ??
            action.output,
        ),
      ]
        .filter(Boolean)
        .join(" · ") || (action.status === "expired" ? "Expired" : "Failed")
    : null;
  return {
    time:
      options.now === undefined
        ? clockTime(action.requestedAt)
        : stampTime(action.requestedAt, options.now),
    mark: action.status === "done" ? "✓" : failed(action) ? "✕" : null,
    text: historyText(action, options.stacks, options.nodeName, options.names),
    server:
      options.showServer && !namesServer(action)
        ? (options.nodeName ?? null)
        : null,
    device: actorOf(action, options.devices),
    duration: durationText(action),
    failure,
  };
}
