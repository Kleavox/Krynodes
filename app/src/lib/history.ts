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
  parseTimestamp,
  shortDate,
  stampTime,
} from "./format";
import { actorOf } from "./operations";
import {
  displayName,
  durationText,
  errorLine,
  objectOf,
  verb,
} from "./services";
import { containersOf, stackOf } from "./stacks";

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
  return [
    actions.length > 0 ? plural(actions.length, "action") : null,
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
  for (const entry of entries) {
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
    incident.summary,
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
  | { via: "deploy" | "rollback" }
  | { via: "run"; action: "start" | "restart" }
  | { via: "confirm"; action: "stop" | "remove" };

export function retryOf(
  action: Pick<ActionRecord, "kind" | "action">,
): Retry | null {
  const service = action.kind === "docker" || action.kind === "systemd";
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

export function historyText(action: ActionRecord, stacks: Stacks = []): string {
  const stack =
    action.kind === "docker" ? stackOf(stacks, action.name) : undefined;
  const name = stack ?? displayName(action.kind, action.name);
  if (action.action === "uninstall") return "Remove Krynodes from the server";
  if (action.action === "logs") return `Read logs of ${name}`;
  return `${verb(action.action)} ${stack ?? objectOf(action)}`;
}

export function actionLine(
  action: ActionRecord,
  options: {
    nodeName?: string;
    showServer?: boolean;
    devices?: { id: string; name: string }[];
    stacks?: Stacks;
    now?: number;
  } = {},
) {
  const failure = failed(action)
    ? [
        action.exitCode === null ? null : `Exit ${action.exitCode}`,
        errorLine(action.output),
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
    text: historyText(action, options.stacks),
    server: options.showServer ? (options.nodeName ?? null) : null,
    device: actorOf(action, options.devices),
    duration: durationText(action),
    failure,
  };
}
