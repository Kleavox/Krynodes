import type {
  ActionRecord,
  ActionStatus,
  ActionVerb,
  NodeRecord,
} from "../types";
import { agentState } from "./agent";
import { displayHandle, parseTimestamp } from "./format";
import { displayName, isPending } from "./services";

const REBOOT_WINDOW_MS = 10 * 60_000;
const SETTLE_MS = 2 * 60_000;
const STAYED_UP_MS = 90_000;

export type ServerOperation =
  | { kind: "restarting"; by: string; since: number; actionId: string }
  | { kind: "updating"; version: string; attempt: number; since: number };

export interface ActivityItem {
  action: ActionRecord;
  id: string;
  nodeId: string;
  nodeName: string;
  kind: ActionRecord["kind"];
  name: string;
  label: string;
  verb: ActionVerb;
  status: ActionStatus;
  by: string;
  at: number;
}

export const handleOf = (email: string) => displayHandle(null, email);

function rebootInFlight(
  node: Pick<NodeRecord, "id" | "connected_at" | "last_seen_at">,
  actions: ActionRecord[],
  now: number,
): ActionRecord | null {
  const latest = actions
    .filter(
      (action) =>
        action.nodeId === node.id &&
        action.kind === "host" &&
        action.action === "reboot",
    )
    .at(-1);
  if (!latest) return null;
  if (isPending(latest)) return latest;
  if (latest.status !== "done" || !latest.finishedAt) return null;
  const finished = parseTimestamp(latest.finishedAt);
  if (!(now - finished < REBOOT_WINDOW_MS)) return null;
  const back =
    node.connected_at !== undefined &&
    parseTimestamp(node.connected_at) > finished;
  const stayed =
    node.last_seen_at !== null &&
    parseTimestamp(node.last_seen_at) - finished > STAYED_UP_MS;
  return back || stayed ? null : latest;
}

export function serverOperation(
  node: NodeRecord,
  actions: ActionRecord[],
  now: number,
): ServerOperation | null {
  const reboot = rebootInFlight(node, actions, now);
  if (reboot) {
    return {
      kind: "restarting",
      by: handleOf(reboot.requestedBy),
      since: parseTimestamp(reboot.requestedAt),
      actionId: reboot.id,
    };
  }
  if (
    node.update_requested_version &&
    agentState(node, null, now) === "updating"
  ) {
    return {
      kind: "updating",
      version: node.update_requested_version,
      attempt: node.update_attempts || 1,
      since: parseTimestamp(node.update_requested_at ?? ""),
    };
  }
  return null;
}

function item(action: ActionRecord, nodeName: string, at: number) {
  return {
    action,
    id: action.id,
    nodeId: action.nodeId,
    nodeName,
    kind: action.kind,
    name: action.name,
    label: displayName(action.kind, action.name),
    verb: action.action,
    status: action.status,
    by: handleOf(action.requestedBy),
    at,
  };
}

export function activity(
  actions: ActionRecord[],
  nodes: NodeRecord[],
  now: number,
): ActivityItem[] {
  const names = new Map(nodes.map((node) => [node.id, node.name]));
  const visible = actions.filter(
    (action) => action.action !== "logs" && names.has(action.nodeId),
  );
  const running = visible
    .filter(isPending)
    .map((action) =>
      item(
        action,
        names.get(action.nodeId)!,
        parseTimestamp(action.requestedAt),
      ),
    );
  for (const node of nodes) {
    const reboot = rebootInFlight(node, visible, now);
    if (!reboot || isPending(reboot)) continue;
    running.push(item(reboot, node.name, parseTimestamp(reboot.requestedAt)));
  }
  return running;
}

export function elapsedText(milliseconds: number): string {
  const total = Math.max(0, Math.floor(milliseconds / 1000));
  if (total < 3600) {
    return `${Math.floor(total / 60)}:${String(total % 60).padStart(2, "0")}`;
  }
  const minutes = Math.floor(total / 60);
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

const RAN = new Set<ActionStatus>(["queued", "sent", "done", "failed"]);

const NOT_PLANNED = new Set(["logs", "autorestart", "manual"]);

export function maintenanceSpans(
  actions: ActionRecord[],
  nodeId: string,
): { from: number; to: number }[] {
  return actions
    .filter(
      (action) =>
        action.nodeId === nodeId &&
        !NOT_PLANNED.has(action.action) &&
        RAN.has(action.status),
    )
    .map((action) => ({
      from: parseTimestamp(action.sentAt ?? action.requestedAt),
      to: action.finishedAt
        ? parseTimestamp(action.finishedAt) +
          (action.action === "reboot" ? REBOOT_WINDOW_MS : SETTLE_MS)
        : Infinity,
    }));
}

export const plannedNow = (
  spans: { from: number; to: number }[],
  now: number,
) => spans.some((span) => span.from <= now && now < span.to);
