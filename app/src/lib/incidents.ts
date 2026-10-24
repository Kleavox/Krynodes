import type { CheckOwner } from "@krynodes/protocol/owner";

import type {
  ActionRecord,
  CheckResult,
  Incident,
  IncidentBoard,
  IncidentDetail,
  IncidentUpdate,
  IncidentUpdateStatus,
} from "../types";
import { formatDuration, parseTimestamp, stampTime } from "./format";
import { historyText } from "./history";
import { errorLine, verb } from "./services";

export const UPDATE_LABEL: Record<IncidentUpdateStatus, string> = {
  investigating: "Investigating",
  identified: "Identified",
  monitoring: "Monitoring",
  update: "Update",
};

export interface Run {
  status: "UP" | "DOWN";
  message: string | null;
  from: string;
  to: string;
  count: number;
}

export function foldResults(results: CheckResult[]): Run[] {
  const runs: Run[] = [];
  const ordered = [...results].sort(
    (a, b) => parseTimestamp(a.t) - parseTimestamp(b.t),
  );
  for (const result of ordered) {
    const last = runs.at(-1);
    if (
      last &&
      last.status === result.status &&
      last.message === result.message
    ) {
      last.to = result.t;
      last.count += 1;
    } else {
      runs.push({
        status: result.status,
        message: result.message,
        from: result.t,
        to: result.t,
        count: 1,
      });
    }
  }
  return runs;
}

export function runText(
  run: Run,
  now: number,
): {
  title: string;
  when: string;
  body: string;
} {
  const from = stampTime(run.from, now);
  return {
    title: run.status === "DOWN" ? "Still Down" : "Up",
    when:
      run.count === 1
        ? from
        : `${from} – ${stampTime(run.to, parseTimestamp(run.from))}`,
    body: [
      run.count === 1 ? "1 check" : `${run.count} checks in a row`,
      run.message,
    ]
      .filter(Boolean)
      .join(" · "),
  };
}

export type TimelineEvent =
  | { type: "resolved"; at: string }
  | { type: "run"; at: string; run: Run }
  | { type: "update"; at: string; update: IncidentUpdate }
  | { type: "opened"; at: string; summary: string | null }
  | { type: "action"; at: string; action: ActionRecord }
  | { type: "lastGood"; at: string; latencyMs: number | null };

const RANK: Record<TimelineEvent["type"], number> = {
  resolved: 5,
  run: 4,
  update: 3,
  opened: 2,
  action: 1,
  lastGood: 0,
};

export function timeline(detail: IncidentDetail): TimelineEvent[] {
  const { incident } = detail;
  const start = parseTimestamp(incident.started_at);
  const end = incident.resolved_at
    ? parseTimestamp(incident.resolved_at)
    : Infinity;
  const during = detail.results.filter((result) => {
    const t = parseTimestamp(result.t);
    return t >= start && t <= end;
  });
  const events: TimelineEvent[] = [
    ...(incident.resolved_at
      ? [{ type: "resolved" as const, at: incident.resolved_at }]
      : []),
    ...foldResults(during).map((run) => ({
      type: "run" as const,
      at: run.to,
      run,
    })),
    ...(detail.updates ?? []).map((update) => ({
      type: "update" as const,
      at: update.createdAt,
      update,
    })),
    { type: "opened", at: incident.started_at, summary: incident.summary },
    ...(detail.actions ?? []).map((action) => ({
      type: "action" as const,
      at: action.requestedAt,
      action,
    })),
    ...(detail.lastGood
      ? [
          {
            type: "lastGood" as const,
            at: detail.lastGood.t,
            latencyMs: detail.lastGood.latencyMs,
          },
        ]
      : []),
  ];
  return events.sort(
    (a, b) =>
      parseTimestamp(b.at) - parseTimestamp(a.at) ||
      RANK[b.type] - RANK[a.type],
  );
}

export function incidentState(
  incident: Pick<Incident, "started_at" | "resolved_at">,
  now: number,
): string {
  const start = parseTimestamp(incident.started_at);
  return incident.resolved_at
    ? `Resolved · Lasted ${formatDuration(parseTimestamp(incident.resolved_at) - start)}`
    : `Open · Down ${formatDuration(now - start)}`;
}

export function ownerLink(owner: CheckOwner): { label: string; to: string } {
  switch (owner.kind) {
    case "stack":
      return {
        label: `Stack ${owner.project}`,
        to: `/services?q=${encodeURIComponent(owner.project)}`,
      };
    case "container":
      return {
        label: `Container ${owner.name}`,
        to: `/services?q=${encodeURIComponent(owner.name)}`,
      };
    case "systemd":
      return {
        label: `Unit ${owner.unit}`,
        to: `/services?q=${encodeURIComponent(owner.unit)}&system=1`,
      };
  }
}

const STRIP_BEFORE_MS = 3_600_000;
const STRIP_SLOTS = 48;

export function incidentStrip(
  incident: Pick<Incident, "started_at" | "resolved_at">,
  results: CheckResult[],
  windowSeconds: number,
  now: number,
): {
  since: number;
  until: number;
  measuredFrom: number;
  slotSeconds: number;
  count: number;
  results: CheckResult[];
} {
  const since = parseTimestamp(incident.started_at) - STRIP_BEFORE_MS;
  const until = incident.resolved_at
    ? parseTimestamp(incident.resolved_at)
    : now;
  const span = (until - since) / 1000;
  const slotSeconds =
    windowSeconds * Math.max(1, Math.ceil(span / STRIP_SLOTS / windowSeconds));
  return {
    since,
    until,
    measuredFrom: Math.min(
      ...results.map((result) => parseTimestamp(result.t)),
    ),
    slotSeconds,
    count: Math.min(STRIP_SLOTS, Math.ceil(span / slotSeconds) + 1),
    results: [...results].sort(
      (a, b) => Number(a.status === "DOWN") - Number(b.status === "DOWN"),
    ),
  };
}

const STATUS_WORD: Partial<Record<ActionRecord["status"], string>> = {
  queued: "waiting",
  sent: "running",
};

export function latestLine(
  entry: IncidentBoard["latest"][string],
): string | null {
  if (entry.update) {
    return `${UPDATE_LABEL[entry.update.status]}: ${entry.update.message}`;
  }
  const action = entry.action;
  if (!action) return null;
  if (action.status === "failed" || action.status === "expired") {
    const detail =
      errorLine(action.output) ??
      (action.exitCode === null ? null : `exit ${action.exitCode}`);
    const what = `${verb(action.action)} ${action.status}`;
    return detail ? `${what}: ${detail}` : what;
  }
  return `${historyText(action)}: ${STATUS_WORD[action.status] ?? action.status}`;
}

export function last30Text(last30: IncidentBoard["last30"]): string {
  if (last30.count === 0) return "Last 30 Days · No Incidents";
  return `Last 30 Days · ${last30.count} ${last30.count === 1 ? "incident" : "incidents"} · ${formatDuration(last30.downMs)} down in total`;
}
