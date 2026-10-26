import type {
  AttentionItem,
  CheckKind,
  CheckRecord,
  CheckResult,
  Incident,
  NodeRecord,
  QuietSpan,
  ServiceEntry,
  ServiceKind,
} from "../types";
import {
  checkDisplayStatus,
  formatDuration,
  nodeState,
  parseTimestamp,
  titleCase,
  type CheckDisplay,
} from "./format";
import type { WorkSpan } from "./series";
import { failureText } from "./services";

const KIND_LABEL: Record<CheckKind, string> = {
  HTTP: "HTTP",
  TCP: "TCP",
  SERVICE: "Systemd",
  CONTAINER: "Docker",
};

export const kindLabel = (kind: string) =>
  KIND_LABEL[kind as CheckKind] ?? kind;

export const TARGET_HINT: Record<CheckKind, string> = {
  HTTP: "Fetched from the server. Down on errors, timeouts and 5xx answers.",
  TCP: "Opened from the server. Down when the connection fails in time.",
  SERVICE: "A unit on the server. Up while systemd reports it active.",
  CONTAINER:
    "A container on the server. Up while Docker reports it running and not unhealthy.",
};

export const TARGET_PLACEHOLDER: Record<CheckKind, string> = {
  HTTP: "https://example.com/health",
  TCP: "127.0.0.1:5432",
  SERVICE: "Choose a service",
  CONTAINER: "Choose a container",
};

const PICKED: Partial<Record<CheckKind, ServiceKind>> = {
  SERVICE: "systemd",
  CONTAINER: "docker",
};

export const pickedKind = (kind: CheckKind) => kind in PICKED;

export function targetOptions(
  services: ServiceEntry[] | undefined,
  kind: CheckKind,
  current: string,
): { name: string; seen: boolean }[] {
  const wanted = PICKED[kind];
  if (!wanted) return [];
  const names = [
    ...new Set(
      (services ?? [])
        .filter((entry) => entry.kind === wanted)
        .map((entry) => entry.name),
    ),
  ].sort((a, b) => a.localeCompare(b));
  const options = names.map((name) => ({ name, seen: true }));
  return current && !names.includes(current)
    ? [{ name: current, seen: false }, ...options]
    : options;
}

export function checkTargetProblem(
  kind: CheckKind,
  target: string,
): string | null {
  const value = target.trim();
  if (value === "" && kind === "CONTAINER") return "Choose a container.";
  if (value === "" && kind === "SERVICE") return "Choose a service.";
  if (value === "") return "Enter a target.";
  if (kind === "HTTP") {
    try {
      const url = new URL(value);
      if (url.protocol === "http:" || url.protocol === "https:") return null;
    } catch {
      return "Use a full URL starting with http:// or https://.";
    }
    return "Use a full URL starting with http:// or https://.";
  }
  if (kind === "TCP") {
    const match = /^([a-zA-Z0-9.-]+):([0-9]{1,5})$/u.exec(value);
    if (!match) return "Use host:port, such as 127.0.0.1:5432.";
    const port = Number(match[2]);
    return port >= 1 && port <= 65_535
      ? null
      : "The port must be between 1 and 65535.";
  }
  if (kind === "CONTAINER") {
    return /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/u.test(value)
      ? null
      : "Choose a container.";
  }
  return /^[a-zA-Z0-9@_.:-]{1,128}$/u.test(value)
    ? null
    : "Use a systemd unit name, such as nginx.service.";
}

export function checksByServer(
  checks: CheckRecord[],
  nodes: NodeRecord[],
  seen: number,
): { node: NodeRecord; checks: CheckRecord[] }[] {
  return nodes.flatMap((node) => {
    const state = nodeState(node, seen);
    const isDown = (check: CheckRecord) =>
      checkDisplayStatus(check.status, state, check.enabled) === "DOWN";
    const own = checks
      .filter((check) => check.node_id === node.id)
      .sort(
        (a, b) =>
          Number(isDown(b)) - Number(isDown(a)) || a.name.localeCompare(b.name),
      );
    return own.length === 0 ? [] : [{ node, checks: own }];
  });
}

const plural = (count: number, word: string) =>
  `${count} ${word}${count === 1 ? "" : "s"}`;

export const serverChecksText = (count: number, down: number) =>
  down > 0
    ? `${plural(count, "check")} · ${down} down`
    : plural(count, "check");

const bare = (text: string) =>
  text
    .replace(/^https?:\/\//u, "")
    .replace(/\/$/u, "")
    .replace(/\.service$/u, "")
    .toLowerCase();

export function shownTarget(
  check: Pick<CheckRecord, "kind" | "name" | "target">,
): string | null {
  const shown = check.target.replace(/^https?:\/\//u, "").replace(/\/$/u, "");
  return bare(check.target) === bare(check.name) ? null : shown;
}

export const failuresText = (count: number) =>
  count >= 2 ? `${count} failures in a row` : null;

export const incidentLine = (updates: number) =>
  updates > 0
    ? `Incident Open · ${plural(updates, "update")} →`
    : "Incident Open →";

export function autoRestartLine(
  check: Pick<CheckRecord, "kind" | "node_id" | "target" | "auto_restart">,
  items: AttentionItem[],
  now: number,
): string | null {
  if (check.kind !== "SERVICE" || check.auto_restart !== 1) return null;
  const unit = check.target.endsWith(".service")
    ? check.target
    : `${check.target}.service`;
  const failed = items.find(
    ({ action }) =>
      action.action === "heal" &&
      action.nodeId === check.node_id &&
      action.kind === "systemd" &&
      action.name === unit,
  );
  return failed ? failureText(failed.action, now) : null;
}

const RUNNING: Partial<Record<CheckKind, string>> = {
  CONTAINER: "Running",
  SERVICE: "Active",
};

export type LiveTone = "ok" | "bad" | "warn" | "idle" | "off" | "info" | "work";

const covers = (from: number, to: number, now: number) =>
  from <= now && now < to;

export function checkLive(view: {
  check: CheckRecord;
  display: CheckDisplay;
  incident?: Pick<Incident, "started_at">;
  latest?: { results: CheckResult[] };
  lastSeen?: string | null;
  work?: WorkSpan[];
  quiet?: QuietSpan[];
  healing?: boolean;
  now: number;
}): { label: string; tone: LiveTone } {
  const { check, display, incident, now } = view;
  if (display === "PAUSED") return { label: "Paused", tone: "idle" };
  const work = (view.work ?? []).find((span) =>
    covers(span.from, span.to, now),
  );
  if (work && !incident && (display === "DOWN" || display === "OFFLINE")) {
    return { label: titleCase(`${work.label} by you`), tone: "work" };
  }
  if (display === "OFFLINE") {
    const routine = (view.quiet ?? []).some(
      (span) =>
        span.why === "routine" &&
        covers(
          parseTimestamp(span.from),
          span.to === null ? Infinity : parseTimestamp(span.to),
          now,
        ),
    );
    if (routine) return { label: "Routine Restart", tone: "info" };
    return {
      label: view.lastSeen
        ? `Offline ${formatDuration(now - parseTimestamp(view.lastSeen))}`
        : "Offline",
      tone: "off",
    };
  }
  if (display === "DOWN") {
    const down = incident
      ? `Down ${formatDuration(now - parseTimestamp(incident.started_at))}`
      : "Down";
    return {
      label: view.healing ? `${down} · Auto-Restarting` : down,
      tone: incident ? "bad" : "warn",
    };
  }
  if (display !== "UP") return { label: "--", tone: "idle" };
  const running = RUNNING[check.kind];
  if (running) {
    return {
      label: check.since
        ? `${running} ${formatDuration(now - parseTimestamp(check.since))}`
        : running,
      tone: "ok",
    };
  }
  const latency = view.latest?.results.at(-1)?.latencyMs ?? null;
  return { label: latency === null ? "--" : `${latency}ms`, tone: "ok" };
}
