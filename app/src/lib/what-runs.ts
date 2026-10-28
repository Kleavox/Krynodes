import { ownerOf, touches, type CheckOwner } from "@krynodes/protocol/owner";

import type {
  AttentionItem,
  CheckRecord,
  Incident,
  ServiceEntry,
  ServicesResponse,
} from "../types";
import { formatDuration, parseTimestamp, shortDate } from "./format";
import { displayName, resting } from "./services";
import { stackOf } from "./stacks";

type ServiceNode = ServicesResponse["nodes"][number];
type CardKind = "stack" | "docker" | "systemd";

export interface RunCard {
  kind: CardKind;
  name: string;
  units: string[];
  problem: boolean;
  checks: CheckRecord[];
  incident: Incident | null;
  notFixed: AttentionItem | null;
}

const KIND_ORDER: Record<CardKind, number> = {
  stack: 0,
  docker: 1,
  systemd: 2,
};

const ownerKey = (owner: CheckOwner) =>
  owner.kind === "stack"
    ? `stack|${owner.project}`
    : owner.kind === "container"
      ? `docker|${owner.name}`
      : `systemd|${owner.unit}`;

const cardOwner = (kind: CardKind, name: string): CheckOwner =>
  kind === "stack"
    ? { kind: "stack", project: name }
    : kind === "docker"
      ? { kind: "container", name }
      : { kind: "systemd", unit: name };

const stopped = (entry: ServiceEntry) =>
  entry.state !== "running" &&
  entry.state !== "starting" &&
  !resting(entry.state);

const newest = <T>(list: T[], at: (item: T) => string) =>
  list.reduce<T | null>(
    (best, item) =>
      best === null || parseTimestamp(at(item)) > parseTimestamp(at(best))
        ? item
        : best,
    null,
  );

export function whatRuns(
  entry: ServiceNode,
  checks: CheckRecord[],
  incidents: Incident[],
  items: AttentionItem[],
): { cards: RunCard[]; other: CheckRecord[] } {
  const own = checks.filter((check) => check.node_id === entry.id);
  const owners = new Map(
    own.map((check) => {
      const owner = ownerOf(check, entry);
      return [check.id, owner ? ownerKey(owner) : null];
    }),
  );
  const claimed = new Set<string>();
  const gather = (keys: string[], units: string[] = []) => {
    const mine = own.filter((check) => keys.includes(owners.get(check.id)!));
    for (const check of mine) claimed.add(check.id);
    const ids = new Set(mine.map((check) => check.id));
    const related = incidents.filter((incident) => ids.has(incident.check_id));
    const open = related.find((incident) => incident.status === "OPEN");
    return {
      units,
      checks: mine,
      incident:
        open ??
        newest(
          related.filter((incident) => incident.status === "RESOLVED"),
          (incident) => incident.started_at,
        ),
      down:
        Boolean(open) ||
        mine.some((check) => check.enabled && check.status === "DOWN"),
    };
  };
  const card = (kind: CardKind, name: string, unhealthy: boolean): RunCard => {
    const owner = cardOwner(kind, name);
    const { down, ...gathered } = gather([ownerKey(owner)]);
    const notFixed = newest(
      items.filter(
        (item) =>
          item.action.nodeId === entry.id && touches(owner, item.action, entry),
      ),
      (item) => item.action.finishedAt ?? item.action.requestedAt,
    );
    return {
      kind,
      name,
      ...gathered,
      notFixed,
      problem: unhealthy || down || notFixed !== null,
    };
  };

  const cards: RunCard[] = [
    ...entry.stacks.map((stack) =>
      card("stack", stack.project, stack.running < stack.total),
    ),
    ...entry.services
      .filter(
        (service) =>
          service.kind === "docker" && !stackOf(entry.stacks, service.name),
      )
      .map((service) => card("docker", service.name, stopped(service))),
  ];
  const folded: ServiceEntry[] = [];
  for (const unit of entry.services.filter(
    (service) => service.kind === "systemd",
  )) {
    const single = card("systemd", unit.name, stopped(unit));
    if (single.problem) cards.push(single);
    else {
      for (const check of single.checks) claimed.delete(check.id);
      folded.push(unit);
    }
  }
  cards.sort(
    (a, b) =>
      Number(b.problem) - Number(a.problem) ||
      KIND_ORDER[a.kind] - KIND_ORDER[b.kind] ||
      a.name.localeCompare(b.name),
  );
  if (folded.length > 0) {
    const units = folded
      .sort(
        (a, b) =>
          Number(a.system) - Number(b.system) || a.name.localeCompare(b.name),
      )
      .map((unit) => unit.name);
    const { down: _, ...gathered } = gather(
      units.map((unit) => ownerKey({ kind: "systemd", unit })),
      units,
    );
    cards.push({
      kind: "systemd",
      name: "",
      ...gathered,
      problem: false,
      notFixed: null,
    });
  }
  return { cards, other: own.filter((check) => !claimed.has(check.id)) };
}

export function foldedUnitsText(units: string[]): string {
  const names = units.map((unit) => displayName("systemd", unit));
  const shown = names.length > 5 ? names.slice(0, 4) : names;
  const more = names.length - shown.length;
  return `${shown.join(" · ")}${more > 0 ? ` + ${more} more` : ""}`;
}

export function incidentNote(incident: Incident, now: number): string {
  const start = parseTimestamp(incident.started_at);
  return incident.resolved_at
    ? `Last Incident ${shortDate(start)}, ${formatDuration(parseTimestamp(incident.resolved_at) - start)}`
    : `Incident Open · Down ${formatDuration(now - start)}`;
}
