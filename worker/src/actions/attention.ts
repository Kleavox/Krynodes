import type { OwnerServer } from "@krynodes/protocol";

import type { ActionRow } from "./store";

export type Health = Map<string, boolean>;

const CHANGES_NOTHING = new Set(["logs", "read", "scan", "export"]);
const MAKES_IT_RUN = new Set([
  "start",
  "restart",
  "deploy",
  "rollback",
  "autorestart",
  "heal",
  "create",
  "restore",
]);
const MAKES_IT = new Set(["create", "restore"]);
const LISTED = new Set(["compose", "docker", "systemd"]);
const KEPT_MS = 90 * 86_400_000;

const targetOf = (row: { node_id: string; kind: string; name: string }) =>
  `${row.node_id}|${row.kind}|${row.name}`;

export function notFixed(
  rows: ActionRow[],
  later: ActionRow[],
  health: Health,
  now: number,
): ActionRow[] {
  return rows.filter((row) => {
    if (
      (row.status !== "failed" && row.status !== "expired") ||
      CHANGES_NOTHING.has(row.action) ||
      row.hidden_at ||
      Date.parse(row.requested_at) < now - KEPT_MS
    ) {
      return false;
    }
    const target = targetOf(row);
    const fixedSince = later.some(
      (next) =>
        next.status === "done" &&
        !CHANGES_NOTHING.has(next.action) &&
        targetOf(next) === target &&
        next.requested_at > row.requested_at,
    );
    if (fixedSince) return false;
    if (!LISTED.has(row.kind)) return true;
    const healthy = health.get(target);
    if (healthy === undefined) return MAKES_IT.has(row.action);
    return !(healthy && MAKES_IT_RUN.has(row.action));
  });
}

export async function loadEstate(db: D1Database, owner: string) {
  const owned = "node_id IN (SELECT id FROM nodes WHERE owner_user_id = ?)";
  const [stacks, services, addresses] = await Promise.all([
    db
      .prepare(
        `SELECT node_id, project, running, total, containers FROM stacks WHERE ${owned}`,
      )
      .bind(owner)
      .all<{
        node_id: string;
        project: string;
        running: number;
        total: number;
        containers: string | null;
      }>(),
    db
      .prepare(`SELECT node_id, kind, name, state FROM services WHERE ${owned}`)
      .bind(owner)
      .all<{
        node_id: string;
        kind: "systemd" | "docker";
        name: string;
        state: string;
      }>(),
    db
      .prepare(
        `SELECT node_id, hostname, project FROM web_addresses WHERE ${owned}`,
      )
      .bind(owner)
      .all<{ node_id: string; hostname: string; project: string }>(),
  ]);
  const servers = new Map<string, Required<OwnerServer>>();
  const health: Health = new Map();
  const server = (id: string) => {
    const found = servers.get(id) ?? {
      stacks: [],
      services: [],
      webAddresses: [],
    };
    servers.set(id, found);
    return found;
  };
  for (const stack of stacks.results) {
    server(stack.node_id).stacks.push({
      project: stack.project,
      containers: stack.containers
        ? (JSON.parse(stack.containers) as string[])
        : [],
    });
    health.set(
      targetOf({
        node_id: stack.node_id,
        kind: "compose",
        name: stack.project,
      }),
      stack.total > 0 && stack.running === stack.total,
    );
  }
  for (const service of services.results) {
    server(service.node_id).services.push({
      kind: service.kind,
      name: service.name,
    });
    health.set(targetOf(service), service.state === "running");
  }
  for (const address of addresses.results) {
    server(address.node_id).webAddresses.push({
      hostname: address.hostname,
      project: address.project,
    });
  }
  return { servers, health, server };
}
