import { agentSupported, QUARANTINE } from "@krynodes/protocol";

import { createBatch } from "../actions/store";
import { toB64url } from "../lib/b64url";
import type { QuarantineMail } from "../lib/mail";
import { changeStatement } from "../routes/network";

export const QUARANTINE_ACTOR = "Quarantine";

const READS = JSON.stringify(QUARANTINE.readVerbs);

const iso = (ms: number) => new Date(ms).toISOString();

const attach = (value: Record<string, string>) =>
  toB64url(new TextEncoder().encode(JSON.stringify(value)));

export interface Timeline {
  batches: string[];
  tailnet: string[];
  dropped: string[];
  removed?: { at: string; by: string | null };
}

export const holdStatement = (db: D1Database, nodeId: string, at: string) =>
  db
    .prepare(
      `UPDATE actions SET status = 'cancelled', finished_at = ?1, attachment = NULL
       WHERE node_id = ?2 AND status = 'queued'
         AND action NOT IN (SELECT value FROM json_each(?3))
         AND NOT (action = 'lockdown' AND requested_by = ?4)`,
    )
    .bind(at, nodeId, READS, QUARANTINE_ACTOR);

export async function quarantinedNodes(
  db: D1Database,
  nodeIds: string[],
): Promise<Map<string, string>> {
  if (nodeIds.length === 0) return new Map();
  const rows = await db
    .prepare(
      `SELECT q.node_id, n.name FROM quarantines q JOIN nodes n ON n.id = q.node_id
       WHERE q.released_at IS NULL AND q.node_id IN (SELECT value FROM json_each(?))`,
    )
    .bind(JSON.stringify(nodeIds))
    .all<{ node_id: string; name: string }>();
  return new Map(rows.results.map((row) => [row.node_id, row.name]));
}

export async function quarantineRefusal(
  db: D1Database,
  nodeIds: string[],
  action: string,
): Promise<{ code: "QUARANTINED"; message: string } | null> {
  if ((QUARANTINE.readVerbs as readonly string[]).includes(action)) return null;
  const [name] = (await quarantinedNodes(db, nodeIds)).values();
  return name === undefined
    ? null
    : {
        code: "QUARANTINED",
        message: `${name} is quarantined. Only reading works there.`,
      };
}

interface Suspect {
  id: string;
  owner_user_id: string;
  name: string;
  tailscale: string | null;
  key: string | null;
  address: string | null;
  member: string | null;
}

function tailnetOf(text: string | null): string[] {
  try {
    const report = JSON.parse(text ?? "null") as {
      addresses?: unknown;
    } | null;
    return Array.isArray(report?.addresses)
      ? report.addresses.filter(
          (address): address is string => typeof address === "string",
        )
      : [];
  } catch {
    return [];
  }
}

export async function quarantine(
  db: D1Database,
  input: {
    nodeId: string;
    why: string;
    now: number;
    by?: { change: string; requestedBy: string };
  },
): Promise<{ started: boolean; nodes: string[] }> {
  const suspect = await db
    .prepare(
      `SELECT n.id, n.owner_user_id, n.name, n.tailscale, m.key, m.address, m.state AS member
       FROM nodes n LEFT JOIN network_members m ON m.node_id = n.id
       WHERE n.id = ? AND NOT EXISTS (
         SELECT 1 FROM quarantines WHERE node_id = n.id AND released_at IS NULL)`,
    )
    .bind(input.nodeId)
    .first<Suspect>();
  if (!suspect) return { started: false, nodes: [] };
  const others = (
    await db
      .prepare(
        `SELECT n.id, n.agent_version, m.state AS member FROM nodes n
         LEFT JOIN network_members m ON m.node_id = n.id
         WHERE n.owner_user_id = ? AND n.id <> ? AND n.enrolled_at IS NOT NULL
           AND n.disabled_at IS NULL
         ORDER BY m.address IS NULL, m.address, n.name`,
      )
      .bind(suspect.owner_user_id, suspect.id)
      .all<{
        id: string;
        agent_version: string | null;
        member: string | null;
      }>()
  ).results;
  const at = iso(input.now);
  const timeline: Timeline = { batches: [], tailnet: [], dropped: [] };
  const statements: D1PreparedStatement[] = [holdStatement(db, suspect.id, at)];
  const queue = (batch: ReturnType<typeof createBatch>) => {
    timeline.batches.push(batch.batchId);
    statements.push(...batch.statements);
  };
  queue(
    createBatch(db, {
      action: "lockdown",
      mode: "parallel",
      targets: [{ nodeId: suspect.id, kind: "host", name: "server" }],
      requestedBy: QUARANTINE_ACTOR,
      now: input.now,
    }),
  );
  const members = others.filter((other) => other.member === "in");
  if (suspect.member === "in" && suspect.key && suspect.address) {
    timeline.dropped = members.map((member) => member.id);
    if (members.length > 0) {
      queue(
        createBatch(db, {
          action: "drop",
          mode: "parallel",
          targets: members.map((member) => ({
            nodeId: member.id,
            kind: "network",
            name: "kry0",
            attachment: attach({
              node: suspect.id,
              key: suspect.key!,
              address: suspect.address!,
            }),
          })),
          requestedBy: QUARANTINE_ACTOR,
          now: input.now,
        }),
      );
    }
    statements.push(
      db
        .prepare(
          `INSERT OR IGNORE INTO network_blocked (owner_user_id, key, node_id, at)
           VALUES (?, ?, ?, ?)`,
        )
        .bind(suspect.owner_user_id, suspect.key, suspect.id, at),
    );
  }
  timeline.tailnet = tailnetOf(suspect.tailscale);
  const servers = others.filter((other) => agentSupported(other.agent_version));
  if (timeline.tailnet.length > 0 && servers.length > 0) {
    queue(
      createBatch(db, {
        action: "block",
        mode: "parallel",
        targets: servers.map((server) => ({
          nodeId: server.id,
          kind: "host",
          name: "tailscale",
          attachment: attach({ addresses: timeline.tailnet.join(" ") }),
        })),
        requestedBy: QUARANTINE_ACTOR,
        now: input.now,
      }),
    );
  }
  statements.unshift(
    db
      .prepare(
        `INSERT INTO quarantines (id, node_id, why, at, timeline) VALUES (?, ?, ?, ?, ?)`,
      )
      .bind(
        crypto.randomUUID(),
        suspect.id,
        input.why,
        at,
        JSON.stringify(timeline),
      ),
  );
  statements.push(
    changeStatement(db, {
      owner: suspect.owner_user_id,
      at,
      change: input.by?.change ?? `Quarantine ${suspect.name}`,
      detail: input.why,
      requestedBy: input.by?.requestedBy ?? QUARANTINE_ACTOR,
      deviceId: null,
      nodes: [suspect.id, ...members.map((member) => member.id)],
      joins: [],
      leaves: [],
    }),
  );
  try {
    await db.batch(statements);
  } catch (error) {
    if (String(error).includes("UNIQUE")) return { started: false, nodes: [] };
    throw error;
  }
  return {
    started: true,
    nodes: [suspect.id, ...servers.map((server) => server.id)],
  };
}

export async function trustedBy(
  db: D1Database,
  owner: string,
  nodeId: string,
): Promise<
  { nodeId: string; nodeName: string; project: string; port: string }[]
> {
  const stacks = await db
    .prepare(
      `SELECT s.node_id, n.name, s.project, s.network FROM stacks s
       JOIN nodes n ON n.id = s.node_id
       WHERE n.owner_user_id = ? AND s.node_id <> ? AND s.network IS NOT NULL
       ORDER BY n.name, s.project`,
    )
    .bind(owner, nodeId)
    .all<{ node_id: string; name: string; project: string; network: string }>();
  return stacks.results.flatMap((stack) => {
    let serves: { port: string; to?: string[] }[] = [];
    try {
      serves =
        (JSON.parse(stack.network) as { serves?: typeof serves }).serves ?? [];
    } catch {
      return [];
    }
    return serves
      .filter((serve) => serve.to?.includes(nodeId))
      .map((serve) => ({
        nodeId: stack.node_id,
        nodeName: stack.name,
        project: stack.project,
        port: serve.port,
      }));
  });
}

export async function quarantineReport(
  db: D1Database,
  nodeId: string,
): Promise<QuarantineMail | null> {
  const row = await db
    .prepare(
      `SELECT q.why, q.at, q.timeline, n.name, n.vault, n.owner_user_id AS owner,
              (SELECT COUNT(*) FROM stacks WHERE node_id = n.id) AS stacks
       FROM quarantines q JOIN nodes n ON n.id = q.node_id
       WHERE q.node_id = ? AND q.released_at IS NULL`,
    )
    .bind(nodeId)
    .first<{
      why: string;
      at: string;
      timeline: string;
      name: string;
      vault: string | null;
      owner: string;
      stacks: number;
    }>();
  if (!row) return null;
  const timeline = JSON.parse(row.timeline) as Timeline;
  const [dropped, trusted] = await Promise.all([
    db
      .prepare(
        "SELECT name FROM nodes WHERE id IN (SELECT value FROM json_each(?)) ORDER BY name",
      )
      .bind(JSON.stringify(timeline.dropped))
      .all<{ name: string }>(),
    trustedBy(db, row.owner, nodeId),
  ]);
  return {
    nodeId,
    nodeName: row.name,
    why: row.why,
    at: row.at,
    droppedBy: dropped.results.map((entry) => entry.name),
    stacks: row.stacks,
    pieces: row.vault ? 1 : 0,
    trusted: trusted.length,
    tailnet: timeline.tailnet.length > 0,
  };
}
