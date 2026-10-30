import { QUARANTINE, type QuarantineEvent } from "@krynodes/protocol";

import type { StoppedMail, WarningMail } from "../lib/mail";
import { changeStatement } from "../routes/network";
import { quarantine, QUARANTINE_ACTOR } from "./quarantine";
import { readSettings } from "./settings";

export const WARNING_KINDS: readonly string[] = [
  "ssh-key",
  "ssh-login",
  "user",
  "sudo",
  "port",
  "rule",
  "firewall",
  "confinement",
  "quiet",
];

export interface Cutoff {
  nodeId: string;
  id: string;
  at: number;
}

const iso = (ms: number) => new Date(ms).toISOString();

export function warningOf(kind: string, detail: Record<string, string>) {
  switch (kind) {
    case "ssh-key":
      return `new SSH key for ${detail.user ?? "a user"}`;
    case "ssh-login":
      return `sign-in as ${detail.user ?? "an admin"} with an unknown key`;
    case "user":
      return `new user ${detail.user ?? ""}`.trim();
    case "sudo":
      return "new sudo rule";
    case "port":
      return `port ${detail.port ?? ""} opened outside Krynodes`.replace(
        "  ",
        " ",
      );
    case "rule":
      return "removed firewall rule";
    case "firewall":
      return "firewall rule added outside Krynodes";
    case "confinement":
      return `denial for ${detail.program ?? "a program"}`;
    default:
      return "quiet agent";
  }
}

const listed = (names: string[]) =>
  names.length < 2
    ? names.join("")
    : `${names.slice(0, -1).join(", ")} and ${names.at(-1)}`;

export function warningStatement(
  db: D1Database,
  warning: {
    nodeId: string;
    id: string;
    kind: string;
    detail: Record<string, string>;
    at: string;
    cutAt: number | null;
  },
) {
  return db
    .prepare(
      `INSERT OR IGNORE INTO warnings (node_id, id, kind, detail, at, cut_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      warning.nodeId,
      warning.id,
      warning.kind,
      JSON.stringify(warning.detail),
      warning.at,
      warning.cutAt === null ? null : iso(warning.cutAt),
    );
}

export interface Intake {
  acked: string[];
  cutoffs: Cutoff[];
  nodes: string[];
  quarantined: string[];
  warned: WarningMail[];
  stopped: StoppedMail[];
}

export async function intake(
  db: D1Database,
  input: { nodeId: string; events: QuarantineEvent[]; now: number },
): Promise<Intake> {
  const { nodeId, events, now } = input;
  const node = await db
    .prepare("SELECT owner_user_id AS owner, name FROM nodes WHERE id = ?")
    .bind(nodeId)
    .first<{ owner: string; name: string }>();
  const acked = events.map((event) => event.id);
  const taken: Intake = {
    acked,
    cutoffs: [],
    nodes: [],
    quarantined: [],
    warned: [],
    stopped: [],
  };
  if (!node) return taken;
  const settings = await readSettings(db, node.owner);
  const statements: D1PreparedStatement[] = [];
  const timed: (Cutoff | null)[] = [];
  const warned: (WarningMail | null)[] = [];
  const stopped: (StoppedMail | null)[] = [];
  const knocks: { from: string; count: number }[] = [];
  const strong: string[] = [];
  for (const event of events) {
    if (event.kind === "confinement" && event.detail.strong === "1") {
      strong.push(
        event.detail.what || "SELinux or AppArmor changed outside Krynodes",
      );
      continue;
    }
    if (event.kind === "knock") {
      knocks.push({
        from: event.detail.from ?? "",
        count: Number(event.detail.count) || 0,
      });
      continue;
    }
    if (event.kind === "stack" && event.detail.stopped === "true") {
      const project = event.detail.stack ?? "";
      const denied = event.detail.why === "confinement";
      const tried = denied
        ? [event.detail.wanted ?? ""].filter(Boolean)
        : (event.detail.tried ?? "").split(" ").filter(Boolean);
      statements.push(
        db
          .prepare(
            `INSERT INTO stopped_stacks (node_id, project, at, tried, count, why) VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT (node_id, project) DO UPDATE SET at = excluded.at, tried = excluded.tried,
               count = excluded.count, why = excluded.why
             WHERE stopped_stacks.at <> excluded.at`,
          )
          .bind(
            nodeId,
            project,
            event.at,
            JSON.stringify(tried),
            Number(event.detail.count) || tried.length,
            denied ? "confinement" : null,
          ),
        changeStatement(db, {
          owner: node.owner,
          at: iso(now),
          change: `Stop ${project} on ${node.name}`,
          detail: denied
            ? `SELinux or AppArmor denied ${event.detail.program || "a container"} ${event.detail.wanted ?? ""}`.trim()
            : `A container tried ${event.detail.count ?? "--"} places it was not given`,
          requestedBy: QUARANTINE_ACTOR,
          deviceId: null,
          nodes: [nodeId],
          joins: [],
          leaves: [],
        }),
      );
      timed.push(null, null);
      warned.push(null, null);
      stopped.push(
        {
          nodeId,
          nodeName: node.name,
          project,
          count: Number(event.detail.count) || tried.length,
          tried: tried.slice(0, 4),
          at: event.at,
          ...(denied
            ? {
                why: "confinement" as const,
                program: event.detail.program ?? "",
              }
            : {}),
        },
        null,
      );
      continue;
    }
    const warns = WARNING_KINDS.includes(event.kind);
    const cutAt =
      warns && settings.cutoff !== null ? now + settings.cutoff * 60_000 : null;
    statements.push(
      warningStatement(db, {
        nodeId,
        id: event.id,
        kind: event.kind,
        detail: event.detail,
        at: event.at,
        cutAt,
      }),
    );
    timed.push(cutAt === null ? null : { nodeId, id: event.id, at: cutAt });
    warned.push(
      warns
        ? {
            nodeId,
            nodeName: node.name,
            kind: event.kind,
            detail: event.detail,
            at: event.at,
            cutAt,
          }
        : null,
    );
    stopped.push(null);
  }
  const results = statements.length > 0 ? await db.batch(statements) : [];
  const fresh = <T>(list: (T | null)[]) =>
    list.flatMap((entry, index) =>
      entry && (results[index]?.meta.changes ?? 0) > 0 ? [entry] : [],
    );
  taken.cutoffs = fresh(timed);
  taken.warned = fresh(warned);
  taken.stopped = fresh(stopped);
  for (const knock of knocks) {
    const started = await knocked(
      db,
      node.owner,
      nodeId,
      knock,
      settings.agree,
      now,
    );
    taken.nodes.push(...started);
    if (started[0]) taken.quarantined.push(started[0]);
  }
  if (strong[0] !== undefined) {
    const started = await quarantine(db, { nodeId, why: strong[0], now });
    taken.nodes.push(...started.nodes);
    if (started.started) taken.quarantined.push(nodeId);
  }
  return taken;
}

export async function cutOffWarning(
  db: D1Database,
  nodeId: string,
  id: string,
): Promise<{ nodes: string[]; quarantined: string[] }> {
  const warning = await db
    .prepare(
      `SELECT w.kind, w.detail, w.cut_at, s.cutoff FROM warnings w
       JOIN nodes n ON n.id = w.node_id
       LEFT JOIN quarantine_settings s ON s.owner_user_id = n.owner_user_id
       WHERE w.node_id = ? AND w.id = ? AND w.answer IS NULL AND w.cut_at IS NOT NULL`,
    )
    .bind(nodeId, id)
    .first<{
      kind: string;
      detail: string;
      cut_at: string;
      cutoff: number | null;
    }>();
  if (!warning) return { nodes: [], quarantined: [] };
  const cut = Date.parse(warning.cut_at);
  await db
    .prepare(
      `UPDATE warnings SET answer = 'cut-off', answered_at = ?, answered_by = ?
       WHERE node_id = ? AND id = ? AND answer IS NULL`,
    )
    .bind(warning.cut_at, QUARANTINE_ACTOR, nodeId, id)
    .run();
  const minutes = warning.cutoff ?? QUARANTINE.defaults.cutoff;
  const started = await quarantine(db, {
    nodeId,
    why: `Nobody said the ${warningOf(warning.kind, JSON.parse(warning.detail) as Record<string, string>)} was theirs within ${minutes} minutes`,
    now: cut,
  });
  return {
    nodes: started.nodes,
    quarantined: started.started ? [nodeId] : [],
  };
}

async function knocked(
  db: D1Database,
  owner: string,
  reporter: string,
  knock: { from: string; count: number },
  agree: number,
  now: number,
): Promise<string[]> {
  const members = (
    await db
      .prepare(
        `SELECT m.node_id, m.address FROM network_members m JOIN nodes n ON n.id = m.node_id
         WHERE n.owner_user_id = ? AND m.state = 'in'`,
      )
      .bind(owner)
      .all<{ node_id: string; address: string | null }>()
  ).results;
  const suspect = members.find(
    (member) => member.address === knock.from && member.node_id !== reporter,
  );
  if (!suspect) return [];
  const since = iso(now - QUARANTINE.agreeMinutes * 60_000);
  await db
    .prepare(
      `INSERT OR REPLACE INTO knocks (suspect, reporter, at, count) VALUES (?, ?, ?, ?)`,
    )
    .bind(suspect.node_id, reporter, iso(now), knock.count)
    .run();
  const reporters = (
    await db
      .prepare(
        `SELECT n.name, k.count FROM knocks k JOIN nodes n ON n.id = k.reporter
         WHERE k.suspect = ? AND k.at >= ?
         ORDER BY n.name`,
      )
      .bind(suspect.node_id, since)
      .all<{ name: string; count: number }>()
  ).results;
  if (reporters.length < Math.min(agree, members.length - 1)) return [];
  const most = Math.max(...reporters.map((entry) => entry.count));
  const started = await quarantine(db, {
    nodeId: suspect.node_id,
    why: `${listed(reporters.map((entry) => entry.name))} saw it knock on ${most} closed ports in one minute`,
    now,
  });
  return started.nodes;
}
