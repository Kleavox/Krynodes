import {
  COMMAND_ACTIONS,
  COMMAND_KINDS,
  isProtected,
  isValidTarget,
  networkArgsValid,
  signedCommandSchema,
  STACK_ACTIONS,
  stackArgsValid,
  type StackKind,
} from "@krynodes/protocol";
import { z } from "zod";

import type { KrynodesApp } from "../env";
import { announce, sendCommand } from "../fleet/client";
import { fromB64url } from "../lib/b64url";
import {
  invalidRequest,
  isMember,
  isUnique,
  networkMember,
  readJson,
} from "./shared";

const NO_ANSWER_MS = 30 * 60_000;
const MAX_LIMIT = 50;
const OUTPUT_KEPT_MS = 24 * 60 * 60_000;

const actionSchema = z
  .strictObject({
    nodeId: z.string().min(1).max(64),
    id: z.string().min(1).max(64),
    kind: z.enum(COMMAND_KINDS),
    name: z.string().min(1).max(128),
    action: z.string().min(1).max(64),
    title: z.string().min(1).max(200),
    signed: z.string().min(1).max(262144),
  })
  .refine((value) => COMMAND_ACTIONS[value.kind].includes(value.action));

type Action = z.infer<typeof actionSchema>;

const isStackKind = (kind: string): kind is StackKind =>
  Object.hasOwn(STACK_ACTIONS, kind);

function signedCommandOf(action: Action): Record<string, unknown> | null {
  try {
    const signed = signedCommandSchema.parse(JSON.parse(action.signed));
    const command = JSON.parse(
      new TextDecoder().decode(fromB64url(signed.command)),
    ) as Record<string, unknown>;
    return command.kind === action.kind &&
      command.action === action.action &&
      command.id === action.id &&
      command.nodeId === action.nodeId
      ? command
      : null;
  } catch {
    return null;
  }
}

function networkCommandHolds(action: Action): boolean {
  const command = signedCommandOf(action);
  return (
    command !== null && networkArgsValid(action.action, command.args ?? {})
  );
}

interface Listed {
  stacks: { project: string }[];
  removed: { project: string }[];
}

async function stackRefusal(
  db: D1Database,
  action: Action,
  kind: StackKind,
  server: string,
): Promise<string | null> {
  const { name } = action;
  const command = signedCommandOf(action);
  if (!command || command.name !== name) {
    return `The signed command does not match this request for ${server}.`;
  }
  if (!isValidTarget(kind, name)) {
    return `${server} has no ${kind} that could be named ${name}.`;
  }
  const args = "args" in command ? command.args : {};
  if (!stackArgsValid(kind, action.action, args)) {
    return `${server} would refuse the settings sent with this ${kind} ${action.action}.`;
  }
  if ((kind === "container" || kind === "unit") && isProtected(kind, name)) {
    return `${name} is protected on ${server}.`;
  }
  if (kind !== "stack") return null;
  const stored = await db
    .prepare("SELECT body FROM node_inventory WHERE node_id = ?")
    .bind(action.nodeId)
    .first<{ body: string }>();
  if (!stored) return `${server} has not reported its Docker inventory yet.`;
  const listed = JSON.parse(stored.body) as Listed;
  const runs = listed.stacks.some((stack) => stack.project === name);
  if (action.action === "create") {
    if (runs) return `A stack named ${name} already runs on ${server}.`;
    if (listed.removed.some((stack) => stack.project === name)) {
      return `A stack named ${name} waits in Removed on ${server}.`;
    }
    return null;
  }
  if (action.action === "restore" || action.action === "purge") return null;
  return runs ? null : `${server} has no stack named ${name}.`;
}

export async function clearOldOutput(db: D1Database, now = Date.now()) {
  await db
    .prepare(
      "UPDATE actions SET output = NULL WHERE output IS NOT NULL AND created_at < ?",
    )
    .bind(new Date(now - OUTPUT_KEPT_MS).toISOString())
    .run();
}

interface ActionRow {
  id: string;
  node_id: string;
  kind: string;
  name: string;
  action: string;
  title: string;
  status: string;
  message: string | null;
  output: string | null;
  created_at: string;
  finished_at: string | null;
  node_name: string;
}

const present = (row: ActionRow, now = Date.now()) => {
  const silent =
    (row.status === "sent" || row.status === "running") &&
    now - Date.parse(row.created_at) > NO_ANSWER_MS;
  return {
    id: row.id,
    nodeId: row.node_id,
    kind: row.kind,
    name: row.name,
    action: row.action,
    title: row.title,
    status: silent ? "failed" : row.status,
    message: silent ? `No answer from ${row.node_name}.` : row.message,
    createdAt: row.created_at,
    finishedAt: row.finished_at,
  };
};

const withOutput = (row: ActionRow, now = Date.now()) => ({
  ...present(row, now),
  output: now - Date.parse(row.created_at) > OUTPUT_KEPT_MS ? null : row.output,
});

const SELECT =
  "SELECT a.*, n.name AS node_name FROM actions a JOIN nodes n ON n.id = a.node_id";

export function registerActionRoutes(app: KrynodesApp): void {
  app.post("/api/actions", async (context) => {
    const body = actionSchema.safeParse(await readJson(context));
    if (
      !body.success ||
      (body.data.kind === "network" && !networkCommandHolds(body.data))
    ) {
      return invalidRequest(context);
    }
    const { nodeId, id, kind, name, action, title, signed } = body.data;
    const db = context.env.DB;
    const node = await db
      .prepare("SELECT name FROM nodes WHERE id = ?")
      .bind(nodeId)
      .first<{ name: string }>();
    if (!node) {
      return context.json(
        { code: "NOT_FOUND", message: "The server was not found." },
        404,
      );
    }
    const refusal = isStackKind(kind)
      ? await stackRefusal(db, body.data, kind, node.name)
      : null;
    if (refusal) {
      return context.json({ code: "REFUSED", message: refusal }, 400);
    }
    if (
      kind === "agent" &&
      action === "remove" &&
      (await isMember(db, nodeId))
    ) {
      return networkMember(context, node.name);
    }
    if (kind === "network" && action === "prepare") {
      const request = await db
        .prepare("SELECT ready, reason FROM network_members WHERE node_id = ?")
        .bind(nodeId)
        .first<{ ready: number; reason: string | null }>();
      if (request?.ready !== 1) {
        return context.json(
          {
            code: "NOT_READY",
            message: request?.reason
              ? `${node.name} cannot join: ${request.reason}`
              : `${node.name} has not reported whether it can join yet.`,
          },
          409,
        );
      }
    }
    try {
      await db
        .prepare(
          "INSERT INTO actions (id, node_id, kind, name, action, title, status, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'sent', ?7)",
        )
        .bind(id, nodeId, kind, name, action, title, new Date().toISOString())
        .run();
    } catch (error) {
      if (!isUnique(error)) throw error;
      return context.json(
        { code: "ACTION_EXISTS", message: "This action was already sent." },
        409,
      );
    }
    let sent = false;
    try {
      sent = await sendCommand(context.env, nodeId, {
        type: "command",
        id,
        kind,
        name,
        action,
        signed,
      });
    } finally {
      if (!sent)
        await db.prepare("DELETE FROM actions WHERE id = ?").bind(id).run();
    }
    if (!sent) {
      return context.json(
        { code: "OFFLINE", message: `${node.name} is offline.` },
        409,
      );
    }
    await announce(context.env, ["fleet"]);
    const row = await db
      .prepare(`${SELECT} WHERE a.id = ?`)
      .bind(id)
      .first<ActionRow>();
    return context.json(withOutput(row!), 201);
  });

  app.get("/api/actions/:id", async (context) => {
    const row = await context.env.DB.prepare(`${SELECT} WHERE a.id = ?`)
      .bind(context.req.param("id"))
      .first<ActionRow>();
    if (!row) {
      return context.json(
        { code: "NOT_FOUND", message: "The action was not found." },
        404,
      );
    }
    return context.json(withOutput(row));
  });

  app.get("/api/actions", async (context) => {
    const node = context.req.query("node");
    const asked = Number(context.req.query("limit"));
    const limit =
      Number.isInteger(asked) && asked >= 1
        ? Math.min(asked, MAX_LIMIT)
        : MAX_LIMIT;
    const rows = await context.env.DB.prepare(
      `${SELECT} WHERE (?1 IS NULL OR a.node_id = ?1) ORDER BY a.created_at DESC, a.rowid DESC LIMIT ?2`,
    )
      .bind(node ?? null, limit)
      .all<ActionRow>();
    const now = Date.now();
    return context.json(rows.results.map((row) => present(row, now)));
  });
}
