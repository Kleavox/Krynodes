import { networkArgsValid, signedCommandSchema } from "@krynodes/protocol";
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

const ACTIONS = {
  trust: ["apply"],
  agent: ["update", "remove"],
  host: ["restart"],
  network: [],
} as const;

const actionSchema = z
  .strictObject({
    nodeId: z.string().min(1).max(64),
    id: z.string().min(1).max(64),
    kind: z.enum(["trust", "agent", "host", "network"]),
    name: z.string().min(1).max(128),
    action: z.string().min(1).max(64),
    title: z.string().min(1).max(200),
    signed: z.string().min(1).max(262144),
  })
  .refine(
    (value) =>
      value.kind === "network" ||
      (ACTIONS[value.kind] as readonly string[]).includes(value.action),
  );

function networkCommandHolds(action: z.infer<typeof actionSchema>): boolean {
  try {
    const signed = signedCommandSchema.parse(JSON.parse(action.signed));
    const command = JSON.parse(
      new TextDecoder().decode(fromB64url(signed.command)),
    ) as Record<string, unknown>;
    return (
      command.kind === "network" &&
      command.action === action.action &&
      command.id === action.id &&
      command.nodeId === action.nodeId &&
      networkArgsValid(action.action, command.args ?? {})
    );
  } catch {
    return false;
  }
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
    output: row.output,
    createdAt: row.created_at,
    finishedAt: row.finished_at,
  };
};

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
    return context.json(present(row!), 201);
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
