import { pokeSoon } from "../fleet/client";
import {
  KIND_VERBS,
  LOGS_AGENT,
  STACKS_AGENT,
  UNSIGNED_VERBS,
  compareVersions,
  isProtectedTarget,
  isValidTarget,
  signedCommandSchema,
} from "@krynodes/protocol";
import type { MiddlewareHandler } from "hono";
import { z } from "zod";

import { requestRefresh } from "../actions/inventory";
import { assertionUv } from "../lib/webauthn";
import {
  cancelStatement,
  createBatch,
  sweepStatements,
  UNIT_SQL,
  type ActionRow,
} from "../actions/store";
import { decodeJson } from "../lib/b64url";
import { readReport } from "../trust/fleet";
import {
  invalidRequest,
  readJson,
  type KrynodesApp,
  type KrynodesEnv,
} from "./shared";

const RECENT_MS = 24 * 3_600_000;
const HISTORY_PAGE = 50;

const actionRequestSchema = z.object({
  action: z.enum([
    "start",
    "stop",
    "restart",
    "deploy",
    "rollback",
    "reboot",
    "logs",
    "remove",
    "purge",
    "restore",
    "create",
    "autorestart",
    "manual",
  ]),
  mode: z.enum(["rolling", "parallel"]).default("rolling"),
  targets: z
    .array(
      z.object({
        id: z.string().uuid().optional(),
        nodeId: z.string().uuid(),
        kind: z.enum(["systemd", "docker", "compose", "host"]),
        name: z.string().min(1).max(128),
        signed: signedCommandSchema.optional(),
      }),
    )
    .min(1)
    .max(50),
});

const STACK_VERBS = new Set([
  "remove",
  "purge",
  "restore",
  "create",
  "autorestart",
  "manual",
]);

function minimumAgent(action: string, kind: string): string | null {
  if (action === "logs") return LOGS_AGENT;
  if (STACK_VERBS.has(action)) return STACKS_AGENT;
  if (kind === "compose" && ["start", "stop", "restart"].includes(action)) {
    return STACKS_AGENT;
  }
  return null;
}

const commandSchema = z.object({
  v: z.literal(1),
  id: z.string(),
  nodeId: z.string(),
  kind: z.string(),
  name: z.string(),
  action: z.string(),
});

const refreshSchema = z.object({
  nodeIds: z.array(z.string().uuid()).max(100).optional(),
});

function toActionRecord(row: ActionRow) {
  return {
    id: row.id,
    batchId: row.batch_id,
    position: row.position,
    mode: row.mode,
    nodeId: row.node_id,
    kind: row.kind,
    name: row.name,
    action: row.action,
    status: row.status,
    requestedBy: row.requested_by,
    requestedAt: row.requested_at,
    deliverableAt: row.deliverable_at,
    sentAt: row.sent_at,
    finishedAt: row.finished_at,
    exitCode: row.exit_code,
    output: row.output,
    deviceId: row.device_id,
  };
}

const targetKey = (target: { nodeId: string; kind: string; name: string }) =>
  `${target.nodeId}|${target.kind}|${target.name}`;

export function registerServiceRoutes(
  app: KrynodesApp,
  requireOperator: MiddlewareHandler<KrynodesEnv>,
): void {
  app.get("/api/services", requireOperator, async (context) => {
    const db = context.env.DB;
    const owner = context.get("identity").id;
    const now = Date.now();
    await db.batch(sweepStatements(db, now));
    const [nodes, services, actions] = await Promise.all([
      db
        .prepare(
          `SELECT id, inventory_at, refresh_requested_at, trust_report, docker
           FROM nodes WHERE owner_user_id = ? AND enrolled_at IS NOT NULL`,
        )
        .bind(owner)
        .all<{
          id: string;
          inventory_at: string | null;
          refresh_requested_at: string | null;
          trust_report: string | null;
          docker: string | null;
        }>(),
      db
        .prepare(
          `SELECT node_id, kind, name, state, since, system FROM services
           WHERE node_id IN (SELECT id FROM nodes WHERE owner_user_id = ?)
           ORDER BY node_id, kind, name`,
        )
        .bind(owner)
        .all<{
          node_id: string;
          kind: "systemd" | "docker";
          name: string;
          state: string;
          since: string | null;
          system: number;
        }>(),
      db
        .prepare(
          `SELECT * FROM actions
           WHERE node_id IN (SELECT id FROM nodes WHERE owner_user_id = ?)
             AND requested_at >= ?
           ORDER BY requested_at, position`,
        )
        .bind(owner, new Date(now - RECENT_MS).toISOString())
        .all<ActionRow>(),
    ]);
    const [stacks, removed] = await Promise.all([
      db
        .prepare(
          `SELECT node_id, project, directory, running, total, compose, rollback FROM stacks
           WHERE node_id IN (SELECT id FROM nodes WHERE owner_user_id = ?)
           ORDER BY node_id, project`,
        )
        .bind(owner)
        .all<{
          node_id: string;
          project: string;
          directory: string;
          running: number;
          total: number;
          compose: number;
          rollback: number;
        }>(),
      db
        .prepare(
          `SELECT node_id, project, directory, removed_at FROM removed_stacks
           WHERE node_id IN (SELECT id FROM nodes WHERE owner_user_id = ?)
           ORDER BY node_id, removed_at DESC`,
        )
        .bind(owner)
        .all<{
          node_id: string;
          project: string;
          directory: string;
          removed_at: string;
        }>(),
    ]);
    return context.json({
      nodes: nodes.results.map((node) => ({
        id: node.id,
        inventoryAt: node.inventory_at,
        refreshRequestedAt: node.refresh_requested_at,
        trust: readReport(node.trust_report),
        docker: node.docker,
        stacks: stacks.results
          .filter((stack) => stack.node_id === node.id)
          .map((stack) => ({
            project: stack.project,
            directory: stack.directory,
            running: stack.running,
            total: stack.total,
            compose: stack.compose === 1,
            rollback: stack.rollback === 1,
          })),
        removed: removed.results
          .filter((stack) => stack.node_id === node.id)
          .map((stack) => ({
            project: stack.project,
            directory: stack.directory,
            removedAt: stack.removed_at,
          })),
        services: services.results
          .filter((service) => service.node_id === node.id)
          .map((service) => ({
            kind: service.kind,
            name: service.name,
            state: service.state,
            since: service.since,
            system: service.system === 1,
          })),
      })),
      actions: actions.results.map((row) =>
        toActionRecord(row.action === "logs" ? { ...row, output: null } : row),
      ),
    });
  });

  app.get("/api/history", requireOperator, async (context) => {
    const [at, id] = (context.req.query("before") ?? "").split("|");
    const rows = await context.env.DB.prepare(
      `SELECT * FROM actions
       WHERE node_id IN (SELECT id FROM nodes WHERE owner_user_id = ?1)
         AND kind <> 'trust'
         AND (?2 IS NULL OR node_id = ?2)
         AND (?3 IS NULL OR requested_at < ?3 OR (requested_at = ?3 AND id < ?4))
       ORDER BY requested_at DESC, id DESC LIMIT ?5`,
    )
      .bind(
        context.get("identity").id,
        context.req.query("node") ?? null,
        at || null,
        id ?? "",
        HISTORY_PAGE + 1,
      )
      .all<ActionRow>();
    const page = rows.results.slice(0, HISTORY_PAGE);
    const last = page.at(-1);
    return context.json({
      actions: page.map((row) => ({
        ...toActionRecord(row),
        output: row.action === "logs" ? null : row.output,
      })),
      next:
        rows.results.length > HISTORY_PAGE && last
          ? `${last.requested_at}|${last.id}`
          : null,
    });
  });

  app.get("/api/actions/:id", requireOperator, async (context) => {
    const row = await context.env.DB.prepare(
      `SELECT * FROM actions WHERE id = ?
         AND node_id IN (SELECT id FROM nodes WHERE owner_user_id = ?)`,
    )
      .bind(context.req.param("id"), context.get("identity").id)
      .first<ActionRow>();
    if (!row) return context.json({ code: "NOT_FOUND" }, 404);
    return context.json({ action: toActionRecord(row) });
  });

  app.get("/api/nodes/:id/actions", requireOperator, async (context) => {
    const db = context.env.DB;
    const node = await db
      .prepare("SELECT id FROM nodes WHERE id = ? AND owner_user_id = ?")
      .bind(context.req.param("id"), context.get("identity").id)
      .first<{ id: string }>();
    if (!node) return context.json({ code: "NOT_FOUND" }, 404);
    await db.batch(sweepStatements(db, Date.now()));
    const rows = await db
      .prepare(
        `SELECT * FROM actions WHERE node_id = ? AND action <> 'logs'
         ORDER BY requested_at DESC, position DESC LIMIT 10`,
      )
      .bind(node.id)
      .all<ActionRow>();
    return context.json({ actions: rows.results.map(toActionRecord) });
  });

  app.post("/api/actions", requireOperator, async (context) => {
    const parsed = actionRequestSchema.safeParse(await readJson(context));
    if (!parsed.success) return invalidRequest(context);
    const { action, mode, targets } = parsed.data;
    const unsigned = (UNSIGNED_VERBS as readonly string[]).includes(action);
    const logs = action === "logs";
    if (
      new Set(targets.map(targetKey)).size !== targets.length ||
      targets.some(
        (target) =>
          !isValidTarget(target.kind, target.name) ||
          !(KIND_VERBS[target.kind] as readonly string[]).includes(action) ||
          (unsigned
            ? target.signed !== undefined
            : target.signed === undefined || target.id === undefined),
      )
    ) {
      return invalidRequest(context);
    }
    if (
      !unsigned &&
      targets.some((target) => {
        const command = commandSchema.safeParse(
          decodeJson(target.signed!.command),
        );
        return (
          !command.success ||
          command.data.id !== target.id ||
          command.data.nodeId !== target.nodeId ||
          command.data.kind !== target.kind ||
          command.data.name !== target.name ||
          command.data.action !== action
        );
      })
    ) {
      return context.json(
        {
          code: "SIGNATURE_MISMATCH",
          message: "The signed command does not match the request.",
        },
        400,
      );
    }
    if (
      !unsigned &&
      targets.some(
        (target) => !assertionUv(target.signed!.grant.authenticatorData),
      )
    ) {
      return context.json(
        {
          code: "FINGERPRINT_NEEDED",
          message:
            "This passkey did not verify a fingerprint. Use the fingerprint, or choose Use a phone in the passkey window.",
        },
        400,
      );
    }
    if (
      !logs &&
      targets.some((target) => isProtectedTarget(target.kind, target.name))
    ) {
      return context.json(
        {
          code: "PROTECTED_TARGET",
          message: "Krynodes never controls this service.",
        },
        422,
      );
    }

    const db = context.env.DB;
    const identity = context.get("identity");
    const now = Date.now();
    const wanted = new Set(targets.map((target) => target.nodeId));
    const nodeIds = JSON.stringify([...wanted]);
    const nodes = await db
      .prepare(
        `SELECT id, name, agent_version, docker FROM nodes
         WHERE owner_user_id = ? AND enrolled_at IS NOT NULL AND disabled_at IS NULL
           AND id IN (SELECT value FROM json_each(?))`,
      )
      .bind(identity.id, nodeIds)
      .all<{
        id: string;
        name: string;
        agent_version: string | null;
        docker: string | null;
      }>();
    if (nodes.results.length !== wanted.size) {
      return context.json(
        { code: "NOT_FOUND", message: "A server was not found." },
        404,
      );
    }
    const byId = new Map(nodes.results.map((node) => [node.id, node]));
    for (const target of targets) {
      const node = byId.get(target.nodeId)!;
      const minimum = minimumAgent(action, target.kind);
      if (
        minimum &&
        compareVersions(node.agent_version ?? "0.0.0", minimum) < 0
      ) {
        return context.json(
          {
            code: "AGENT_TOO_OLD",
            message: logs
              ? `Update the agent on ${node.name} to ${minimum} or newer to read logs.`
              : `Update the agent on ${node.name} to ${minimum} or newer.`,
          },
          422,
        );
      }
    }

    await db.batch(sweepStatements(db, now));
    const needServices = targets.some(
      (target) => target.kind === "systemd" || target.kind === "docker",
    );
    const needStacks = targets.some((target) => target.kind === "compose");
    const [services, stacks, watched, pending] = await Promise.all([
      needServices
        ? db
            .prepare(
              `SELECT node_id AS nodeId, kind, name FROM services
               WHERE node_id IN (SELECT value FROM json_each(?))`,
            )
            .bind(nodeIds)
            .all<{ nodeId: string; kind: string; name: string }>()
        : { results: [] },
      needStacks
        ? db
            .prepare(
              `SELECT node_id AS nodeId, project AS name, compose, rollback, 0 AS removed FROM stacks
               WHERE node_id IN (SELECT value FROM json_each(?1))
               UNION ALL
               SELECT node_id, project, 0, 0, 1 FROM removed_stacks
               WHERE node_id IN (SELECT value FROM json_each(?1))`,
            )
            .bind(nodeIds)
            .all<{
              nodeId: string;
              name: string;
              compose: number;
              rollback: number;
              removed: number;
            }>()
        : { results: [] },
      action === "autorestart"
        ? db
            .prepare(
              `SELECT node_id AS nodeId, ${UNIT_SQL} AS name FROM checks
               WHERE kind = 'SERVICE' AND node_id IN (SELECT value FROM json_each(?))`,
            )
            .bind(nodeIds)
            .all<{ nodeId: string; name: string }>()
        : { results: [] },
      db
        .prepare(
          `SELECT node_id AS nodeId, kind, name FROM actions
           WHERE status IN ('queued', 'sent') AND action <> 'logs'
             AND node_id IN (SELECT value FROM json_each(?))`,
        )
        .bind(nodeIds)
        .all<{ nodeId: string; kind: string; name: string }>(),
    ]);

    if (action === "create") {
      const taken = new Set(
        stacks.results.map((stack) => `${stack.nodeId}|${stack.name}`),
      );
      const used = targets.find((target) =>
        taken.has(`${target.nodeId}|${target.name}`),
      );
      if (used) {
        const waiting = stacks.results.some(
          (stack) =>
            stack.removed === 1 &&
            stack.nodeId === used.nodeId &&
            stack.name === used.name,
        );
        return context.json(
          {
            code: "STACK_EXISTS",
            message: waiting
              ? `A stack named ${used.name} waits in Removed on ${byId.get(used.nodeId)!.name}. Restore it or delete it permanently first.`
              : `${byId.get(used.nodeId)!.name} already runs a stack named ${used.name}.`,
          },
          409,
        );
      }
      const bare = targets.find(
        (target) => byId.get(target.nodeId)!.docker !== "ready",
      );
      if (bare) {
        return context.json(
          {
            code: "NO_DOCKER",
            message: `${byId.get(bare.nodeId)!.name} has no Docker with Compose.`,
          },
          422,
        );
      }
    } else if (action !== "manual") {
      const present = new Set([
        ...services.results.map(targetKey),
        ...stacks.results
          .filter((stack) =>
            stack.removed === 1
              ? action === "restore" || action === "purge"
              : action !== "restore" &&
                stack.compose === 1 &&
                (action !== "rollback" || stack.rollback === 1),
          )
          .map((stack) =>
            targetKey({
              nodeId: stack.nodeId,
              kind: "compose",
              name: stack.name,
            }),
          ),
        ...nodes.results.map((node) =>
          targetKey({ nodeId: node.id, kind: "host", name: "server" }),
        ),
      ]);
      if (targets.some((target) => !present.has(targetKey(target)))) {
        return context.json(
          {
            code: "UNKNOWN_TARGET",
            message: "A service is no longer on its server. Refresh the list.",
          },
          422,
        );
      }
    }
    if (action === "autorestart") {
      const checked = new Set(
        watched.results.map((check) => `${check.nodeId}|systemd|${check.name}`),
      );
      if (targets.some((target) => !checked.has(targetKey(target)))) {
        return context.json(
          {
            code: "NO_CHECK",
            message:
              "Add a SERVICE check for this unit first; it decides when to restart.",
          },
          422,
        );
      }
    }
    const busy = new Set(pending.results.map(targetKey));
    if (!logs && targets.some((target) => busy.has(targetKey(target)))) {
      return context.json(
        {
          code: "ACTION_PENDING",
          message: "An action for this service is still running.",
        },
        409,
      );
    }

    const batch = createBatch(db, {
      action,
      mode,
      targets,
      requestedBy: identity.email,
      now,
      deviceId: targets[0]?.signed?.grant.credentialId,
    });
    const credential = targets[0]?.signed?.grant.credentialId;
    const used = credential
      ? [
          db
            .prepare(
              "UPDATE devices SET last_used_at = ? WHERE id = ? AND owner_user_id = ?",
            )
            .bind(new Date(now).toISOString(), credential, identity.id),
        ]
      : [];
    try {
      await db.batch([...batch.statements, ...used]);
    } catch (error) {
      if (!String(error).includes("UNIQUE")) throw error;
      return context.json(
        {
          code: "ACTION_PENDING",
          message: "An action for this service is still running.",
        },
        409,
      );
    }
    pokeSoon(
      context,
      identity.id,
      targets.map((target) => target.nodeId),
    );
    return context.json(
      { batchId: batch.batchId, actions: batch.actions },
      201,
    );
  });

  app.post("/api/actions/:batchId/cancel", requireOperator, async (context) => {
    const db = context.env.DB;
    const now = Date.now();
    const [cancelled] = await db.batch([
      cancelStatement(
        db,
        context.req.param("batchId"),
        context.get("identity").id,
        now,
      ),
      ...sweepStatements(db, now),
    ]);
    return context.json({ cancelled: cancelled?.meta.changes ?? 0 });
  });

  app.post("/api/services/refresh", requireOperator, async (context) => {
    const parsed = refreshSchema.safeParse((await readJson(context)) ?? {});
    if (!parsed.success) return invalidRequest(context);
    const ownerId = context.get("identity").id;
    const refreshed = await requestRefresh(
      context.env.DB,
      ownerId,
      parsed.data.nodeIds,
      Date.now(),
    );
    pokeSoon(context, ownerId, refreshed);
    return context.json({ refreshed: refreshed.length }, 202);
  });
}
