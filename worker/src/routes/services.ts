import { pokeSoon } from "../fleet/client";
import {
  FEATURE_AGENT,
  KIND_VERBS,
  MIN_AGENT_VERSION,
  RECIPES,
  UNSIGNED_VERBS,
  agentHasFeatures,
  agentSupported,
  hostVerbFits,
  isProtectedTarget,
  isValidTarget,
  networkArgsValid,
  signedCommandSchema,
} from "@krynodes/protocol";
import type { MiddlewareHandler } from "hono";
import { z } from "zod";

import { requestRefresh } from "../actions/inventory";
import { assertionUv } from "../lib/webauthn";
import {
  cancelStatement,
  createBatch,
  QUESTIONS,
  SEALED_VERBS,
  sweepStatements,
  UNIT_SQL,
  type ActionRow,
} from "../actions/store";
import { decodeJson, toB64url } from "../lib/b64url";
import { filterListeners, type Finding, type Listener } from "../lib/ranges";
import { liveRange, readNetwork } from "../network/document";
import { networkMember } from "./admin";
import { readPrivateRanges } from "./settings";
import { ownersRefusal } from "../trust/approval";
import { loadFleet, readReport } from "../trust/fleet";
import {
  invalidRequest,
  readJson,
  type KrynodesApp,
  type KrynodesEnv,
} from "./shared";

const RECENT_MS = 24 * 3_600_000;

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
    "edit",
    "read",
    "adopt",
    "apply",
    "undo",
    "lockdown",
    "unlock",
    "scan",
    "install",
    "uninstall",
    "signin",
    "refresh",
    "find",
    "preview",
    "upgrade",
    "hold",
    "unhold",
    "addrepo",
    "droprepo",
    "inspect",
    "probe",
    "test",
    "prepare",
    "unprepare",
    "rekey",
  ]),
  mode: z.enum(["rolling", "parallel"]).default("rolling"),
  targets: z
    .array(
      z.object({
        id: z.string().uuid().optional(),
        nodeId: z.string().uuid(),
        kind: z.enum([
          "systemd",
          "docker",
          "compose",
          "host",
          "apt",
          "network",
        ]),
        name: z.string().min(1).max(128),
        signed: signedCommandSchema.optional(),
        args: z.record(z.string().max(64), z.string()).optional(),
      }),
    )
    .min(1)
    .max(50),
  then: z.literal("delete").optional(),
});

const OWN_STACK = /^\/var\/lib\/kry-exec\/compose\/[^/]+$/u;

export const READ_ONLY = new Set([
  "logs",
  "read",
  "scan",
  "refresh",
  "find",
  "preview",
  "inspect",
  "probe",
  "test",
]);

const MAX_ASKED_BYTES = 4096;

const askedAttachment = (args: Record<string, string> | undefined) => {
  if (args === undefined) return undefined;
  const bytes = new TextEncoder().encode(JSON.stringify(args));
  return bytes.length > MAX_ASKED_BYTES ? null : toB64url(bytes);
};

const needsFeatures = (target: { kind: string; name: string }) =>
  target.kind === "apt" ||
  target.kind === "network" ||
  (target.kind === "host" && target.name === "tailscale");

const askedFits = (
  kind: string,
  action: string,
  args: Record<string, string>,
) =>
  askedAttachment(args) !== null &&
  (kind === "apt" || (kind === "network" && networkArgsValid(action, args)));

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

export function toActionRecord(row: ActionRow) {
  if (SEALED_VERBS.includes(row.action)) row = { ...row, output: null };
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
    progress: parsed(row.progress ?? null),
  };
}

function securityReport(
  text: string | null,
  ranges: string[],
  network: string | null,
): unknown {
  const report = parsed(text) as {
    findings?: unknown;
    listeners?: Listener[];
  } | null;
  if (!report) return report;
  const { listeners: _, ...shown } = Array.isArray(report.findings)
    ? filterListeners(
        report as { findings: Finding[]; listeners?: Listener[] },
        ranges,
        network ?? undefined,
      )
    : report;
  return shown;
}

function parsed(text: string | null): unknown {
  if (text === null) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
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
    const [ranges, network] = await Promise.all([
      readPrivateRanges(db, owner),
      readNetwork(db, owner).then(liveRange),
    ]);
    const [nodes, services, actions] = await Promise.all([
      db
        .prepare(
          `SELECT id, inventory_at, refresh_requested_at, trust_report, docker,
                  seal_key, security, vault
           FROM nodes WHERE owner_user_id = ? AND enrolled_at IS NOT NULL AND disabled_at IS NULL`,
        )
        .bind(owner)
        .all<{
          id: string;
          inventory_at: string | null;
          refresh_requested_at: string | null;
          trust_report: string | null;
          docker: string | null;
          seal_key: string | null;
          security: string | null;
          vault: string | null;
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
    const [stacks, removed, addresses] = await Promise.all([
      db
        .prepare(
          `SELECT node_id, project, directory, running, total, compose, rollback, access, public, containers, network FROM stacks
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
          access: string | null;
          public: string | null;
          containers: string | null;
          network: string | null;
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
      db
        .prepare(
          `SELECT hostname, node_id, project, service, port, mode, path FROM web_addresses
           WHERE node_id IN (SELECT id FROM nodes WHERE owner_user_id = ?)
           ORDER BY hostname`,
        )
        .bind(owner)
        .all<{
          hostname: string;
          node_id: string;
          project: string;
          service: string;
          port: number;
          mode: string;
          path: string | null;
        }>(),
    ]);
    return context.json({
      nodes: nodes.results.map((node) => ({
        id: node.id,
        inventoryAt: node.inventory_at,
        refreshRequestedAt: node.refresh_requested_at,
        trust: readReport(node.trust_report),
        docker: node.docker,
        sealKey: node.seal_key,
        security: securityReport(node.security, ranges, network),
        vault: parsed(node.vault),
        webAddresses: addresses.results
          .filter((address) => address.node_id === node.id)
          .map(({ node_id: _, ...address }) => address),
        stacks: stacks.results
          .filter((stack) => stack.node_id === node.id)
          .map((stack) => ({
            project: stack.project,
            directory: stack.directory,
            running: stack.running,
            total: stack.total,
            compose: stack.compose === 1,
            rollback: stack.rollback === 1,
            access: stack.access,
            public: (parsed(stack.public) as string[] | null) ?? [],
            containers: (parsed(stack.containers) as string[] | null) ?? [],
            network: parsed(stack.network),
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
        toActionRecord(
          READ_ONLY.has(row.action) ? { ...row, output: null } : row,
        ),
      ),
    });
  });

  app.get("/api/cloudflare", requireOperator, async (context) => {
    const db = context.env.DB;
    const owner = context.get("identity").id;
    const [settings, expiry] = await Promise.all([
      db
        .prepare("SELECT zone, set_id FROM cloudflare WHERE owner_user_id = ?")
        .bind(owner)
        .first<{ zone: string; set_id: string | null }>(),
      db
        .prepare(
          `SELECT MAX(expires_at) AS expires FROM web_addresses
           WHERE node_id IN (SELECT id FROM nodes WHERE owner_user_id = ?)`,
        )
        .bind(owner)
        .first<{ expires: string | null }>(),
    ]);
    const host = new URL(context.env.PUBLIC_ORIGIN).hostname;
    return context.json({
      zone: settings?.zone ?? host.split(".").slice(1).join("."),
      setId: settings?.set_id ?? null,
      aud: context.env.ACCESS_AUD ?? null,
      expiresAt: expiry?.expires ?? null,
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
    const [rows, network] = await Promise.all([
      db
        .prepare(
          `SELECT * FROM actions WHERE node_id = ?1
             AND action <> 'logs' AND action NOT IN (SELECT value FROM json_each(?2))
           ORDER BY requested_at DESC, position DESC LIMIT 10`,
        )
        .bind(node.id, JSON.stringify(QUESTIONS))
        .all<ActionRow>(),
      db
        .prepare(
          `SELECT id, at, requested_by, device_id,
                  CASE WHEN EXISTS (SELECT 1 FROM json_each(joins) WHERE value = ?1)
                    THEN 'Joined Private Network' ELSE 'Left Private Network' END AS change
           FROM network_changes
           WHERE owner_user_id = ?2
             AND (EXISTS (SELECT 1 FROM json_each(joins) WHERE value = ?1)
               OR EXISTS (SELECT 1 FROM json_each(leaves) WHERE value = ?1))
           ORDER BY at DESC, id DESC LIMIT 10`,
        )
        .bind(node.id, context.get("identity").id)
        .all<{
          id: string;
          at: string;
          requested_by: string;
          device_id: string | null;
          change: string;
        }>(),
    ]);
    return context.json({
      actions: rows.results.map(toActionRecord),
      network: network.results.map((row) => ({
        id: row.id,
        at: row.at,
        change: row.change,
        requestedBy: row.requested_by,
        deviceId: row.device_id,
      })),
    });
  });

  app.post("/api/actions", requireOperator, async (context) => {
    const parsed = actionRequestSchema.safeParse(await readJson(context));
    if (!parsed.success) return invalidRequest(context);
    const { action, mode, targets, then } = parsed.data;
    const unsigned = (UNSIGNED_VERBS as readonly string[]).includes(action);
    const logs = action === "logs";
    if (
      (then !== undefined &&
        (action !== "uninstall" || targets.length !== 1)) ||
      new Set(targets.map(targetKey)).size !== targets.length ||
      targets.some(
        (target) =>
          !isValidTarget(target.kind, target.name) ||
          !(KIND_VERBS[target.kind] as readonly string[]).includes(action) ||
          (target.kind === "host" && !hostVerbFits(target.name, action)) ||
          (target.args !== undefined &&
            (!unsigned || !askedFits(target.kind, action, target.args))) ||
          (target.kind === "network" &&
            unsigned &&
            !networkArgsValid(action, target.args ?? {})) ||
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
    if (
      (action === "remove" || action === "purge") &&
      targets.some(
        (target) => target.kind === "apt" && target.name === "openssh-server",
      )
    ) {
      return context.json(
        {
          code: "PROTECTED_TARGET",
          message: "Krynodes never removes openssh-server.",
        },
        422,
      );
    }

    const db = context.env.DB;
    const identity = context.get("identity");
    if (!unsigned) {
      const refused = await ownersRefusal(
        context.env,
        await loadFleet(db, identity.id),
        targets.map((target) => target.signed!.grant),
        identity.email,
      );
      if (refused) {
        return context.json(
          { code: refused.code, message: refused.message },
          refused.status,
        );
      }
    }
    const now = Date.now();
    const wanted = new Set(targets.map((target) => target.nodeId));
    const nodeIds = JSON.stringify([...wanted]);
    const nodes = await db
      .prepare(
        `SELECT id, name, agent_version, docker, tailscale,
                (SELECT json_extract(report, '$.apt') FROM packages
                 WHERE node_id = nodes.id) AS apt
         FROM nodes
         WHERE owner_user_id = ? AND enrolled_at IS NOT NULL AND disabled_at IS NULL
           AND id IN (SELECT value FROM json_each(?))`,
      )
      .bind(identity.id, nodeIds)
      .all<{
        id: string;
        name: string;
        agent_version: string | null;
        docker: string | null;
        tailscale: string | null;
        apt: number | null;
      }>();
    if (nodes.results.length !== wanted.size) {
      return context.json(
        { code: "NOT_FOUND", message: "A server was not found." },
        404,
      );
    }
    const byId = new Map(nodes.results.map((node) => [node.id, node]));
    const old = nodes.results.find(
      (node) => !agentSupported(node.agent_version),
    );
    if (old) {
      return context.json(
        {
          code: "AGENT_TOO_OLD",
          message: `Update the agent on ${old.name} to ${MIN_AGENT_VERSION} or newer.`,
        },
        422,
      );
    }
    const behind = targets.find(
      (target) =>
        needsFeatures(target) &&
        !agentHasFeatures(byId.get(target.nodeId)!.agent_version),
    );
    if (behind) {
      return context.json(
        {
          code: "AGENT_TOO_OLD",
          message: `Update the agent on ${byId.get(behind.nodeId)!.name} to ${FEATURE_AGENT} or newer.`,
        },
        422,
      );
    }
    if (then) {
      const member = await networkMember(db, targets[0]!.nodeId);
      if (member) return member(context);
    }
    const aptless = targets.find(
      (target) => target.kind === "apt" && byId.get(target.nodeId)!.apt === 0,
    );
    if (aptless) {
      return context.json(
        {
          code: "NO_APT",
          message: `${byId.get(aptless.nodeId)!.name} does not use apt.`,
        },
        422,
      );
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
              `SELECT node_id AS nodeId, project AS name, compose, rollback, 0 AS removed, directory FROM stacks
               WHERE node_id IN (SELECT value FROM json_each(?1))
               UNION ALL
               SELECT node_id, project, 0, 0, 1, directory FROM removed_stacks
               WHERE node_id IN (SELECT value FROM json_each(?1))`,
            )
            .bind(nodeIds)
            .all<{
              nodeId: string;
              name: string;
              compose: number;
              rollback: number;
              removed: number;
              directory: string;
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
           WHERE status IN ('queued', 'sent')
             AND action NOT IN (SELECT value FROM json_each(?2))
             AND node_id IN (SELECT value FROM json_each(?1))`,
        )
        .bind(nodeIds, JSON.stringify([...READ_ONLY]))
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
                (action !== "rollback" || stack.rollback === 1) &&
                (action !== "edit" || OWN_STACK.test(stack.directory)) &&
                (action !== "adopt" || !OWN_STACK.test(stack.directory)),
          )
          .map((stack) =>
            targetKey({
              nodeId: stack.nodeId,
              kind: "compose",
              name: stack.name,
            }),
          ),
        ...nodes.results.flatMap((node) =>
          [
            "server",
            ...RECIPES,
            ...(node.docker === "missing" || node.docker === "no-compose"
              ? ["docker"]
              : []),
            ...(node.tailscale === null ? [] : ["tailscale"]),
          ].map((name) => targetKey({ nodeId: node.id, kind: "host", name })),
        ),
      ]);
      if (
        targets.some(
          (target) =>
            target.kind !== "apt" &&
            target.kind !== "network" &&
            !present.has(targetKey(target)),
        )
      ) {
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
    if (
      !READ_ONLY.has(action) &&
      targets.some((target) => busy.has(targetKey(target)))
    ) {
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
      targets: targets.map(({ args, ...target }) => ({
        ...target,
        attachment: askedAttachment(args) ?? undefined,
      })),
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
    const deleting = then
      ? [
          db
            .prepare(
              "UPDATE nodes SET deleting_batch = ? WHERE id = ? AND owner_user_id = ?",
            )
            .bind(batch.batchId, targets[0]!.nodeId, identity.id),
        ]
      : [];
    try {
      await db.batch([...batch.statements, ...used, ...deleting]);
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
