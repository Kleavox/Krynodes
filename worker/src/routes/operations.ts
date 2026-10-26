import {
  FEATURE_AGENT,
  MIN_AGENT_VERSION,
  agentHasFeatures,
  agentSupported,
  isValidTarget,
  signedCommandSchema,
} from "@krynodes/protocol";
import type { MiddlewareHandler } from "hono";
import { z } from "zod";

import { createBatch, sweepStatements } from "../actions/store";
import { pokeSoon } from "../fleet/client";
import { decodeJson } from "../lib/b64url";
import { assertionUv } from "../lib/webauthn";
import { ownersRefusal } from "../trust/approval";
import { loadFleet } from "../trust/fleet";
import {
  invalidRequest,
  readJson,
  type KrynodesApp,
  type KrynodesEnv,
} from "./shared";

const uuid = z.string().uuid();
const HOSTNAME =
  /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/u;

const stepSchema = z.object({
  id: uuid,
  nodeId: uuid,
  kind: z.enum(["compose", "vault", "host"]),
  name: z.string().min(1).max(128),
  action: z.enum([
    "export",
    "create",
    "remove",
    "purge",
    "expose",
    "unexpose",
    "store",
    "release",
    "reshare",
    "forget",
    "uninstall",
    "reach",
  ]),
  signed: signedCommandSchema,
  attachFrom: z.number().int().min(0).max(19).optional(),
  attachKey: uuid.optional(),
});

const operationSchema = z.object({
  kind: z.enum(["move", "expose", "unexpose", "split", "reshare"]),
  zone: z.string().regex(HOSTNAME).optional(),
  steps: z.array(stepSchema).min(1).max(20),
  deleteNode: uuid.optional(),
});

const commandSchema = z.object({
  v: z.literal(1),
  id: z.string(),
  nodeId: z.string(),
  kind: z.string(),
  name: z.string(),
  action: z.string(),
  args: z.record(z.string(), z.string()).optional(),
});

type Step = z.infer<typeof stepSchema> & { args: Record<string, string> };

const TOKEN_CHANGES = ["store", "reshare", "forget"];

interface NodeRow {
  id: string;
  name: string;
  agent_version: string | null;
  docker: string | null;
  seal_key: string | null;
  vault: string | null;
}

const is = (step: Step | undefined, kind: string, ...actions: string[]) =>
  step !== undefined && step.kind === kind && actions.includes(step.action);

const releasesTo = (release: Step, target: Step, attach: Step) =>
  release.args.to === target.nodeId &&
  release.nodeId !== target.nodeId &&
  attach.attachFrom === 0;

function exposeArgs(step: Step): boolean {
  const {
    hostname = "",
    zone = "",
    port = "",
    mode = "",
    path = "",
  } = step.args;
  return (
    HOSTNAME.test(hostname) &&
    zone !== "" &&
    hostname.endsWith(`.${zone}`) &&
    /^\d{1,5}$/u.test(port) &&
    ["allow", "path", "everyone"].includes(mode) &&
    (mode !== "path" || path.startsWith("/")) &&
    (step.args.service ?? "") !== ""
  );
}

function shaped(kind: string, steps: Step[]): boolean {
  const [first, second, third] = steps;
  const plain = steps.every(
    (step, index) => step.attachFrom === undefined || step.attachFrom < index,
  );
  if (!plain) return false;
  switch (kind) {
    case "move": {
      const removed = is(third, "compose", "remove", "purge");
      const reaches = steps.slice(removed ? 3 : 2);
      return (
        is(first, "compose", "export") &&
        is(second, "compose", "create") &&
        second!.attachFrom === 0 &&
        first!.nodeId !== second!.nodeId &&
        first!.args.to === second!.nodeId &&
        (!removed ||
          (third!.nodeId === first!.nodeId && third!.name === first!.name)) &&
        reaches.length <= 8 &&
        reaches.every(
          (step) =>
            is(step, "compose", "reach") &&
            step.attachFrom === undefined &&
            step.nodeId !== first!.nodeId &&
            step.nodeId !== second!.nodeId &&
            Object.keys(step.args).join() === "reaches",
        )
      );
    }
    case "expose":
    case "unexpose": {
      const verb = kind;
      const released = is(first, "vault", "release");
      const main = released ? second : first;
      const tail = steps.slice(released ? 2 : 1);
      return (
        is(main, "compose", verb) &&
        (!released || releasesTo(first!, main!, main!)) &&
        (verb === "unexpose"
          ? HOSTNAME.test(main!.args.hostname ?? "") && !!main!.args.zone
          : exposeArgs(main!)) &&
        tail.length <= (verb === "unexpose" ? 1 : 0) &&
        tail.every(
          (step) =>
            is(step, "compose", "remove", "purge") &&
            step.nodeId === main!.nodeId &&
            step.name === main!.name,
        )
      );
    }
    case "split": {
      const set = first?.args.set;
      return (
        steps.every(
          (step) =>
            is(step, "vault", "store") &&
            step.attachFrom === undefined &&
            step.args.set === set &&
            step.args.holders === String(steps.length),
        ) && new Set(steps.map((step) => step.nodeId)).size === steps.length
      );
    }
    case "reshare": {
      const released = is(first, "vault", "release");
      const reshare = released ? second : first;
      const index = released ? 1 : 0;
      if (!is(reshare, "vault", "reshare")) return false;
      if (released && !releasesTo(first!, reshare!, reshare!)) return false;
      const last = steps.at(-1)!;
      const leaving = is(last, "host", "uninstall");
      if (
        leaving &&
        (last.name !== "server" ||
          last.attachFrom !== undefined ||
          last.nodeId !== reshare!.args.cleanup)
      ) {
        return false;
      }
      const rest = steps.slice(index + 1, leaving ? -1 : undefined);
      const stores = rest.filter((step) => step.action === "store");
      const forgets = rest.filter((step) => step.action === "forget");
      const holders = (reshare!.args.holders ?? "")
        .split(",")
        .map((entry) => entry.split(":")[0]);
      return (
        stores.length + forgets.length === rest.length &&
        rest.every((step) => step.kind === "vault") &&
        stores.every(
          (step) =>
            step.attachFrom === index &&
            step.attachKey === step.nodeId &&
            step.args.set === reshare!.args.set &&
            step.args.holders === String(stores.length),
        ) &&
        holders.length === stores.length &&
        stores.every((step) => holders.includes(step.nodeId)) &&
        forgets.every(
          (step) =>
            step.attachFrom === undefined && !holders.includes(step.nodeId),
        )
      );
    }
  }
  return false;
}

interface HeldPiece {
  set: string;
  holders: number;
}

function vaultOf(node: NodeRow): (HeldPiece & { previous?: HeldPiece }) | null {
  try {
    return JSON.parse(node.vault ?? "null") as
      (HeldPiece & { previous?: HeldPiece }) | null;
  } catch {
    return null;
  }
}

const holdsSet = (vault: ReturnType<typeof vaultOf>, set?: string) =>
  vault !== null &&
  (set === undefined || vault.set === set || vault.previous?.set === set);

export function registerOperationRoutes(
  app: KrynodesApp,
  requireOperator: MiddlewareHandler<KrynodesEnv>,
): void {
  app.post("/api/operations", requireOperator, async (context) => {
    const parsed = operationSchema.safeParse(await readJson(context));
    if (!parsed.success) return invalidRequest(context);
    const { kind, zone, deleteNode } = parsed.data;
    const steps: Step[] = [];
    for (const step of parsed.data.steps) {
      const command = commandSchema.safeParse(decodeJson(step.signed.command));
      if (
        !command.success ||
        command.data.id !== step.id ||
        command.data.nodeId !== step.nodeId ||
        command.data.kind !== step.kind ||
        command.data.name !== step.name ||
        command.data.action !== step.action
      ) {
        return context.json(
          {
            code: "SIGNATURE_MISMATCH",
            message: "The signed command does not match the request.",
          },
          400,
        );
      }
      if (!assertionUv(step.signed.grant.authenticatorData)) {
        return context.json(
          {
            code: "FINGERPRINT_NEEDED",
            message: "This passkey did not verify a fingerprint.",
          },
          400,
        );
      }
      if (!isValidTarget(step.kind, step.name)) return invalidRequest(context);
      steps.push({ ...step, args: command.data.args ?? {} });
    }
    const cleanup = steps.find((step) => step.action === "reshare")?.args
      .cleanup;
    const leaving = steps.some((step) => step.action === "uninstall");
    if (
      !shaped(kind, steps) ||
      new Set(steps.map((step) => step.id)).size !== steps.length ||
      (kind === "split" && !zone) ||
      (deleteNode !== undefined &&
        (kind !== "reshare" || deleteNode !== cleanup)) ||
      (leaving && deleteNode === undefined)
    ) {
      return invalidRequest(context);
    }

    const db = context.env.DB;
    const identity = context.get("identity");
    const refusal = await ownersRefusal(
      context.env,
      await loadFleet(db, identity.id),
      steps.map((step) => step.signed.grant),
      identity.email,
    );
    if (refusal) {
      return context.json(
        { code: refusal.code, message: refusal.message },
        refusal.status,
      );
    }
    const now = Date.now();
    const wanted = [...new Set(steps.map((step) => step.nodeId))];
    const nodes = await db
      .prepare(
        `SELECT id, name, agent_version, docker, seal_key, vault FROM nodes
         WHERE owner_user_id = ? AND enrolled_at IS NOT NULL AND disabled_at IS NULL
           AND id IN (SELECT value FROM json_each(?))`,
      )
      .bind(identity.id, JSON.stringify(wanted))
      .all<NodeRow>();
    if (nodes.results.length !== wanted.length) {
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
    const behind = steps.find(
      (step) =>
        step.action === "reach" &&
        !agentHasFeatures(byId.get(step.nodeId)!.agent_version),
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
    for (const step of steps) {
      if (step.args.key !== undefined) {
        const target = byId.get(step.args.to ?? "");
        if (!target || target.seal_key !== step.args.key) {
          return context.json(
            {
              code: "KEY_CHANGED",
              message: "A server's key changed. Refresh and try again.",
            },
            409,
          );
        }
      }
      if (step.action === "release" || step.action === "reshare") {
        const vault = vaultOf(byId.get(step.nodeId)!);
        const wanted =
          step.action === "release" ? step.args.set : step.args.source;
        if (!holdsSet(vault, wanted)) {
          return context.json(
            {
              code: "NO_PIECE",
              message: `${byId.get(step.nodeId)!.name} holds no piece of the Cloudflare token. Spread it again.`,
            },
            422,
          );
        }
      }
    }
    if (kind === "reshare") {
      const reshare = steps.find((step) => step.action === "reshare")!;
      const listed = (reshare.args.holders ?? "").split(",");
      if (
        listed.some((entry) => {
          const [node, key] = entry.split(":");
          return !node || byId.get(node)?.seal_key !== key;
        })
      ) {
        return context.json(
          {
            code: "KEY_CHANGED",
            message: "A server's key changed. Refresh and try again.",
          },
          409,
        );
      }
    }
    await db.batch(sweepStatements(db, now));
    if (kind !== "move") {
      const pending = await db
        .prepare(
          `SELECT action FROM actions
           WHERE status IN ('queued', 'sent') AND kind = 'vault'
             AND node_id IN (SELECT id FROM nodes WHERE owner_user_id = ?)`,
        )
        .bind(identity.id)
        .all<{ action: string }>();
      const changing = kind === "split" || kind === "reshare";
      const changed = pending.results.some((row) =>
        TOKEN_CHANGES.includes(row.action),
      );
      if (changed || (changing && pending.results.length > 0)) {
        return context.json(
          {
            code: "TOKEN_BUSY",
            message: changed
              ? "The Cloudflare token is being changed. Try again when that finishes."
              : "The Cloudflare token is in use for a web address. Try again when that finishes.",
          },
          409,
        );
      }
    }
    const composeSteps = steps.filter((step) => step.kind === "compose");
    if (composeSteps.length > 0) {
      const stacks = await db
        .prepare(
          `SELECT node_id AS nodeId, project AS name, compose FROM stacks
           WHERE node_id IN (SELECT value FROM json_each(?1))
           UNION ALL
           SELECT node_id, project, -1 FROM removed_stacks
           WHERE node_id IN (SELECT value FROM json_each(?1))`,
        )
        .bind(JSON.stringify(wanted))
        .all<{ nodeId: string; name: string; compose: number }>();
      const live = new Set(
        stacks.results
          .filter((stack) => stack.compose === 1)
          .map((stack) => `${stack.nodeId}|${stack.name}`),
      );
      const taken = new Set(
        stacks.results.map((stack) => `${stack.nodeId}|${stack.name}`),
      );
      for (const step of composeSteps) {
        const key = `${step.nodeId}|${step.name}`;
        if (step.action === "create") {
          if (taken.has(key)) {
            return context.json(
              {
                code: "STACK_EXISTS",
                message: `${byId.get(step.nodeId)!.name} already has a stack named ${step.name}.`,
              },
              409,
            );
          }
          if (byId.get(step.nodeId)!.docker !== "ready") {
            return context.json(
              {
                code: "NO_DOCKER",
                message: `${byId.get(step.nodeId)!.name} has no Docker with Compose.`,
              },
              422,
            );
          }
        } else if (!live.has(key)) {
          return context.json(
            {
              code: "UNKNOWN_TARGET",
              message: "A stack is no longer on its server. Refresh the list.",
            },
            422,
          );
        }
      }
    }

    const batch = createBatch(db, {
      action: steps[0]!.action,
      mode: kind === "split" ? "parallel" : "rolling",
      targets: steps.map((step) => ({
        id: step.id,
        nodeId: step.nodeId,
        kind: step.kind,
        name: step.name,
        action: step.action,
        signed: step.signed,
        ...(step.attachFrom === undefined
          ? {}
          : { attachFrom: step.attachFrom }),
        ...(step.attachKey === undefined ? {} : { attachKey: step.attachKey }),
      })),
      requestedBy: identity.email,
      now,
      deviceId: steps[0]!.signed.grant.credentialId,
    });
    const settings =
      kind === "split"
        ? [
            db
              .prepare(
                `INSERT INTO cloudflare (owner_user_id, zone, set_id, updated_at)
                 VALUES (?1, ?2, NULL, ?3)
                 ON CONFLICT (owner_user_id) DO UPDATE SET
                   zone = excluded.zone, updated_at = excluded.updated_at`,
              )
              .bind(identity.id, zone, new Date(now).toISOString()),
          ]
        : [];
    const deleting = deleteNode
      ? [
          db
            .prepare(
              "UPDATE nodes SET deleting_batch = ? WHERE id = ? AND owner_user_id = ?",
            )
            .bind(batch.batchId, deleteNode, identity.id),
        ]
      : [];
    try {
      await db.batch([...batch.statements, ...settings, ...deleting]);
    } catch (error) {
      if (!String(error).includes("UNIQUE")) throw error;
      return context.json(
        {
          code: "ACTION_PENDING",
          message: "An action for this stack is still running.",
        },
        409,
      );
    }
    pokeSoon(context, identity.id, wanted);
    return context.json(
      { batchId: batch.batchId, actions: batch.actions },
      201,
    );
  });
}
