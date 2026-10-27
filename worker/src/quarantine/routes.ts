import {
  agentHasFeatures,
  codeOf,
  looser,
  QUARANTINE,
  quarantineSettingsSchema,
  releaseSchema,
  releaseText,
  signedCommandSchema,
} from "@krynodes/protocol";
import type { MiddlewareHandler } from "hono";
import { z } from "zod";

import { createBatch, sweepStatements } from "../actions/store";
import { pokeSoon } from "../fleet/client";
import { decodeJson, toB64url } from "../lib/b64url";
import { assertionUv } from "../lib/webauthn";
import { changeStatement } from "../routes/network";
import {
  invalidRequest,
  readJson,
  type KrynodesApp,
  type KrynodesContext,
  type KrynodesEnv,
} from "../routes/shared";
import { ownersRefusal } from "../trust/approval";
import { loadFleet } from "../trust/fleet";
import { confirmed, confirmingDevice } from "../trust/intent";
import { warningOf } from "./events";
import { quarantine, trustedBy, type Timeline } from "./quarantine";
import { readSettings, settingsText, writeSettings } from "./settings";

const ACCEPTS = ["ssh-key", "ssh-login", "user", "sudo", "port"];

const SHORT: Record<string, string> = {
  "ssh-key": "new key",
  "ssh-login": "sign-in",
  user: "new user",
  sudo: "new sudo rule",
  port: "new port",
  rule: "removed rule",
  quiet: "quiet agent",
};

const stepSchema = z.object({
  id: z.string().uuid(),
  nodeId: z.string().uuid(),
  kind: z.literal("host"),
  name: z.enum(["server", "tailscale"]),
  action: z.enum(["accept", "release", "unlock", "unblock"]),
  signed: signedCommandSchema,
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

const releaseBodySchema = z.object({
  code: z.string().regex(/^[A-Z2-7]{5}-[A-Z2-7]{5}$/u),
  steps: z.array(stepSchema).min(1).max(40),
});

type Step = z.infer<typeof stepSchema> & { args: Record<string, string> };

const same = (args: Record<string, string>, wanted: Record<string, string>) =>
  Object.keys(args).length === Object.keys(wanted).length &&
  Object.entries(wanted).every(([key, value]) => args[key] === value);

const is = (
  step: Step | undefined,
  nodeId: string,
  name: string,
  action: string,
  args: Record<string, string>,
) =>
  step !== undefined &&
  step.nodeId === nodeId &&
  step.name === name &&
  step.action === action &&
  same(step.args, args);

const parsed = <T>(text: string | null, fallback: T): T => {
  try {
    return (JSON.parse(text ?? "null") as T | null) ?? fallback;
  } catch {
    return fallback;
  }
};

async function verified(
  context: KrynodesContext,
  steps: z.infer<typeof stepSchema>[],
): Promise<Step[] | Response> {
  const out: Step[] = [];
  for (const step of steps) {
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
    out.push({ ...step, args: command.data.args ?? {} });
  }
  const identity = context.get("identity");
  const refused = await ownersRefusal(
    context.env,
    await loadFleet(context.env.DB, identity.id),
    steps.map((step) => step.signed.grant),
    identity.email,
  );
  return refused
    ? context.json(
        { code: refused.code, message: refused.message },
        refused.status,
      )
    : out;
}

const ownedNode = (context: KrynodesContext, id: string) =>
  context.env.DB.prepare(
    "SELECT id, name, vault, tailscale_vault, release FROM nodes WHERE id = ? AND owner_user_id = ?",
  )
    .bind(id, context.get("identity").id)
    .first<{
      id: string;
      name: string;
      vault: string | null;
      tailscale_vault: string | null;
      release: string | null;
    }>();

const notFound = (context: KrynodesContext) =>
  context.json({ code: "NOT_FOUND", message: "A server was not found." }, 404);

const unanswered = (context: KrynodesContext) =>
  context.json(
    { code: "ANSWERED", message: "This warning was answered already." },
    409,
  );

async function openWarning(context: KrynodesContext): Promise<
  | Response
  | {
      node: { id: string; name: string };
      warning: { id: string; kind: string; detail: Record<string, string> };
    }
> {
  const node = await ownedNode(context, context.req.param("nodeId")!);
  if (!node) return notFound(context);
  const row = await context.env.DB.prepare(
    "SELECT id, kind, detail, answer FROM warnings WHERE node_id = ? AND id = ?",
  )
    .bind(node.id, context.req.param("id"))
    .first<{
      id: string;
      kind: string;
      detail: string;
      answer: string | null;
    }>();
  if (!row) return notFound(context);
  if (row.answer !== null) return unanswered(context);
  return {
    node,
    warning: {
      id: row.id,
      kind: row.kind,
      detail: parsed<Record<string, string>>(row.detail, {}),
    },
  };
}

const answerStatement = (
  db: D1Database,
  nodeId: string,
  id: string,
  answer: string,
  by: string,
  at: string,
) =>
  db
    .prepare(
      `UPDATE warnings SET answer = ?, answered_at = ?, answered_by = ?
       WHERE node_id = ? AND id = ? AND answer IS NULL`,
    )
    .bind(answer, at, by, nodeId, id);

export function registerQuarantineRoutes(
  app: KrynodesApp,
  requireOperator: MiddlewareHandler<KrynodesEnv>,
): void {
  app.post(
    "/api/nodes/:nodeId/warnings/:id/cut",
    requireOperator,
    async (context) => {
      const found = await openWarning(context);
      if (found instanceof Response) return found;
      const { node, warning } = found;
      const db = context.env.DB;
      const identity = context.get("identity");
      const now = Date.now();
      const answered = await answerStatement(
        db,
        node.id,
        warning.id,
        "cut",
        identity.email,
        new Date(now).toISOString(),
      ).run();
      if ((answered.meta.changes ?? 0) === 0) return unanswered(context);
      const started = await quarantine(db, {
        nodeId: node.id,
        why: `You cut it off after a ${warningOf(warning.kind, warning.detail)}`,
        now,
        by: { change: `Cut off ${node.name}`, requestedBy: identity.email },
      });
      pokeSoon(context, identity.id, started.nodes);
      return context.json({ quarantined: true });
    },
  );

  app.post(
    "/api/nodes/:nodeId/warnings/:id/me",
    requireOperator,
    async (context) => {
      const body = z
        .object({ target: stepSchema.optional() })
        .safeParse((await readJson(context)) ?? {});
      if (!body.success) return invalidRequest(context);
      const found = await openWarning(context);
      if (found instanceof Response) return found;
      const { node, warning } = found;
      const db = context.env.DB;
      const identity = context.get("identity");
      const now = Date.now();
      const at = new Date(now).toISOString();
      const change = (deviceId: string | null) =>
        changeStatement(db, {
          owner: identity.id,
          at,
          change: `It was me: the ${SHORT[warning.kind] ?? warning.kind} on ${node.name}`,
          detail: warningOf(warning.kind, warning.detail),
          requestedBy: identity.email,
          deviceId,
          nodes: [node.id],
          joins: [],
          leaves: [],
        });
      const answer = answerStatement(
        db,
        node.id,
        warning.id,
        "me",
        identity.email,
        at,
      );
      if (!ACCEPTS.includes(warning.kind)) {
        const refused = await confirmed(
          context,
          "warning.me",
          `${node.id}/${warning.id}`,
        );
        if (refused) return refused;
        await db.batch([answer, change(confirmingDevice(context))]);
        return context.json({ answered: true });
      }
      if (!body.data.target) return invalidRequest(context);
      const steps = await verified(context, [body.data.target]);
      if (steps instanceof Response) return steps;
      if (
        !is(steps[0], node.id, "server", "accept", {
          kind: warning.kind,
          item: warning.detail.item ?? "",
        })
      ) {
        return invalidRequest(context);
      }
      const device = steps[0]!.signed.grant.credentialId;
      const batch = createBatch(db, {
        action: "accept",
        mode: "parallel",
        targets: [
          {
            id: steps[0]!.id,
            nodeId: node.id,
            kind: "host",
            name: "server",
            signed: steps[0]!.signed,
          },
        ],
        requestedBy: identity.email,
        now,
        deviceId: device,
      });
      await db.batch([...batch.statements, answer, change(device)]);
      pokeSoon(context, identity.id, [node.id]);
      return context.json({ batchId: batch.batchId }, 201);
    },
  );

  app.get("/api/nodes/:id/quarantine", requireOperator, async (context) => {
    const db = context.env.DB;
    const owner = context.get("identity").id;
    const node = await ownedNode(context, context.req.param("id"));
    if (!node) return notFound(context);
    const [row, stopped, stacks, web, others] = await Promise.all([
      db
        .prepare(
          `SELECT id, why, at, timeline, released_at, released_by FROM quarantines
           WHERE node_id = ? ORDER BY at DESC LIMIT 1`,
        )
        .bind(node.id)
        .first<{
          id: string;
          why: string;
          at: string;
          timeline: string;
          released_at: string | null;
          released_by: string | null;
        }>(),
      db
        .prepare(
          "SELECT project, at, tried, count FROM stopped_stacks WHERE node_id = ? ORDER BY project",
        )
        .bind(node.id)
        .all<{ project: string; at: string; tried: string; count: number }>(),
      db
        .prepare(
          "SELECT project FROM stacks WHERE node_id = ? ORDER BY project",
        )
        .bind(node.id)
        .all<{ project: string }>(),
      db
        .prepare(
          "SELECT hostname, project FROM web_addresses WHERE node_id = ? ORDER BY hostname",
        )
        .bind(node.id)
        .all<{ hostname: string; project: string }>(),
      trustedBy(db, owner, node.id),
    ]);
    const timeline = parsed<Timeline>(row?.timeline ?? null, {
      batches: [],
      tailnet: [],
      dropped: [],
    });
    const knocks = row
      ? (
          await db
            .prepare(
              `SELECT n.name AS reporter, k.at, k.count FROM knocks k
               JOIN nodes n ON n.id = k.reporter
               WHERE k.suspect = ? AND k.at <= ? AND k.at >= ?
               ORDER BY k.at`,
            )
            .bind(
              node.id,
              row.at,
              new Date(
                Date.parse(row.at) - QUARANTINE.agreeMinutes * 60_000,
              ).toISOString(),
            )
            .all<{ reporter: string; at: string; count: number }>()
        ).results
      : [];
    const address = await db
      .prepare("SELECT address FROM network_members WHERE node_id = ?")
      .bind(node.id)
      .first<string | null>("address");
    const steps = row
      ? (
          await db
            .prepare(
              `SELECT a.node_id, n.name, a.action, a.status, a.finished_at FROM actions a
               JOIN json_each(?) b ON b.value = a.batch_id
               JOIN nodes n ON n.id = a.node_id
               ORDER BY b.key, a.position`,
            )
            .bind(JSON.stringify(timeline.batches))
            .all<{
              node_id: string;
              name: string;
              action: string;
              status: string;
              finished_at: string | null;
            }>()
        ).results
      : [];
    const pending = releaseSchema.safeParse(parsed(node.release, null));
    return context.json({
      quarantine: row
        ? {
            id: row.id,
            why: row.why,
            at: row.at,
            releasedAt: row.released_at,
            releasedBy: row.released_by,
            tailnet: timeline.tailnet,
            removed: timeline.removed ?? null,
            address: address ?? null,
            knocks,
            steps: steps.map((step) => ({
              nodeId: step.node_id,
              nodeName: step.name,
              action: step.action,
              status: step.status,
              finishedAt: step.finished_at,
            })),
          }
        : null,
      release: pending.success ? pending.data : null,
      stopped: stopped.results.map((stack) => ({
        project: stack.project,
        at: stack.at,
        tried: parsed<string[]>(stack.tried, []),
        count: stack.count,
      })),
      changeThese: {
        stacks: stacks.results.map((stack) => stack.project),
        vault: parsed<unknown>(node.vault, null),
        tailscaleVault: parsed<unknown>(node.tailscale_vault, null),
        webAddresses: web.results,
        trusted: others,
      },
    });
  });

  app.post("/api/nodes/:id/release", requireOperator, async (context) => {
    const body = releaseBodySchema.safeParse(await readJson(context));
    if (!body.success) return invalidRequest(context);
    const db = context.env.DB;
    const identity = context.get("identity");
    const node = await ownedNode(context, context.req.param("id"));
    if (!node) return notFound(context);
    const open = await db
      .prepare(
        "SELECT id, timeline FROM quarantines WHERE node_id = ? AND released_at IS NULL",
      )
      .bind(node.id)
      .first<{ id: string; timeline: string }>();
    if (!open) {
      return context.json(
        {
          code: "NOT_QUARANTINED",
          message: `${node.name} is not quarantined.`,
        },
        409,
      );
    }
    const now = Date.now();
    const codeRefusal = (message: string) =>
      context.json({ code: "RELEASE_CODE", message }, 422);
    const pending = releaseSchema.safeParse(parsed(node.release, null));
    if (!pending.success) {
      return codeRefusal(`Run sudo kry release-code on ${node.name} first.`);
    }
    const release = pending.data;
    if (Date.parse(release.expires) <= now) {
      return codeRefusal(
        `That code has ended. Run sudo kry release-code on ${node.name} again.`,
      );
    }
    const digest = new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(releaseText(release)),
      ),
    );
    if (codeOf(digest) !== body.data.code) {
      return codeRefusal(
        `That is not the code ${node.name} showed. Type it again.`,
      );
    }
    const steps = await verified(context, body.data.steps);
    if (steps instanceof Response) return steps;
    const timeline = parsed<Timeline>(open.timeline, {
      batches: [],
      tailnet: [],
      dropped: [],
    });
    const blocked = (
      await db
        .prepare(
          `SELECT node_id FROM actions
           WHERE batch_id IN (SELECT value FROM json_each(?)) AND action = 'block'`,
        )
        .bind(JSON.stringify(timeline.batches))
        .all<{ node_id: string }>()
    ).results.map((row) => row.node_id);
    const unlocks = is(steps[1], node.id, "server", "unlock", {}) ? 1 : 0;
    const unblocks = steps.slice(1 + unlocks);
    const addresses = { addresses: timeline.tailnet.join(" ") };
    if (
      !is(steps[0], node.id, "server", "release", {
        key: release.key,
        signer: release.signer,
        seal: release.seal,
        token: release.token,
        code: body.data.code,
      }) ||
      unblocks.length !== blocked.length ||
      new Set(unblocks.map((step) => step.nodeId)).size !== unblocks.length ||
      !unblocks.every(
        (step) =>
          blocked.includes(step.nodeId) &&
          is(step, step.nodeId, "tailscale", "unblock", addresses),
      )
    ) {
      return invalidRequest(context);
    }
    const device = steps[0]!.signed.grant.credentialId;
    const at = new Date(now).toISOString();
    const batch = createBatch(db, {
      action: "release",
      mode: "rolling",
      targets: steps.map((step) => ({
        id: step.id,
        nodeId: step.nodeId,
        kind: step.kind,
        name: step.name,
        action: step.action,
        signed: step.signed,
      })),
      requestedBy: identity.email,
      now,
      deviceId: device,
    });
    await db.batch(sweepStatements(db, now));
    try {
      await db.batch([
        ...batch.statements,
        db
          .prepare(
            `UPDATE quarantines SET released_at = ?, released_by = ?
             WHERE id = ? AND released_at IS NULL`,
          )
          .bind(at, device, open.id),
        db
          .prepare(
            "UPDATE nodes SET release = json_set(release, '$.released', json('true')) WHERE id = ?",
          )
          .bind(node.id),
        db
          .prepare(
            `UPDATE warnings SET answer = 'released', answered_at = ?, answered_by = ?
             WHERE node_id = ? AND answer IS NULL`,
          )
          .bind(at, identity.email, node.id),
        changeStatement(db, {
          owner: identity.id,
          at,
          change: `Release ${node.name}`,
          detail: null,
          requestedBy: identity.email,
          deviceId: device,
          nodes: [node.id, ...blocked],
          joins: [],
          leaves: [],
        }),
        db
          .prepare(
            "UPDATE devices SET last_used_at = ? WHERE id = ? AND owner_user_id = ?",
          )
          .bind(at, device, identity.id),
      ]);
    } catch (error) {
      if (!String(error).includes("UNIQUE")) throw error;
      return context.json(
        {
          code: "ACTION_PENDING",
          message: `An action on ${node.name} is still running.`,
        },
        409,
      );
    }
    pokeSoon(context, identity.id, [node.id, ...blocked]);
    return context.json(
      { batchId: batch.batchId, actions: batch.actions },
      201,
    );
  });

  app.get("/api/settings/quarantine", requireOperator, async (context) =>
    context.json({
      settings: await readSettings(context.env.DB, context.get("identity").id),
    }),
  );

  app.put("/api/settings/quarantine", requireOperator, async (context) => {
    const body = quarantineSettingsSchema.safeParse(await readJson(context));
    if (!body.success) return invalidRequest(context);
    const db = context.env.DB;
    const identity = context.get("identity");
    const before = await readSettings(db, identity.id);
    const after = body.data;
    if (looser(before, after)) {
      const refused = await confirmed(
        context,
        "quarantine.settings",
        settingsText(after),
      );
      if (refused) return refused;
    }
    const now = Date.now();
    const statements = [
      writeSettings(db, identity.id, after, new Date(now).toISOString()),
    ];
    const members =
      after.scan < before.scan || (after.stop && !before.stop)
        ? (
            await db
              .prepare(
                `SELECT m.node_id, n.agent_version FROM network_members m
                 JOIN nodes n ON n.id = m.node_id
                 WHERE n.owner_user_id = ? AND m.state = 'in'
                 ORDER BY m.address`,
              )
              .bind(identity.id)
              .all<{ node_id: string; agent_version: string | null }>()
          ).results
            .filter((member) => agentHasFeatures(member.agent_version))
            .map((member) => member.node_id)
        : [];
    if (members.length > 0) {
      const attachment = toB64url(
        new TextEncoder().encode(
          JSON.stringify({
            scan: String(after.scan),
            stop: String(after.stop),
          }),
        ),
      );
      statements.push(
        ...createBatch(db, {
          action: "tighten",
          mode: "parallel",
          targets: members.map((nodeId) => ({
            nodeId,
            kind: "network",
            name: "kry0",
            attachment,
          })),
          requestedBy: identity.email,
          now,
        }).statements,
      );
    }
    await db.batch(statements);
    pokeSoon(context, identity.id, members);
    return context.json({ settings: after });
  });
}
