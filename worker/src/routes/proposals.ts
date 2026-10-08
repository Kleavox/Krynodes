import {
  MIN_AGENT_VERSION,
  evaluateQuorum,
  summarizeChange,
  trustChangeSchema,
  type TrustChange,
} from "@krynodes/protocol";
import type { MiddlewareHandler } from "hono";
import { z } from "zod";

import { createBatch, sweepStatements } from "../actions/store";
import { pokeNodes } from "../fleet/client";
import type { Env } from "../env";
import { fromB64url } from "../lib/b64url";
import { sendProposalEmail } from "../lib/mail";
import { Refusal, verifyApproval } from "../trust/approval";
import { agentCurrent, loadFleet, type Fleet } from "../trust/fleet";
import {
  invalidRequest,
  readJson,
  type KrynodesApp,
  type KrynodesEnv,
} from "./shared";

const b64url = z
  .string()
  .min(1)
  .max(4096)
  .regex(/^[A-Za-z0-9_-]+$/u);

const approvalSchema = z.strictObject({
  credentialId: b64url,
  authenticatorData: b64url,
  clientDataJSON: b64url,
  signature: b64url,
  proof: b64url.optional(),
});

const openSchema = z.strictObject({
  change: z
    .string()
    .min(1)
    .max(65536)
    .regex(/^[A-Za-z0-9_-]+$/u),
  approval: approvalSchema,
});

const approveSchema = z.strictObject({ approval: approvalSchema });

type Approval = z.infer<typeof approvalSchema>;

interface ProposalRow {
  id: string;
  change: string;
  title: string;
  version: number;
  approvals: string;
  status: "open" | "applied" | "expired" | "cancelled" | "superseded";
  opened_by: string;
  opened_at: string;
  expires_at: string;
  closed_at: string | null;
}

const DAY_MS = 24 * 3_600_000;
const CHANGES_PAGE = 20;
const SKEW_MS = 60_000;
const MAX_OPEN = 5;

function decodeChange(text: string): TrustChange | null {
  try {
    const parsed = trustChangeSchema.safeParse(
      JSON.parse(new TextDecoder().decode(fromB64url(text))),
    );
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

function describe(fleet: Fleet, change: TrustChange) {
  const names = Object.fromEntries(
    fleet.devices.map((device) => [device.id, device.name]),
  );
  for (const key of change.core ?? []) names[key.id] ??= key.name;
  return summarizeChange({
    names,
    servers: Object.fromEntries(
      fleet.nodes.map((node) => [node.id, node.name]),
    ),
    currentCore: fleet.core,
    currentAccess: Object.fromEntries(
      fleet.nodes.map((node) => [
        node.id,
        fleet.ids(node.report?.access ?? []),
      ]),
    ),
    change: {
      core: change.core?.map((key) => key.id) ?? null,
      access: change.access,
    },
  }).title;
}

function missing(
  fleet: Fleet,
  change: TrustChange,
  approvals: Approval[],
): string | null {
  for (const [nodeId, access] of Object.entries(change.access)) {
    const node = fleet.nodes.find((entry) => entry.id === nodeId);
    const result = evaluateQuorum({
      current: {
        core: fleet.ids(node?.report?.core ?? []),
        access: fleet.ids(node?.report?.access ?? []),
      },
      change: { core: change.core?.map((key) => key.id) ?? null, access },
      approvals: approvals.map((approval) => approval.credentialId),
    });
    if (!result.ok) return result.reason;
  }
  return null;
}

function checkChange(env: Env, fleet: Fleet, change: TrustChange, now: number) {
  const origin = new URL(env.PUBLIC_ORIGIN);
  if (change.origin !== origin.origin || change.rpId !== origin.hostname) {
    throw new Refusal(400, "WRONG_ORIGIN", "The change is for another origin.");
  }
  const issued = Date.parse(change.issuedAt);
  const expires = Date.parse(change.expiresAt);
  if (issued > now + SKEW_MS || expires <= now || expires - issued > DAY_MS) {
    throw new Refusal(
      400,
      "BAD_WINDOW",
      "The change must last at most 24 hours.",
    );
  }
  const targets = Object.keys(change.access);
  const devicesOrRule =
    change.core !== null || change.passphrase !== null || change.requireUv;
  for (const nodeId of targets) {
    const node = fleet.nodes.find((entry) => entry.id === nodeId);
    if (!node) throw new Refusal(404, "NOT_FOUND", "A server was not found.");
    if (!agentCurrent(node)) {
      throw new Refusal(
        422,
        "NEEDS_AGENT",
        `Update ${node.name} to agent ${MIN_AGENT_VERSION} first.`,
      );
    }
    if ((node.report?.core.length ?? 0) === 0) {
      throw new Refusal(
        409,
        "NOT_TRUSTED",
        `${node.name} trusts no device yet. Use Trust on servers first.`,
      );
    }
    if (change.version <= (node.report?.version ?? 0)) {
      throw new Refusal(
        409,
        "STALE_VERSION",
        "Another change reached the servers first. Start again.",
      );
    }
  }
  checkFingerprints(fleet, change);
  if (devicesOrRule) {
    const trusted = fleet.nodes.filter(
      (node) => (node.report?.core.length ?? 0) > 0,
    );
    if (trusted.some((node) => !targets.includes(node.id))) {
      throw new Refusal(
        400,
        "INCOMPLETE",
        "Adding or removing a device, the passphrase or the fingerprint rule must reach every server.",
      );
    }
  }
}

function checkFingerprints(fleet: Fleet, change: TrustChange) {
  if (change.passphrase !== null) {
    throw new Refusal(
      400,
      "NO_PASSPHRASE",
      "Krynodes no longer uses a passphrase; fingerprints confirm every change.",
    );
  }
  for (const key of change.core ?? []) {
    const device = fleet.devices.find((entry) => entry.id === key.id);
    if (!fleet.core.includes(key.id) && device?.verifies !== true) {
      throw new Refusal(
        422,
        "CANNOT_VERIFY",
        `${device?.name ?? "A device"} has not shown it can verify a fingerprint, so it cannot join.`,
      );
    }
  }
}

async function notify(env: Env, fleet: Fleet, title: string, openedBy: string) {
  try {
    await sendProposalEmail(env, {
      title,
      openedBy:
        fleet.devices.find((device) => device.id === openedBy)?.name ??
        "an unknown device",
    });
  } catch (error) {
    console.error("[kry proposals]", error);
  }
}

async function sweepExpired(env: Env, ownerId: string, now: number) {
  await env.DB.prepare(
    `UPDATE proposals SET status = 'expired', closed_at = ?
     WHERE owner_user_id = ? AND status = 'open' AND expires_at < ?`,
  )
    .bind(new Date(now).toISOString(), ownerId, new Date(now).toISOString())
    .run();
}

async function apply(
  env: Env,
  input: {
    ownerId: string;
    email: string;
    fleet: Fleet;
    id: string;
    text: string;
    change: TrustChange;
    title: string;
    approvals: Approval[];
    openedBy: string;
    isNew: boolean;
    now: number;
  },
) {
  const db = env.DB;
  const at = new Date(input.now).toISOString();
  const guard = input.isNew ? null : input.id;
  const batch = createBatch(db, {
    action: "trust",
    mode: "parallel",
    targets: Object.keys(input.change.access).map((nodeId) => ({
      nodeId,
      kind: "trust" as const,
      name: "devices",
      signed: { change: input.text, approvals: input.approvals },
    })),
    requestedBy: input.email,
    now: input.now,
    whileOpen: guard ?? undefined,
  });
  const record = input.isNew
    ? db
        .prepare(
          `INSERT INTO proposals (id, owner_user_id, change, title, version, approvals, status, opened_by, opened_at, expires_at, closed_at)
           VALUES (?, ?, ?, ?, ?, ?, 'applied', ?, ?, ?, ?)`,
        )
        .bind(
          input.id,
          input.ownerId,
          input.text,
          input.title,
          input.change.version,
          JSON.stringify(input.approvals),
          input.openedBy,
          at,
          input.change.expiresAt,
          at,
        )
    : db
        .prepare(
          `UPDATE proposals SET status = 'applied', approvals = ?, closed_at = ?
           WHERE id = ? AND status = 'open'`,
        )
        .bind(JSON.stringify(input.approvals), at, input.id);
  const open = (slot: number) =>
    `(?${slot} IS NULL OR EXISTS (SELECT 1 FROM proposals WHERE id = ?${slot} AND status = 'open'))`;
  const statements = [
    ...batch.statements,
    db
      .prepare(
        `UPDATE proposals SET status = 'superseded', closed_at = ?1
         WHERE owner_user_id = ?2 AND status = 'open' AND id <> ?3 AND version <= ?4
           AND ${open(5)}`,
      )
      .bind(at, input.ownerId, input.id, input.change.version, guard),
    db
      .prepare(
        `UPDATE devices SET last_used_at = ?1
         WHERE owner_user_id = ?2 AND id IN (SELECT value FROM json_each(?3)) AND ${open(4)}`,
      )
      .bind(
        at,
        input.ownerId,
        JSON.stringify(
          input.approvals.map((approval) => approval.credentialId),
        ),
        guard,
      ),
  ];
  if (input.change.core) {
    statements.push(
      db
        .prepare(
          `UPDATE devices SET removed_at = ?1
           WHERE owner_user_id = ?2 AND removed_at IS NULL
             AND id IN (SELECT value FROM json_each(?3))
             AND id NOT IN (SELECT value FROM json_each(?4))
             AND ${open(5)}`,
        )
        .bind(
          at,
          input.ownerId,
          JSON.stringify(input.fleet.core),
          JSON.stringify(input.change.core.map((key) => key.id)),
          guard,
        ),
    );
  }
  statements.push(record);
  await db.batch(sweepStatements(db, input.now));
  try {
    const results = await db.batch(statements);
    if (!results.at(-1)?.meta.changes) {
      throw new Refusal(
        410,
        "CLOSED",
        "The change was cancelled or closed while it was approved.",
      );
    }
  } catch (error) {
    if (error instanceof Refusal) throw error;
    if (!String(error).includes("UNIQUE")) throw error;
    throw new Refusal(
      409,
      "ACTION_PENDING",
      "A device change is still on its way to a server. Try again in a minute.",
    );
  }
  await pokeNodes(env, input.ownerId, Object.keys(input.change.access));
}

export function registerProposalRoutes(
  app: KrynodesApp,
  requireOperator: MiddlewareHandler<KrynodesEnv>,
): void {
  const refused = (
    context: Parameters<MiddlewareHandler<KrynodesEnv>>[0],
    error: unknown,
  ) => {
    if (error instanceof Refusal) {
      return context.json(
        { code: error.code, message: error.message },
        error.status,
      );
    }
    throw error;
  };

  app.get("/api/proposals", requireOperator, async (context) => {
    const ownerId = context.get("identity").id;
    const now = Date.now();
    await sweepExpired(context.env, ownerId, now);
    const rows = await context.env.DB.prepare(
      `SELECT id, change, title, version, approvals, status, opened_by, opened_at, expires_at, closed_at
       FROM proposals WHERE owner_user_id = ? AND (status = 'open' OR closed_at >= ?)
       ORDER BY opened_at DESC, id DESC LIMIT 50`,
    )
      .bind(ownerId, new Date(now - 30 * DAY_MS).toISOString())
      .all<ProposalRow>();
    const fleet = await loadFleet(context.env.DB, ownerId);
    return context.json({
      proposals: rows.results.toReversed().map((row) => {
        const approvals = JSON.parse(row.approvals) as Approval[];
        const change = decodeChange(row.change);
        return {
          id: row.id,
          change: row.change,
          title: row.title,
          status: row.status,
          approvals: approvals.map((approval) => approval.credentialId),
          openedBy: row.opened_by,
          openedAt: row.opened_at,
          expiresAt: row.expires_at,
          closedAt: row.closed_at,
          missing:
            row.status === "open" && change
              ? missing(fleet, change, approvals)
              : null,
        };
      }),
    });
  });

  app.get("/api/proposals/history", requireOperator, async (context) => {
    const ownerId = context.get("identity").id;
    const [at, id] = (context.req.query("before") ?? "").split("|");
    const [rows, devices] = await Promise.all([
      context.env.DB.prepare(
        `SELECT id, change, title, version, approvals, status, opened_by, opened_at, expires_at, closed_at
         FROM proposals
         WHERE owner_user_id = ?1 AND status <> 'open'
           AND (?2 IS NULL OR closed_at < ?2 OR (closed_at = ?2 AND id < ?3))
         ORDER BY closed_at DESC, id DESC LIMIT ?4`,
      )
        .bind(ownerId, at || null, id ?? "", CHANGES_PAGE + 1)
        .all<ProposalRow>(),
      context.env.DB.prepare(
        "SELECT id, name FROM devices WHERE owner_user_id = ?",
      )
        .bind(ownerId)
        .all<{ id: string; name: string }>(),
    ]);
    const page = rows.results.slice(0, CHANGES_PAGE);
    const known = new Map(
      devices.results.map((device) => [device.id, device.name]),
    );
    const last = page.at(-1);
    return context.json({
      changes: page.map((row) => {
        const change = decodeChange(row.change);
        const names = new Map(known);
        for (const key of change?.core ?? []) {
          if (!names.has(key.id)) names.set(key.id, key.name);
        }
        const name = (device: string) =>
          names.get(device) ?? "A removed device";
        return {
          id: row.id,
          title: row.title,
          status: row.status,
          version: row.version,
          targets: Object.keys(change?.access ?? {}),
          openedBy: name(row.opened_by),
          approvedBy: (
            JSON.parse(row.approvals) as { credentialId: string }[]
          ).map((approval) => name(approval.credentialId)),
          openedAt: row.opened_at,
          closedAt: row.closed_at,
        };
      }),
      next:
        rows.results.length > CHANGES_PAGE && last
          ? `${last.closed_at}|${last.id}`
          : null,
    });
  });

  app.post("/api/proposals", requireOperator, async (context) => {
    const parsed = openSchema.safeParse(await readJson(context));
    if (!parsed.success) return invalidRequest(context);
    const change = decodeChange(parsed.data.change);
    if (!change) return invalidRequest(context);
    const identity = context.get("identity");
    const now = Date.now();
    try {
      await sweepExpired(context.env, identity.id, now);
      const fleet = await loadFleet(context.env.DB, identity.id);
      checkChange(context.env, fleet, change, now);
      const open = await context.env.DB.prepare(
        "SELECT COUNT(*) AS n FROM proposals WHERE owner_user_id = ? AND status = 'open'",
      )
        .bind(identity.id)
        .first<{ n: number }>();
      if ((open?.n ?? 0) >= MAX_OPEN) {
        throw new Refusal(
          409,
          "TOO_MANY",
          "Five changes are already waiting. Approve or cancel one first.",
        );
      }
      const bytes = fromB64url(parsed.data.change);
      await verifyApproval(context.env, fleet, bytes, parsed.data.approval);
      const approvals = [parsed.data.approval];
      const id = crypto.randomUUID();
      const title = describe(fleet, change);
      const openedBy = parsed.data.approval.credentialId;
      const waiting = missing(fleet, change, approvals);
      if (waiting === null) {
        await apply(context.env, {
          ownerId: identity.id,
          email: identity.email,
          fleet,
          id,
          text: parsed.data.change,
          change,
          title,
          approvals,
          openedBy,
          isNew: true,
          now,
        });
        return context.json({ id, status: "applied" }, 201);
      }
      await context.env.DB.prepare(
        `INSERT INTO proposals (id, owner_user_id, change, title, version, approvals, status, opened_by, opened_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)`,
      )
        .bind(
          id,
          identity.id,
          parsed.data.change,
          title,
          change.version,
          JSON.stringify(approvals),
          openedBy,
          new Date(now).toISOString(),
          change.expiresAt,
        )
        .run();
      await notify(context.env, fleet, title, openedBy);
      return context.json({ id, status: "open", missing: waiting }, 201);
    } catch (error) {
      return refused(context, error);
    }
  });

  app.post("/api/proposals/:id/approvals", requireOperator, async (context) => {
    const parsed = approveSchema.safeParse(await readJson(context));
    if (!parsed.success) return invalidRequest(context);
    const identity = context.get("identity");
    const now = Date.now();
    try {
      await sweepExpired(context.env, identity.id, now);
      const row = await context.env.DB.prepare(
        `SELECT id, change, title, version, approvals, status, opened_by, opened_at, expires_at, closed_at
         FROM proposals WHERE id = ? AND owner_user_id = ?`,
      )
        .bind(context.req.param("id"), identity.id)
        .first<ProposalRow>();
      if (!row)
        throw new Refusal(404, "NOT_FOUND", "The change was not found.");
      if (row.status !== "open") {
        throw new Refusal(410, "CLOSED", `The change is ${row.status}.`);
      }
      const change = decodeChange(row.change);
      if (!change)
        throw new Refusal(400, "BAD_CHANGE", "The change is malformed.");
      const approvals = JSON.parse(row.approvals) as Approval[];
      if (
        approvals.some(
          (approval) =>
            approval.credentialId === parsed.data.approval.credentialId,
        )
      ) {
        throw new Refusal(
          409,
          "ALREADY_APPROVED",
          "This device already approved the change. Approve on another trusted device.",
        );
      }
      const fleet = await loadFleet(context.env.DB, identity.id);
      checkChange(context.env, fleet, change, now);
      await verifyApproval(
        context.env,
        fleet,
        fromB64url(row.change),
        parsed.data.approval,
      );
      approvals.push(parsed.data.approval);
      const waiting = missing(fleet, change, approvals);
      if (waiting === null) {
        await apply(context.env, {
          ownerId: identity.id,
          email: identity.email,
          fleet,
          id: row.id,
          text: row.change,
          change,
          title: row.title,
          approvals,
          openedBy: row.opened_by,
          isNew: false,
          now,
        });
        return context.json({ id: row.id, status: "applied" });
      }
      const stored = await context.env.DB.prepare(
        "UPDATE proposals SET approvals = ? WHERE id = ? AND status = 'open' AND approvals = ?",
      )
        .bind(JSON.stringify(approvals), row.id, row.approvals)
        .run();
      if (!stored.meta.changes) {
        throw new Refusal(
          409,
          "APPROVED_TOGETHER",
          "Another approval arrived at the same moment. Approve again.",
        );
      }
      return context.json({ id: row.id, status: "open", missing: waiting });
    } catch (error) {
      return refused(context, error);
    }
  });

  app.post("/api/proposals/:id/cancel", requireOperator, async (context) => {
    const result = await context.env.DB.prepare(
      `UPDATE proposals SET status = 'cancelled', closed_at = ?
       WHERE id = ? AND owner_user_id = ? AND status = 'open'`,
    )
      .bind(
        new Date().toISOString(),
        context.req.param("id"),
        context.get("identity").id,
      )
      .run();
    if (result.meta.changes === 0) {
      return context.json(
        { code: "NOT_FOUND", message: "No open change was found." },
        404,
      );
    }
    return context.json({ cancelled: true });
  });
}
