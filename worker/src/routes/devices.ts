import {
  MIN_AGENT_VERSION,
  trustChangeSchema,
  type TrustChange,
} from "@krynodes/protocol";
import type { MiddlewareHandler } from "hono";
import { z } from "zod";

import { createBatch, sweepStatements } from "../actions/store";
import { pokeSoon } from "../fleet/client";
import { fromB64url } from "../lib/b64url";
import { notYours } from "../trust/approval";
import { agentCurrent, loadFleet, type Fleet } from "../trust/fleet";
import {
  invalidRequest,
  readJson,
  type KrynodesApp,
  type KrynodesContext,
  type KrynodesEnv,
} from "./shared";

const b64url = z
  .string()
  .min(1)
  .max(65536)
  .regex(/^[A-Za-z0-9_-]+$/u);

const deviceSchema = z.strictObject({
  id: z
    .string()
    .min(1)
    .max(1400)
    .regex(/^[A-Za-z0-9_-]+$/u),
  name: z.string().trim().min(1).max(40),
  alg: z.union([z.literal(-7), z.literal(-257)]),
  publicKey: b64url,
  verifies: z.boolean().optional(),
});

const renameSchema = z.strictObject({
  name: z.string().trim().min(1).max(40),
});

const firstSchema = z.strictObject({
  changes: z.array(b64url).min(1).max(100),
});

function readChange(text: string): TrustChange | null {
  try {
    const parsed = trustChangeSchema.safeParse(
      JSON.parse(new TextDecoder().decode(fromB64url(text))),
    );
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

const sameIds = (a: string[], b: string[]) =>
  a.length === b.length && a.every((id) => b.includes(id));

function firstTrustAllowed(fleet: Fleet, change: TrustChange): boolean {
  const [nodeId, ...others] = Object.keys(change.access);
  if (!nodeId || others.length > 0 || !change.core) return false;
  const core = change.core.map((key) => key.id);
  const access = change.access[nodeId] ?? [];
  const active = fleet.devices.filter((device) => device.removedAt === null);
  const known = change.core.every((key) =>
    active.some(
      (device) =>
        device.id === key.id &&
        device.publicKey === key.publicKey &&
        device.alg === key.alg,
    ),
  );
  if (!known) return false;
  const expected =
    fleet.core.length > 0 ? fleet.core : core.length === 1 ? core : null;
  if (!expected || !sameIds(core, expected)) return false;
  const founding = expected.length < 2;
  if (!sameIds(access, founding ? core : [])) return false;
  return change.requireUv === true && change.passphrase === null;
}

export function registerDeviceRoutes(
  app: KrynodesApp,
  requireOperator: MiddlewareHandler<KrynodesEnv>,
): void {
  app.get("/api/devices", requireOperator, async (context) => {
    const identity = context.get("identity");
    const fleet = await loadFleet(context.env.DB, identity.id);
    return context.json({
      devices: fleet.devices
        .filter((device) => device.removedAt === null)
        .map((device) => ({
          id: device.id,
          name: device.name,
          alg: device.alg,
          publicKey: device.publicKey,
          createdAt: device.createdAt,
          lastUsedAt: device.lastUsedAt,
          verifies: device.verifies,
          fingerprint: device.fingerprint,
          core: fleet.core.includes(device.id),
          owner: device.account,
          mine: device.account === identity.email,
        })),
    });
  });

  const ownDevice = async (context: KrynodesContext) => {
    const identity = context.get("identity");
    const fleet = await loadFleet(context.env.DB, identity.id);
    const device = fleet.devices.find(
      (entry) =>
        entry.id === context.req.param("id") && entry.removedAt === null,
    );
    if (!device) {
      return {
        fleet,
        refused: context.json(
          { code: "NOT_FOUND", message: "The device was not found." },
          404,
        ),
      };
    }
    const other = notYours(device, identity.email);
    return {
      fleet,
      refused: other
        ? context.json({ code: other.code, message: other.message }, 403)
        : null,
    };
  };

  app.post("/api/devices", requireOperator, async (context) => {
    const parsed = deviceSchema.safeParse(await readJson(context));
    if (!parsed.success) return invalidRequest(context);
    const device = parsed.data;
    const fleet = await loadFleet(context.env.DB, context.get("identity").id);
    const twin = fleet.devices.find(
      (entry) =>
        entry.removedAt === null &&
        (entry.id === device.id || entry.publicKey === device.publicKey),
    );
    if (twin) {
      return context.json(
        {
          code: "DEVICE_EXISTS",
          message: `This passkey is already registered as ${twin.name}.`,
        },
        409,
      );
    }
    if (device.verifies !== true) {
      return context.json(
        {
          code: "CANNOT_VERIFY",
          message:
            "This passkey cannot verify a fingerprint. Choose Use a phone or a security key instead.",
        },
        422,
      );
    }
    try {
      await context.env.DB.prepare(
        `INSERT INTO devices (id, owner_user_id, name, alg, public_key, created_at, verifies, account)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
        .bind(
          device.id,
          context.get("identity").id,
          device.name,
          device.alg,
          device.publicKey,
          new Date().toISOString(),
          device.verifies === undefined ? null : device.verifies ? 1 : 0,
          context.get("identity").email,
        )
        .run();
    } catch (error) {
      if (!String(error).includes("UNIQUE")) throw error;
      return context.json(
        {
          code: "DEVICE_EXISTS",
          message: "This device is already registered.",
        },
        409,
      );
    }
    return context.json({ id: device.id }, 201);
  });

  app.patch("/api/devices/:id", requireOperator, async (context) => {
    const parsed = renameSchema.safeParse(await readJson(context));
    if (!parsed.success) return invalidRequest(context);
    const { refused } = await ownDevice(context);
    if (refused) return refused;
    const result = await context.env.DB.prepare(
      "UPDATE devices SET name = ? WHERE id = ? AND owner_user_id = ? AND removed_at IS NULL",
    )
      .bind(
        parsed.data.name,
        context.req.param("id"),
        context.get("identity").id,
      )
      .run();
    if (result.meta.changes === 0) {
      return context.json(
        { code: "NOT_FOUND", message: "The device was not found." },
        404,
      );
    }
    return context.json({ name: parsed.data.name });
  });

  app.delete("/api/devices/:id", requireOperator, async (context) => {
    const ownerId = context.get("identity").id;
    const id = context.req.param("id");
    const { fleet, refused } = await ownDevice(context);
    if (refused) return refused;
    if (fleet.core.includes(id)) {
      return context.json(
        {
          code: "CORE_DEVICE",
          message: "A trusted device leaves only through an approved change.",
        },
        409,
      );
    }
    const result = await context.env.DB.prepare(
      "UPDATE devices SET removed_at = ? WHERE id = ? AND owner_user_id = ? AND removed_at IS NULL",
    )
      .bind(new Date().toISOString(), id, ownerId)
      .run();
    if (result.meta.changes === 0) {
      return context.json(
        { code: "NOT_FOUND", message: "The device was not found." },
        404,
      );
    }
    return context.json({ removed: true });
  });

  app.post("/api/trust", requireOperator, async (context) => {
    const parsed = firstSchema.safeParse(await readJson(context));
    if (!parsed.success) return invalidRequest(context);
    const db = context.env.DB;
    const identity = context.get("identity");
    const now = Date.now();
    const fleet = await loadFleet(db, identity.id);
    const origin = new URL(context.env.PUBLIC_ORIGIN);
    const changes = parsed.data.changes.map((text) => ({
      text,
      change: readChange(text),
    }));
    if (
      changes.some(
        ({ change }) =>
          !change ||
          change.origin !== origin.origin ||
          change.rpId !== origin.hostname ||
          !firstTrustAllowed(fleet, change),
      )
    ) {
      return invalidRequest(context);
    }
    const nodeIds = changes.map(
      ({ change }) => Object.keys(change!.access)[0]!,
    );
    if (new Set(nodeIds).size !== nodeIds.length) {
      return invalidRequest(context);
    }
    for (const nodeId of nodeIds) {
      const node = fleet.nodes.find((entry) => entry.id === nodeId);
      if (!node) {
        return context.json(
          { code: "NOT_FOUND", message: "A server was not found." },
          404,
        );
      }
      if (!agentCurrent(node)) {
        return context.json(
          {
            code: "NEEDS_AGENT",
            message: `${node.name} needs agent ${MIN_AGENT_VERSION} or later.`,
          },
          422,
        );
      }
      if ((node.report?.core.length ?? 0) > 0) {
        return context.json(
          {
            code: "TRUST_EXISTS",
            message:
              "A server already trusts devices. Change them with an approved change.",
          },
          409,
        );
      }
    }
    const batch = createBatch(db, {
      action: "trust",
      mode: "parallel",
      targets: changes.map(({ text }, index) => ({
        nodeId: nodeIds[index]!,
        kind: "trust" as const,
        name: "devices",
        signed: { change: text, approvals: [] },
      })),
      requestedBy: identity.email,
      now,
    });
    await db.batch(sweepStatements(db, now));
    try {
      await db.batch(batch.statements);
    } catch (error) {
      if (!String(error).includes("UNIQUE")) throw error;
      return context.json(
        {
          code: "ACTION_PENDING",
          message: "A device change is still on its way to a server.",
        },
        409,
      );
    }
    pokeSoon(context, identity.id, nodeIds);
    return context.json({ queued: changes.length }, 202);
  });
}
