import { assertionSchema } from "@krynodes/protocol";
import { z } from "zod";

import type { KrynodesApp } from "../env";
import { fromB64url } from "../lib/b64url";
import { randomToken } from "../lib/crypto";
import { assertionSynced, verifyAssertion } from "../lib/webauthn";
import { invalidRequest, isUnique, readJson } from "./shared";

const CHALLENGE_MS = 5 * 60_000;

const b64url = (max: number) =>
  z.string().regex(new RegExp(`^[A-Za-z0-9_-]{1,${max}}$`, "u"));

const registerSchema = z.strictObject({
  id: b64url(1400),
  name: z.string().trim().min(1).max(40),
  alg: z.union([z.literal(-7), z.literal(-257)]),
  publicKey: b64url(2048),
  challenge: b64url(128),
  assertion: assertionSchema,
});

const renameSchema = z.strictObject({ name: z.string().trim().min(1).max(40) });

const TRUSTED = `EXISTS (
  SELECT 1 FROM node_trust t
  WHERE EXISTS (SELECT 1 FROM json_each(t.core) WHERE value = d.id)
     OR EXISTS (SELECT 1 FROM json_each(t.access) WHERE value = d.id))`;

interface DeviceRow {
  id: string;
  name: string;
  alg: string;
  public_key: string;
  synced: number;
  created_at: string;
  trusted: number;
}

const SELECT = `SELECT d.id, d.name, d.alg, d.public_key, d.synced, d.created_at, ${TRUSTED} AS trusted FROM devices d`;

export function registerDeviceRoutes(app: KrynodesApp): void {
  app.get("/api/devices", async (context) => {
    const rows = await context.env.DB.prepare(
      `${SELECT} ORDER BY d.id`,
    ).all<DeviceRow>();
    return context.json(
      rows.results.map((row) => ({
        id: row.id,
        name: row.name,
        alg: Number(row.alg),
        publicKey: row.public_key,
        synced: row.synced === 1,
        createdAt: row.created_at,
        trusted: row.trusted === 1,
      })),
    );
  });

  app.post("/api/devices/register/options", async (context) => {
    const db = context.env.DB;
    const challenge = randomToken();
    const now = Date.now();
    const expiresAt = new Date(now + CHALLENGE_MS).toISOString();
    const [, , existing] = await Promise.all([
      db
        .prepare(
          "DELETE FROM settings WHERE key LIKE 'challenge:%' AND value <= ?",
        )
        .bind(new Date(now).toISOString())
        .run(),
      db
        .prepare("INSERT INTO settings (key, value) VALUES (?, ?)")
        .bind(`challenge:${challenge}`, expiresAt)
        .run(),
      db.prepare("SELECT id FROM devices ORDER BY id").all<{ id: string }>(),
    ]);
    const { id, email } = context.get("identity");
    return context.json({
      challenge,
      rpId: new URL(context.env.PUBLIC_ORIGIN).hostname,
      user: { id, name: email },
      exclude: existing.results.map((row) => row.id),
      expiresAt,
    });
  });

  app.post("/api/devices/register", async (context) => {
    const body = registerSchema.safeParse(await readJson(context));
    if (!body.success) return invalidRequest(context);
    const { id, name, alg, publicKey, challenge, assertion } = body.data;
    const db = context.env.DB;
    const spent = await db
      .prepare("DELETE FROM settings WHERE key = ? AND value > ?")
      .bind(`challenge:${challenge}`, new Date().toISOString())
      .run();
    if (!spent.meta.changes) {
      return context.json(
        {
          code: "INVALID_CHALLENGE",
          message: "The passkey request expired. Try again.",
        },
        400,
      );
    }
    const origin = new URL(context.env.PUBLIC_ORIGIN);
    let verified: { uv: boolean };
    try {
      if (assertion.credentialId !== id) throw new Error("another credential");
      verified = await verifyAssertion({ alg, publicKey }, assertion, {
        origin: origin.origin,
        rpId: origin.hostname,
        challenge: fromB64url(challenge),
      });
    } catch {
      return context.json(
        {
          code: "INVALID_PROOF",
          message: "The passkey did not prove it holds its key. Try again.",
        },
        400,
      );
    }
    if (!verified.uv) {
      return context.json(
        {
          code: "CANNOT_VERIFY",
          message:
            "This passkey does not ask for a fingerprint, face or PIN. Choose Use a phone or a security key instead.",
        },
        422,
      );
    }
    const twin = await db
      .prepare("SELECT name FROM devices WHERE id = ? OR public_key = ?")
      .bind(id, publicKey)
      .first<{ name: string }>();
    const exists = {
      code: "DEVICE_EXISTS",
      message: `This passkey is already registered${twin ? ` as ${twin.name}` : ""}.`,
    };
    if (twin) return context.json(exists, 409);
    try {
      await db
        .prepare(
          "INSERT INTO devices (id, name, alg, public_key, synced, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(
          id,
          name,
          String(alg),
          publicKey,
          assertionSynced(assertion.authenticatorData) ? 1 : 0,
          new Date().toISOString(),
        )
        .run();
    } catch (error) {
      if (!isUnique(error)) throw error;
      return context.json(exists, 409);
    }
    return context.json({ id }, 201);
  });

  app.patch("/api/devices/:id", async (context) => {
    const body = renameSchema.safeParse(await readJson(context));
    if (!body.success) return invalidRequest(context);
    const renamed = await context.env.DB.prepare(
      "UPDATE devices SET name = ? WHERE id = ?",
    )
      .bind(body.data.name, context.req.param("id"))
      .run();
    return renamed.meta.changes
      ? context.json({ name: body.data.name })
      : context.json(
          { code: "NOT_FOUND", message: "The passkey was not found." },
          404,
        );
  });

  app.delete("/api/devices/:id", async (context) => {
    const row = await context.env.DB.prepare(`${SELECT} WHERE d.id = ?`)
      .bind(context.req.param("id"))
      .first<DeviceRow>();
    if (!row) {
      return context.json(
        { code: "NOT_FOUND", message: "The passkey was not found." },
        404,
      );
    }
    if (row.trusted === 1) {
      return context.json(
        {
          code: "STILL_TRUSTED",
          message: `${row.name} is trusted by a server. Take it out of the trust first.`,
        },
        409,
      );
    }
    await context.env.DB.prepare("DELETE FROM devices WHERE id = ?")
      .bind(row.id)
      .run();
    return context.json({ removed: true });
  });
}
