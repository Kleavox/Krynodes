import type { MiddlewareHandler } from "hono";
import { z } from "zod";

import type { Env } from "../env";
import { randomToken, sha256 } from "../lib/crypto";
import { liveRange, readNetwork } from "../network/document";
import { loadFleet, type Fleet } from "../trust/fleet";
import { confirmed, confirmingDevice } from "../trust/intent";
import { agentRateLimit } from "./agent";
import {
  agentOrigin,
  invalidRequest,
  readJson,
  type KrynodesApp,
  type KrynodesEnv,
} from "./shared";

const ENROLLMENT_TTL_MS = 30 * 60_000;

const setupSchema = z.object({
  recommended: z.boolean().default(false),
  docker: z.boolean().default(false),
  rebootHour: z.number().int().min(0).max(23).nullable().default(null),
  network: z.boolean().default(false),
});

type Setup = z.infer<typeof setupSchema>;

const SHELL_SAFE = /^[A-Za-z0-9._:/,=+-]+$/u;
const TAIL = /\nmain "\$@"\n$/u;

const REFUSED =
  '#!/bin/sh\necho "This install command was already used or has expired. Create a new one in Krynodes." >&2\nexit 1\n';

const commandFor = (env: Env, token: string) =>
  `curl -fsSL ${agentOrigin(env)}/i/${token} | sudo sh`;

function readSetup(text: string | null): Setup {
  try {
    const parsed = setupSchema.safeParse(JSON.parse(text ?? "{}"));
    return parsed.success ? parsed.data : setupSchema.parse({});
  } catch {
    return setupSchema.parse({});
  }
}

function installArgs(
  env: Env,
  token: string,
  fleet: Fleet,
  setup: Setup,
  device: string | null,
  range: string | null,
): string[] {
  const args = [agentOrigin(env), token];
  const core = fleet.devices.filter((item) => fleet.core.includes(item.id));
  if (core.length > 0) {
    args.push("--trust", env.PUBLIC_ORIGIN);
    if (core.length < 2) args.push("--grant");
    else if (device && fleet.core.includes(device)) {
      args.push("--access", device);
    }
    args.push(
      "--",
      ...core.map((item) => `${item.id}.${item.alg}.${item.publicKey}`),
    );
  }
  const steps = [
    ...(setup.recommended ? ["recommended"] : []),
    ...(setup.docker ? ["docker"] : []),
  ];
  if (steps.length > 0) {
    args.push("--setup", steps.join(","));
    if (setup.recommended && setup.rebootHour !== null) {
      args.push("--reboot-hour", String(setup.rebootHour));
    }
  }
  if (setup.network && range) args.push("--network", range);
  return args;
}

const script = (body: string, status = 200) =>
  new Response(body, {
    status,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
    },
  });

export function registerEnrollmentRoutes(
  app: KrynodesApp,
  requireOperator: MiddlewareHandler<KrynodesEnv>,
): void {
  app.post("/api/enrollments", requireOperator, async (context) => {
    const setup = setupSchema.safeParse((await readJson(context)) ?? {});
    if (!setup.success) return invalidRequest(context);
    const fleet = await loadFleet(context.env.DB, context.get("identity").id);
    const refused = await confirmed(context, "enrollment.create", "new", fleet);
    if (refused) return refused;
    const id = crypto.randomUUID();
    const token = randomToken();
    const expiresAt = new Date(Date.now() + ENROLLMENT_TTL_MS).toISOString();
    await context.env.DB.prepare(
      `INSERT INTO enrollment_tokens (id, owner_user_id, token_hash, expires_at, setup, device_id)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        id,
        context.get("identity").id,
        await sha256(token),
        expiresAt,
        JSON.stringify(setup.data),
        confirmingDevice(context),
      )
      .run();
    return context.json(
      {
        id,
        enrollmentToken: token,
        enrollmentExpiresAt: expiresAt,
        command: commandFor(context.env, token),
      },
      201,
    );
  });

  app.patch("/api/enrollments/:id", requireOperator, async (context) => {
    const setup = setupSchema.safeParse(await readJson(context));
    if (!setup.success) return invalidRequest(context);
    const db = context.env.DB;
    const owner = context.get("identity").id;
    const result = await db
      .prepare(
        `UPDATE enrollment_tokens SET setup = ?
         WHERE id = ? AND owner_user_id = ? AND used_at IS NULL AND expires_at > ?`,
      )
      .bind(
        JSON.stringify(setup.data),
        context.req.param("id"),
        owner,
        new Date().toISOString(),
      )
      .run();
    if (result.meta.changes > 0) return context.json({ ok: true });
    const known = await db
      .prepare(
        "SELECT id FROM enrollment_tokens WHERE id = ? AND owner_user_id = ?",
      )
      .bind(context.req.param("id"), owner)
      .first();
    return known
      ? context.json(
          {
            code: "ENROLLMENT_CLOSED",
            message: "This install command was already used or has expired.",
          },
          409,
        )
      : context.json({ code: "NOT_FOUND" }, 404);
  });

  app.get("/i/:token", agentRateLimit, async (context) => {
    const token = context.req.param("token");
    if (!/^[A-Za-z0-9_-]{20,128}$/u.test(token)) return script(REFUSED);
    const db = context.env.DB;
    const row = await db
      .prepare(
        `SELECT owner_user_id, setup, device_id FROM enrollment_tokens
         WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`,
      )
      .bind(await sha256(token), new Date().toISOString())
      .first<{
        owner_user_id: string;
        setup: string | null;
        device_id: string | null;
      }>();
    if (!row) return script(REFUSED);
    const args = installArgs(
      context.env,
      token,
      await loadFleet(db, row.owner_user_id),
      readSetup(row.setup),
      row.device_id,
      liveRange(await readNetwork(db, row.owner_user_id)),
    );
    const installer = await context.env.ASSETS.fetch(
      new Request(new URL("/install.sh", context.req.url)),
    );
    const text = installer.ok ? await installer.text() : "";
    if (!TAIL.test(text) || !args.every((arg) => SHELL_SAFE.test(arg))) {
      console.error("[kry] the installer cannot be served");
      return script(
        '#!/bin/sh\necho "Krynodes cannot serve the installer now. Try again in a minute." >&2\nexit 1\n',
        503,
      );
    }
    return script(
      text.replace(
        TAIL,
        () => `\n{\n  kry_args='${args.join(" ")}'\n  main $kry_args\n}\n`,
      ),
    );
  });

  app.get("/api/enrollments/:id", requireOperator, async (context) => {
    const row = await context.env.DB.prepare(
      `SELECT e.expires_at, e.used_at, n.id AS node_id, n.name AS node_name
       FROM enrollment_tokens e
       LEFT JOIN nodes n ON n.id = e.node_id
       WHERE e.id = ? AND e.owner_user_id = ?`,
    )
      .bind(context.req.param("id"), context.get("identity").id)
      .first<{
        expires_at: string;
        used_at: string | null;
        node_id: string | null;
        node_name: string | null;
      }>();
    if (!row) return context.json({ code: "NOT_FOUND" }, 404);
    if (row.used_at) {
      return context.json({
        status: "used",
        node: row.node_id ? { id: row.node_id, name: row.node_name } : null,
      });
    }
    return context.json({
      status: Date.parse(row.expires_at) > Date.now() ? "pending" : "expired",
    });
  });
}
