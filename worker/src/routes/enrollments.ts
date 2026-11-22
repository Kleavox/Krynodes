import { z } from "zod";

import { readAgentRelease } from "../agent/releases";
import type { KrynodesApp } from "../env";
import { randomToken, sha256 } from "../lib/crypto";
import { agentOrigin, invalidRequest, readJson } from "./shared";

const ENROLLMENT_TTL_MS = 60 * 60_000;
const SHELL_SAFE = /^[A-Za-z0-9:/._,-]+$/u;
const TAIL = /\nmain "\$@"\n$/u;
const DOWNLOADS = "https://github.com/Kleavox/Krynodes/releases/download";

const createSchema = z.strictObject({
  name: z.string().trim().min(1).max(64),
  trust: z.array(z.string().min(1).max(1400)).min(1).max(20),
});

const refusal = (message: string) =>
  `#!/bin/sh\necho "${message}" >&2\nexit 1\n`;

const script = (body: string, status = 200) =>
  new Response(body, {
    status,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
    },
  });

export function registerEnrollmentRoutes(app: KrynodesApp): void {
  app.post("/api/enrollments", async (context) => {
    const body = createSchema.safeParse(await readJson(context));
    if (
      !body.success ||
      new Set(body.data.trust).size !== body.data.trust.length
    ) {
      return invalidRequest(context);
    }
    const { name, trust } = body.data;
    const db = context.env.DB;
    const known = await db
      .prepare(
        "SELECT COUNT(*) AS count FROM devices WHERE id IN (SELECT value FROM json_each(?))",
      )
      .bind(JSON.stringify(trust))
      .first<{ count: number }>();
    if (known?.count !== trust.length) {
      return context.json(
        {
          code: "UNKNOWN_DEVICE",
          message: "A passkey to trust is not registered here.",
        },
        422,
      );
    }
    if (
      await db.prepare("SELECT 1 FROM nodes WHERE name = ?").bind(name).first()
    ) {
      return context.json(
        {
          code: "NAME_TAKEN",
          message: `${name} is already a server. Choose another name.`,
        },
        409,
      );
    }
    const id = crypto.randomUUID();
    const token = randomToken();
    const now = Date.now();
    const expiresAt = new Date(now + ENROLLMENT_TTL_MS).toISOString();
    await db
      .prepare(
        "INSERT INTO enrollments (id, token_hash, name, trust, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
      )
      .bind(
        id,
        await sha256(token),
        name,
        JSON.stringify(trust),
        new Date(now).toISOString(),
        expiresAt,
      )
      .run();
    return context.json(
      {
        id,
        command: `curl -fsSL ${agentOrigin(context.env)}/i/${token} | sudo sh`,
        expiresAt,
      },
      201,
    );
  });

  app.get("/api/enrollments/:id", async (context) => {
    const row = await context.env.DB.prepare(
      "SELECT node_id FROM enrollments WHERE id = ?",
    )
      .bind(context.req.param("id"))
      .first<{ node_id: string | null }>();
    return row
      ? context.json({ nodeId: row.node_id })
      : context.json({ code: "NOT_FOUND" }, 404);
  });

  app.get("/i/:token", async (context) => {
    const token = context.req.param("token");
    const refused = script(
      refusal(
        "This install command was already used or has expired. Create a new one in Krynodes.",
      ),
    );
    if (!/^[A-Za-z0-9_-]{20,128}$/u.test(token)) return refused;
    const db = context.env.DB;
    const row = await db
      .prepare(
        "SELECT trust FROM enrollments WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
      )
      .bind(await sha256(token), new Date().toISOString())
      .first<{ trust: string }>();
    if (!row) return refused;
    const { version } = await readAgentRelease(db);
    if (!version) {
      return script(
        refusal(
          "Krynodes has not found an agent release yet. Check for one in Krynodes, then create a new install command.",
        ),
      );
    }
    const devices = await db
      .prepare(
        "SELECT id, alg, public_key FROM devices WHERE id IN (SELECT value FROM json_each(?)) ORDER BY id",
      )
      .bind(row.trust)
      .all<{ id: string; alg: string; public_key: string }>();
    if (devices.results.length === 0) {
      return script(
        refusal(
          "None of the passkeys for this install command are registered any more. Create a new one in Krynodes.",
        ),
      );
    }
    const args = [
      "--endpoint",
      agentOrigin(context.env),
      "--token",
      token,
      "--origin",
      context.env.PUBLIC_ORIGIN,
      "--trust",
      devices.results
        .map((device) => `${device.id}.${device.alg}.${device.public_key}`)
        .join(","),
    ];
    const installer = await context.env.ASSETS.fetch(
      new Request(new URL("/install.sh", context.req.url)),
    );
    const text = installer.ok ? await installer.text() : "";
    const pinned = `${DOWNLOADS}/agent-v${version}`;
    if (
      !TAIL.test(text) ||
      ![pinned, ...args].every((value) => SHELL_SAFE.test(value))
    ) {
      console.error("[kry] the installer cannot be served");
      return script(
        refusal(
          "Krynodes cannot serve the installer now. Try again in a minute.",
        ),
        503,
      );
    }
    return script(
      text.replace(
        TAIL,
        () => `\nKRY_DOWNLOAD_BASE='${pinned}'\nmain ${args.join(" ")}\n`,
      ),
    );
  });
}
