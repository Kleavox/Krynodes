import { agentSupported, MIN_AGENT } from "@krynodes/protocol";
import type { MiddlewareHandler } from "hono";
import { z } from "zod";

import type { KrynodesApp, KrynodesEnv } from "../env";
import { announce, upgradeInto } from "../fleet/client";
import { randomToken, readBearerToken, sha256 } from "../lib/crypto";
import { isUnique, readJson } from "./shared";

const agentRateLimit: MiddlewareHandler<KrynodesEnv> = async (
  context,
  next,
) => {
  const limiter = context.env.AGENT_RATE_LIMIT;
  if (limiter) {
    const key = context.req.header("cf-connecting-ip") ?? "unknown";
    const { success } = await limiter.limit({ key });
    if (!success) {
      return context.json(
        { code: "RATE_LIMITED", message: "Too many agent requests." },
        429,
      );
    }
  }
  await next();
};

const enrollSchema = z.strictObject({
  hostname: z.string().min(1).max(255),
  os: z.string().min(1).max(64),
  arch: z.string().min(1).max(64),
  kernel: z.string().min(1).max(128),
  version: z.string().min(1).max(64),
});

export function registerAgentRoutes(app: KrynodesApp): void {
  app.use("/api/agent/*", agentRateLimit);
  app.use("/i/*", agentRateLimit);

  app.post("/api/agent/enroll", async (context) => {
    const token = readBearerToken(context.req.header("authorization"));
    const host = enrollSchema.safeParse(await readJson(context));
    if (!token || !host.success) {
      return context.json({ code: "INVALID_ENROLLMENT" }, 400);
    }
    if (!agentSupported(host.data.version)) {
      return context.json(
        {
          code: "AGENT_UPDATE_REQUIRED",
          message: `Agents before ${MIN_AGENT} are no longer supported. Update the agent on the server.`,
        },
        426,
      );
    }
    const db = context.env.DB;
    const now = new Date().toISOString();
    const invite = await db
      .prepare(
        "SELECT id, name FROM enrollments WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
      )
      .bind(await sha256(token), now)
      .first<{ id: string; name: string }>();
    if (!invite) return context.json({ code: "INVALID_ENROLLMENT" }, 401);
    const nodeId = crypto.randomUUID();
    const agentToken = randomToken();
    let created: D1Result[];
    try {
      created = await db.batch([
        db
          .prepare(
            `INSERT INTO nodes (id, name, agent_token_hash, enrolled_at, hostname, os, arch, kernel, version)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9
             WHERE EXISTS (SELECT 1 FROM enrollments WHERE id = ?10 AND used_at IS NULL)`,
          )
          .bind(
            nodeId,
            invite.name,
            await sha256(agentToken),
            now,
            host.data.hostname,
            host.data.os,
            host.data.arch,
            host.data.kernel,
            host.data.version,
            invite.id,
          ),
        db
          .prepare(
            "UPDATE enrollments SET used_at = ?, node_id = ? WHERE id = ? AND used_at IS NULL",
          )
          .bind(now, nodeId, invite.id),
      ]);
    } catch (error) {
      if (!isUnique(error)) throw error;
      return context.json(
        {
          code: "NAME_TAKEN",
          message: `${invite.name} is already a server. Create a new install command with another name.`,
        },
        409,
      );
    }
    if (!created[0]?.meta.changes) {
      return context.json({ code: "INVALID_ENROLLMENT" }, 401);
    }
    await announce(context.env, ["fleet"]);
    return context.json({ nodeId, token: agentToken });
  });

  app.get("/api/agent/stream", async (context) => {
    if (context.req.header("upgrade")?.toLowerCase() !== "websocket") {
      return context.json({ code: "UPGRADE_REQUIRED" }, 426);
    }
    const token = readBearerToken(context.req.header("authorization"));
    const node = token
      ? await context.env.DB.prepare(
          "SELECT id FROM nodes WHERE agent_token_hash = ?",
        )
          .bind(await sha256(token))
          .first<{ id: string }>()
      : null;
    if (!node) return context.json({ code: "UNAUTHORIZED" }, 401);
    const version =
      /^kry-agent\/(\S+)/u.exec(context.req.header("user-agent") ?? "")?.[1] ??
      "";
    return upgradeInto(context.env, context.req.raw, "/connect", {
      "x-kry-node": node.id,
      "x-kry-version": version,
    });
  });
}
