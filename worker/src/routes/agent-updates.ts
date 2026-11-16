import { pokeSoon } from "../fleet/client";
import type { MiddlewareHandler } from "hono";

import { compareVersions } from "@krynodes/protocol";

import {
  canUpdateRemotely,
  checkAgentRelease,
  readAgentRelease,
  requestAutoUpdates,
} from "../agent/releases";
import type { KrynodesApp, KrynodesEnv } from "./shared";

export function registerAgentUpdateRoutes(
  app: KrynodesApp,
  requireOperator: MiddlewareHandler<KrynodesEnv>,
): void {
  app.post("/api/nodes/:id/update", requireOperator, async (context) => {
    const node = await context.env.DB.prepare(
      `SELECT id, agent_version FROM nodes
       WHERE id = ? AND owner_user_id = ? AND kind = 'server' AND enrolled_at IS NOT NULL`,
    )
      .bind(context.req.param("id"), context.get("identity").id)
      .first<{ id: string; agent_version: string | null }>();
    if (!node) return context.json({ code: "NOT_FOUND" }, 404);

    const { version } = await readAgentRelease(context.env.DB);
    if (!version) {
      return context.json(
        { code: "NO_RELEASE", message: "No agent release is known yet." },
        409,
      );
    }
    if (!canUpdateRemotely(node.agent_version)) {
      return context.json(
        {
          code: "AGENT_CANNOT_UPDATE",
          message: "This agent cannot update itself. Run the update command.",
        },
        409,
      );
    }
    if (compareVersions(node.agent_version!, version) >= 0) {
      return context.json(
        { code: "UP_TO_DATE", message: "The agent is already up to date." },
        409,
      );
    }

    await context.env.DB.prepare(
      `UPDATE nodes SET update_requested_version = ?, update_requested_at = ?,
             update_attempts = 1, update_error = NULL
       WHERE id = ?`,
    )
      .bind(version, new Date().toISOString(), node.id)
      .run();
    pokeSoon(context, context.get("identity").id, [node.id]);
    return context.json({ version }, 202);
  });

  app.post("/api/agent-release/check", requireOperator, async (context) => {
    const release = await checkAgentRelease(context.env.DB);
    const requested = release.version
      ? await requestAutoUpdates(context.env.DB, release.version)
      : 0;
    return context.json({ ...release, requested });
  });
}
