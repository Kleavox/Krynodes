import { runReleaseCheck } from "./agent/releases";
import { app } from "./app";
import type { Env } from "./env";
import { sendTokenEmail } from "./lib/mail";

export { FleetHub } from "./fleet/hub";

const worker = {
  fetch(request: Request, env: Env, context: ExecutionContext) {
    return app.fetch(request, env, context);
  },
  scheduled(
    _controller: ScheduledController,
    env: Env,
    context: ExecutionContext,
  ): void {
    context.waitUntil(runRetention(env));
    context.waitUntil(runReleaseCheck(env.DB));
    context.waitUntil(remindTokens(env));
  },
};

const REMIND_MS = 30 * 86_400_000;

export async function remindTokens(env: Env, now = Date.now()): Promise<void> {
  const rows = await env.DB.prepare(
    `SELECT cloudflare.owner_user_id AS owner, MAX(web_addresses.expires_at) AS expires,
            cloudflare.reminded_at AS reminded
     FROM cloudflare
     JOIN nodes ON nodes.owner_user_id = cloudflare.owner_user_id
     JOIN web_addresses ON web_addresses.node_id = nodes.id
     WHERE web_addresses.expires_at IS NOT NULL
     GROUP BY cloudflare.owner_user_id`,
  ).all<{ owner: string; expires: string; reminded: string | null }>();
  for (const row of rows.results) {
    const expires = Date.parse(row.expires);
    if (!Number.isFinite(expires) || expires - now > REMIND_MS) continue;
    if (row.reminded && Date.parse(row.reminded) >= expires - REMIND_MS) {
      continue;
    }
    await sendTokenEmail(env, { expiresAt: row.expires });
    await env.DB.prepare(
      "UPDATE cloudflare SET reminded_at = ? WHERE owner_user_id = ?",
    )
      .bind(new Date(now).toISOString(), row.owner)
      .run();
  }
}

export async function runRetention(env: Env): Promise<void> {
  await env.DB.prepare("DELETE FROM node_windows WHERE window_start < ?")
    .bind(new Date(Date.now() - 8 * 86_400_000).toISOString())
    .run();
  await env.DB.prepare(
    `DELETE FROM incidents
     WHERE status = 'RESOLVED'
       AND datetime(resolved_at) < datetime('now', '-180 days')`,
  ).run();
  await env.DB.prepare(
    "DELETE FROM enrollment_tokens WHERE datetime(expires_at) < datetime('now', '-1 day')",
  ).run();
  await env.DB.prepare(
    "DELETE FROM actions WHERE datetime(requested_at) < datetime('now', '-90 days')",
  ).run();
  await env.DB.prepare(
    `UPDATE actions SET output = NULL
     WHERE action IN ('logs', 'read') AND output IS NOT NULL
       AND datetime(finished_at) < datetime('now', '-1 day')`,
  ).run();
  await env.DB.prepare(
    `DELETE FROM proposals
     WHERE status <> 'open' AND datetime(closed_at) < datetime('now', '-365 days')`,
  ).run();
  await env.DB.prepare(
    "DELETE FROM devices WHERE datetime(removed_at) < datetime('now', '-365 days')",
  ).run();
}

export default worker;
