import type { MiddlewareHandler } from "hono";
import { z } from "zod";

import { parseRange } from "../lib/ranges";
import { invalidRequest, readJson } from "./shared";
import type { KrynodesApp, KrynodesEnv } from "./shared";

const KEY = "private_ranges";

export async function readPrivateRanges(db: D1Database): Promise<string[]> {
  const row = await db
    .prepare("SELECT value FROM settings WHERE key = ?")
    .bind(KEY)
    .first<{ value: string }>();
  const parsed = z.array(z.string()).safeParse(JSON.parse(row?.value ?? "[]"));
  return parsed.success ? parsed.data : [];
}

export function registerSettingRoutes(
  app: KrynodesApp,
  requireOperator: MiddlewareHandler<KrynodesEnv>,
): void {
  app.get("/api/settings/private-ranges", requireOperator, async (context) =>
    context.json({ ranges: await readPrivateRanges(context.env.DB) }),
  );

  app.put("/api/settings/private-ranges", requireOperator, async (context) => {
    const body = z
      .object({ ranges: z.array(z.string().max(64)).max(32) })
      .safeParse(await readJson(context));
    if (!body.success) return invalidRequest(context);
    const ranges: string[] = [];
    for (const entry of body.data.ranges) {
      const range = parseRange(entry);
      if (!range) {
        return context.json(
          {
            code: "INVALID_RANGE",
            message: `${entry.trim()} is not an address range, such as 10.8.0.0/24.`,
          },
          400,
        );
      }
      if (!ranges.includes(range)) ranges.push(range);
    }
    await context.env.DB.prepare(
      `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
       ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
    )
      .bind(KEY, JSON.stringify(ranges), new Date().toISOString())
      .run();
    return context.json({ ranges });
  });
}
