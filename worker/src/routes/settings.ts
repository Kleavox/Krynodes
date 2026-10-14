import type { MiddlewareHandler } from "hono";
import { z } from "zod";

import { parseRange } from "../lib/ranges";
import { invalidRequest, readJson } from "./shared";
import type { KrynodesApp, KrynodesEnv } from "./shared";

const KEY = "private_ranges";
const ENROLL_KEY = "enroll_defaults";

const enrollDefaultsSchema = z.object({
  recommended: z.boolean(),
  docker: z.boolean(),
  hour: z.number().int().min(0).max(23),
});

const ENROLL_DEFAULTS = { recommended: true, docker: true, hour: 3 };

const DISPLAY_KEY = "address_display";

const displaySchema = z.object({ display: z.enum(["hidden", "shown"]) });

const readSetting = async (db: D1Database, key: string) =>
  (
    await db
      .prepare("SELECT value FROM settings WHERE key = ?")
      .bind(key)
      .first<{ value: string }>()
  )?.value;

const writeSetting = (db: D1Database, key: string, value: unknown) =>
  db
    .prepare(
      `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
       ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
    )
    .bind(key, JSON.stringify(value), new Date().toISOString())
    .run();

export async function readPrivateRanges(db: D1Database): Promise<string[]> {
  const parsed = z
    .array(z.string())
    .safeParse(JSON.parse((await readSetting(db, KEY)) ?? "[]"));
  return parsed.success ? parsed.data : [];
}

export function registerSettingRoutes(
  app: KrynodesApp,
  requireOperator: MiddlewareHandler<KrynodesEnv>,
): void {
  app.get("/api/settings/address-display", requireOperator, async (context) => {
    const parsed = displaySchema.safeParse({
      display: JSON.parse(
        (await readSetting(context.env.DB, DISPLAY_KEY)) ?? '"hidden"',
      ),
    });
    return context.json(parsed.success ? parsed.data : { display: "hidden" });
  });

  app.put("/api/settings/address-display", requireOperator, async (context) => {
    const body = displaySchema.safeParse(await readJson(context));
    if (!body.success) return invalidRequest(context);
    await writeSetting(context.env.DB, DISPLAY_KEY, body.data.display);
    return context.json(body.data);
  });

  app.get("/api/settings/enroll-defaults", requireOperator, async (context) => {
    const parsed = enrollDefaultsSchema.safeParse(
      JSON.parse((await readSetting(context.env.DB, ENROLL_KEY)) ?? "null"),
    );
    return context.json(parsed.success ? parsed.data : ENROLL_DEFAULTS);
  });

  app.put("/api/settings/enroll-defaults", requireOperator, async (context) => {
    const body = enrollDefaultsSchema.safeParse(await readJson(context));
    if (!body.success) return invalidRequest(context);
    await writeSetting(context.env.DB, ENROLL_KEY, body.data);
    return context.json(body.data);
  });

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
    await writeSetting(context.env.DB, KEY, ranges);
    return context.json({ ranges });
  });
}
