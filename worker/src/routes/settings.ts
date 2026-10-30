import type { MiddlewareHandler } from "hono";
import { z } from "zod";

import { sha256 } from "../lib/crypto";
import { parseRange } from "../lib/ranges";
import { fingerprint, parseKeyLine } from "../lib/ssh";
import { confirmed } from "../trust/intent";
import { liveRange, readNetwork } from "../network/document";
import { invalidRequest, readJson } from "./shared";
import type { KrynodesApp, KrynodesEnv } from "./shared";

const KEY = "private_ranges";
const ENROLL_KEY = "enroll_defaults";

const keysSchema = z
  .array(
    z
      .string()
      .max(16384)
      .refine((line) => parseKeyLine(line) !== null),
  )
  .max(4);

const enrollDefaultsSchema = z.preprocess(
  (value) =>
    value !== null &&
    typeof value === "object" &&
    !("keys" in value) &&
    "admin" in value
      ? {
          ...value,
          keys:
            (value as { admin: { keys?: unknown } | null }).admin?.keys ?? [],
        }
      : value,
  z.object({
    recommended: z.boolean(),
    docker: z.boolean(),
    hour: z.number().int().min(0).max(23),
    network: z.boolean().default(false),
    confine: z.boolean().default(false),
    keys: keysSchema.default([]),
  }),
);

type EnrollDefaults = z.infer<typeof enrollDefaultsSchema>;

const ENROLL_DEFAULTS: EnrollDefaults = {
  recommended: true,
  docker: true,
  hour: 3,
  network: false,
  confine: false,
  keys: [],
};

export async function readEnrollDefaults(
  db: D1Database,
): Promise<EnrollDefaults> {
  try {
    const parsed = enrollDefaultsSchema.safeParse(
      JSON.parse((await readSetting(db, ENROLL_KEY)) ?? "null"),
    );
    return parsed.success ? parsed.data : ENROLL_DEFAULTS;
  } catch {
    return ENROLL_DEFAULTS;
  }
}

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

async function readTypedRanges(db: D1Database): Promise<string[]> {
  const parsed = z
    .array(z.string())
    .safeParse(JSON.parse((await readSetting(db, KEY)) ?? "[]"));
  return parsed.success ? parsed.data : [];
}

export async function readPrivateRanges(
  db: D1Database,
  owner: string,
): Promise<string[]> {
  const [typed, network] = await Promise.all([
    readTypedRanges(db),
    readNetwork(db, owner),
  ]);
  const range = liveRange(network);
  return range && !typed.includes(range) ? [...typed, range] : typed;
}

export function registerSettingRoutes(
  app: KrynodesApp,
  requireOperator: MiddlewareHandler<KrynodesEnv>,
): void {
  const shown = async (defaults: EnrollDefaults) => ({
    ...defaults,
    keys: await Promise.all(
      defaults.keys.map(async (line, index) => {
        const key = parseKeyLine(line, index)!;
        return {
          line,
          type: key.type,
          fingerprint: await fingerprint(key.blob),
          label: key.label,
        };
      }),
    ),
  });

  app.get("/api/settings/enroll-defaults", requireOperator, async (context) =>
    context.json(await shown(await readEnrollDefaults(context.env.DB))),
  );

  app.put("/api/settings/enroll-defaults", requireOperator, async (context) => {
    const body = enrollDefaultsSchema.safeParse(await readJson(context));
    if (!body.success) return invalidRequest(context);
    const db = context.env.DB;
    const wanted = body.data.keys.join("\n");
    if (wanted !== (await readEnrollDefaults(db)).keys.join("\n")) {
      const refused = await confirmed(
        context,
        "enroll.admin",
        await sha256(wanted),
      );
      if (refused) return refused;
    }
    await writeSetting(db, ENROLL_KEY, body.data);
    return context.json(await shown(body.data));
  });

  app.get("/api/settings/private-ranges", requireOperator, async (context) => {
    const [ranges, network] = await Promise.all([
      readTypedRanges(context.env.DB),
      readNetwork(context.env.DB, context.get("identity").id),
    ]);
    return context.json({ ranges, network: liveRange(network) });
  });

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
            message: `${entry.trim()} is not an address range written as address/bits.`,
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
