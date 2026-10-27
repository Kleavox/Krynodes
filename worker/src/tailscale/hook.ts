import {
  TAILSCALE,
  webhookBodySchema,
  type WebhookEvent,
} from "@krynodes/protocol";

import { hubFor, streamsOn } from "../fleet/client";
import type { Env } from "../env";
import type { TailnetMail } from "../lib/mail";
import type { KrynodesApp } from "../routes/shared";

const MAX_BODY = 256 * 1024;
const MINUTE = 60_000;
const BEGIN = "// krynodes: begin";
const END = "// krynodes: end";

const iso = (ms: number) => new Date(ms).toISOString();

interface Owner {
  owner_user_id: string;
  client_id: string;
  webhook_secret: string;
}

function signature(header: string | undefined) {
  let t: number | null = null;
  const v1: Uint8Array[] = [];
  for (const part of (header ?? "").split(",")) {
    const [key, value = ""] = part.trim().split("=");
    if (key === "t" && /^\d{1,12}$/u.test(value)) t = Number(value);
    if (key === "v1" && /^[0-9a-f]{64}$/iu.test(value)) {
      v1.push(
        Uint8Array.from(value.match(/../gu)!, (pair) => parseInt(pair, 16)),
      );
    }
  }
  return { t, v1 };
}

async function signedWith(
  secret: string,
  t: number,
  body: Uint8Array,
  v1: Uint8Array[],
): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const prefix = new TextEncoder().encode(`${t}.`);
  const signed = new Uint8Array(prefix.byteLength + body.byteLength);
  signed.set(prefix);
  signed.set(body, prefix.byteLength);
  for (const mac of v1) {
    if (await crypto.subtle.verify("HMAC", key, mac, signed)) return true;
  }
  return false;
}

const tagged = (value: unknown) =>
  (Array.isArray(value)
    ? value
    : typeof value === "string"
      ? value.split(/[\s,]+/u)
      : []
  ).includes(TAILSCALE.tag);

const stableId = (id: string) =>
  /^n[0-9A-Za-z]+$/u.test(id) && !id.endsWith("CNTRL") ? `${id}CNTRL` : id;

function blockOf(text: string): string[] | null {
  const lines = text.split(/\r?\n/u).map((line) => line.trim());
  const begin = lines.findIndex((line) => line.startsWith(BEGIN));
  const end = lines.findIndex(
    (line, index) => index > begin && line.startsWith(END),
  );
  return begin < 0 || end < 0 ? null : lines.slice(begin + 1, end);
}

const normal = (lines: string[]) =>
  lines.map((line) => line.trim().replace(/,$/u, "")).filter(Boolean);

function minus(from: string[], take: string[]): string[] {
  const left = new Map<string, number>();
  for (const line of take) left.set(line, (left.get(line) ?? 0) + 1);
  return from.filter((line) => {
    const count = left.get(line) ?? 0;
    if (count === 0) return true;
    left.set(line, count - 1);
    return false;
  });
}

function compared(before: string[], after: string[]) {
  const removed = minus(before, after);
  const added = minus(after, before);
  return {
    added: added.length,
    removed: removed.length,
    lines: [
      ...removed.map((line) => `- ${line}`),
      ...added.map((line) => `+ ${line}`),
    ]
      .slice(0, 20)
      .map((line) => line.slice(0, 200)),
  };
}

export function policyChange(before: string, after: string) {
  const old = blockOf(before);
  const next = blockOf(after);
  if (old !== null && next !== null) {
    const block = compared(normal(old), normal(next));
    if (block.added + block.removed > 0) return { block: true, ...block };
  }
  return {
    block: false,
    ...compared(normal(before.split(/\r?\n/u)), normal(after.split(/\r?\n/u))),
  };
}

const text = (value: unknown) => (typeof value === "string" ? value : "");

function alarmsOf(
  db: D1Database,
  owner: Owner,
  events: WebhookEvent[],
  now: number,
) {
  return events.flatMap((event) => {
    const data = event.data ?? {};
    const parsed = Date.parse(event.timestamp);
    const at = Number.isFinite(parsed) ? Math.min(parsed, now) : now;
    const id = owner.owner_user_id;
    if (
      event.type === "nodeCreated" &&
      tagged(data.managedBy) &&
      /^[\w-]{1,64}$/u.test(text(data.nodeID))
    ) {
      const device = stableId(text(data.nodeID));
      const due = at + TAILSCALE.judgeMinutes * MINUTE;
      return [
        {
          due,
          statement: db
            .prepare(
              `INSERT OR IGNORE INTO tailscale_alarms (id, owner_user_id, kind, device, detail, at, due_at)
               SELECT ?1, ?2, 'device', ?3, ?4, ?5, ?6
               WHERE NOT EXISTS (
                 SELECT 1 FROM tailscale_nodes t JOIN nodes n ON n.id = t.node_id
                 WHERE n.owner_user_id = ?2 AND t.device = ?3)`,
            )
            .bind(
              `${id}:device:${device}`,
              id,
              device,
              JSON.stringify({
                name: text(data.deviceName).slice(0, 253) || device,
                tag: TAILSCALE.tag,
              }),
              iso(at),
              iso(due),
            ),
        },
      ];
    }
    if (event.type === "policyUpdate" && data.actor === owner.client_id) {
      return [
        {
          due: now,
          statement: db
            .prepare(
              `INSERT OR IGNORE INTO tailscale_alarms (id, owner_user_id, kind, detail, at, due_at)
               SELECT ?1, ?2, 'policy', ?3, ?4, ?5
               WHERE NOT EXISTS (
                 SELECT 1 FROM actions a JOIN nodes n ON n.id = a.node_id
                 WHERE n.owner_user_id = ?2 AND a.kind = 'vault' AND a.name = 'tailscale'
                   AND a.action = 'save'
                   AND (a.status IN ('queued', 'sent') OR a.finished_at >= ?6))`,
            )
            .bind(
              `${id}:policy:${iso(at)}`,
              id,
              JSON.stringify(
                policyChange(text(data.oldPolicy), text(data.newPolicy)),
              ),
              iso(at),
              iso(now),
              iso(at - TAILSCALE.saveQuietMinutes * MINUTE),
            ),
        },
      ];
    }
    return [];
  });
}

async function wake(env: Env, owner: string, due: number) {
  if (!streamsOn(env)) return;
  try {
    await hubFor(env, owner).fetch("https://fleet/tailnet", {
      method: "POST",
      body: JSON.stringify({ owner, due }),
    });
  } catch (error) {
    console.error("[kry fleet]", error);
  }
}

export function registerTailscaleHook(app: KrynodesApp): void {
  app.post(TAILSCALE.hook, async (context) => {
    const refused = () =>
      context.json(
        {
          code: "UNSIGNED",
          message: "This call is not signed by your tailnet.",
        },
        401,
      );
    if (Number(context.req.header("content-length") ?? 0) > MAX_BODY) {
      return refused();
    }
    const body = new Uint8Array(await context.req.arrayBuffer());
    const { t, v1 } = signature(
      context.req.header("tailscale-webhook-signature"),
    );
    const now = Date.now();
    if (
      body.byteLength > MAX_BODY ||
      t === null ||
      v1.length === 0 ||
      Math.abs(now / 1000 - t) > TAILSCALE.tolerance
    ) {
      return refused();
    }
    let events: WebhookEvent[];
    try {
      events = webhookBodySchema.parse(
        JSON.parse(new TextDecoder().decode(body)),
      );
    } catch {
      return refused();
    }
    const tailnets = [...new Set(events.map((event) => event.tailnet))];
    if (tailnets.length !== 1) return refused();
    const db = context.env.DB;
    const rows = await db
      .prepare(
        "SELECT owner_user_id, client_id, webhook_secret FROM tailscale WHERE tailnet = ?",
      )
      .bind(tailnets[0])
      .all<Owner>();
    let owner: Owner | undefined;
    for (const row of rows.results) {
      if (await signedWith(row.webhook_secret, t, body, v1)) {
        owner = row;
        break;
      }
    }
    if (!owner) return refused();
    const alarms = alarmsOf(db, owner, events, now);
    if (alarms.length > 0) {
      const written = await db.batch(alarms.map((alarm) => alarm.statement));
      const due = alarms
        .filter((_, index) => (written[index]?.meta.changes ?? 0) > 0)
        .map((alarm) => alarm.due);
      if (due.length > 0) {
        await wake(context.env, owner.owner_user_id, Math.min(...due));
      }
    }
    return context.json({});
  });
}

interface DueRow {
  id: string;
  kind: "device" | "policy";
  detail: string;
  at: string;
  known: number;
}

function detailOf(text: string): Record<string, unknown> {
  try {
    const value = JSON.parse(text) as unknown;
    return value && typeof value === "object"
      ? (value as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}

export async function judgeTailnet(
  db: D1Database,
  owner: string,
  now: number,
): Promise<{ mails: TailnetMail[]; due: number | null }> {
  const [due, joining] = await Promise.all([
    db
      .prepare(
        `SELECT a.id, a.kind, a.detail, a.at,
                EXISTS (SELECT 1 FROM tailscale_nodes t JOIN nodes n ON n.id = t.node_id
                        WHERE n.owner_user_id = ?1 AND t.device = a.device) AS known
         FROM tailscale_alarms a
         WHERE a.owner_user_id = ?1 AND a.raised_at IS NULL AND a.cleared_at IS NULL
           AND a.due_at <= ?2`,
      )
      .bind(owner, iso(now))
      .all<DueRow>(),
    db
      .prepare(
        `SELECT 1 FROM actions a JOIN nodes n ON n.id = a.node_id
         WHERE n.owner_user_id = ? AND a.kind = 'host' AND a.name = 'tailscale'
           AND a.action = 'join' AND a.status IN ('queued', 'sent')
         LIMIT 1`,
      )
      .bind(owner)
      .first(),
  ]);
  const raise = db.prepare(
    "UPDATE tailscale_alarms SET raised_at = ?1, due_at = NULL WHERE id = ?2 AND raised_at IS NULL",
  );
  const judged = due.results.map((row) => {
    const limit = Date.parse(row.at) + TAILSCALE.judgeLimitMinutes * MINUTE;
    if (row.kind === "device" && row.known === 1) {
      return {
        row,
        statement: db
          .prepare("DELETE FROM tailscale_alarms WHERE id = ?")
          .bind(row.id),
        raised: false,
      };
    }
    if (row.kind === "device" && joining !== null && now < limit) {
      return {
        row,
        statement: db
          .prepare("UPDATE tailscale_alarms SET due_at = ? WHERE id = ?")
          .bind(
            iso(Math.min(now + TAILSCALE.judgeMinutes * MINUTE, limit)),
            row.id,
          ),
        raised: false,
      };
    }
    return { row, statement: raise.bind(iso(now), row.id), raised: true };
  });
  const written =
    judged.length === 0
      ? []
      : await db.batch(judged.map((item) => item.statement));
  const mails = judged.flatMap(({ row, raised }, index): TailnetMail[] => {
    if (!raised || (written[index]?.meta.changes ?? 0) === 0) return [];
    const detail = detailOf(row.detail);
    return row.kind === "device"
      ? [
          {
            kind: "device",
            name: text(detail.name) || "--",
            tag: text(detail.tag) || TAILSCALE.tag,
            at: row.at,
          },
        ]
      : [
          {
            kind: "policy",
            at: row.at,
            block: detail.block === true,
            added: Number(detail.added) || 0,
            removed: Number(detail.removed) || 0,
          },
        ];
  });
  const next = await db
    .prepare(
      `SELECT MIN(due_at) AS due FROM tailscale_alarms
       WHERE owner_user_id = ? AND raised_at IS NULL AND cleared_at IS NULL`,
    )
    .bind(owner)
    .first<{ due: string | null }>();
  return { mails, due: next?.due ? Date.parse(next.due) : null };
}
