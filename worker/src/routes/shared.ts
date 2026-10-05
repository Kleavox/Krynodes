import type { Context, Hono } from "hono";

import type { Env } from "../env";
import type { Identity } from "../lib/session";
import type { CheckKind } from "../lib/checks";

export type KrynodesEnv = {
  Bindings: Env;
  Variables: { identity: Identity };
};

export type KrynodesApp = Hono<KrynodesEnv>;
export type KrynodesContext = Context<KrynodesEnv>;

export interface CheckRow {
  id: string;
  node_id: string | null;
  name: string;
  kind: CheckKind;
  target: string;
  enabled: number;
  status: string;
  timeout_seconds: number;
  latency_ms: number | null;
  last_checked_at: string | null;
  consecutive_failures: number;
  last_message: string | null;
  auto_restart?: number;
}

export async function readJson(context: KrynodesContext): Promise<unknown> {
  return context.req.json().catch(() => null);
}

export function findOwnedNode(db: D1Database, id: string, ownerId: string) {
  return db
    .prepare("SELECT id FROM nodes WHERE id = ? AND owner_user_id = ? LIMIT 1")
    .bind(id, ownerId)
    .first<{ id: string }>();
}

export function invalidRequest(context: KrynodesContext) {
  return context.json(
    { code: "INVALID_REQUEST", message: "Check the submitted fields." },
    400,
  );
}

export function agentOrigin(env: Env): string {
  return env.AGENT_ORIGIN ?? env.PUBLIC_ORIGIN;
}
