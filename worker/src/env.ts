import type { Context, Hono } from "hono";

import type { Identity } from "./lib/session";

export interface Env {
  ASSETS: Fetcher;
  DB: D1Database;
  FLEET: DurableObjectNamespace;
  ENVIRONMENT: "development" | "production";
  PUBLIC_ORIGIN: string;
  AGENT_ORIGIN?: string;
  AGENT_RATE_LIMIT?: RateLimit;
  RELEASES?: string;
  ACCESS_TEAM_DOMAIN?: string;
  ACCESS_AUD?: string;
  EMAIL?: SendEmail;
  ALERT_EMAIL?: string;
  FROM_EMAIL?: string;
  STATUS_PAGE_URL?: string;
}

export type KrynodesEnv = {
  Bindings: Env;
  Variables: { identity: Identity };
};

export type KrynodesApp = Hono<KrynodesEnv>;
export type KrynodesContext = Context<KrynodesEnv>;
