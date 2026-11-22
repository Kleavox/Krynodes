import type { MiddlewareHandler } from "hono";

import type { Env, KrynodesEnv } from "../env";
import { verifyAccessToken } from "./access";

export interface Identity {
  id: string;
  email: string;
  username: string | null;
}

type SessionVia = "access" | "standalone";

const STANDALONE: Identity = {
  id: "standalone",
  email: "standalone@localhost",
  username: "standalone",
};

function accessConfig(env: Env) {
  return env.ACCESS_TEAM_DOMAIN && env.ACCESS_AUD
    ? { teamDomain: env.ACCESS_TEAM_DOMAIN, audience: env.ACCESS_AUD }
    : null;
}

export function requireGuardInProduction(env: Env): void {
  if (env.ENVIRONMENT === "production" && !accessConfig(env)) {
    throw new Error(
      "Cloudflare Access is not configured in production, so every session check would fall open",
    );
  }
}

export async function resolveSession(
  request: Request,
  env: Env,
): Promise<{ via: SessionVia; identity: Identity | null }> {
  const access = accessConfig(env);
  if (!access) return { via: "standalone", identity: STANDALONE };

  const verified = await verifyAccessToken(request, access);
  return {
    via: "access",
    identity: verified
      ? {
          id: STANDALONE.id,
          email: verified.email,
          username: null,
        }
      : null,
  };
}

export const requireOperator: MiddlewareHandler<KrynodesEnv> = async (
  context,
  next,
) => {
  const { identity } = await resolveSession(context.req.raw, context.env);
  if (!identity) {
    return context.json(
      { code: "UNAUTHORIZED", message: "Sign in through Cloudflare Access." },
      401,
    );
  }
  context.set("identity", identity);
  await next();
};
