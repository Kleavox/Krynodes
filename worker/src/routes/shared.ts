import type { Env, KrynodesContext } from "../env";

export const readJson = (context: KrynodesContext): Promise<unknown> =>
  context.req.json().catch(() => null);

export const invalidRequest = (context: KrynodesContext) =>
  context.json(
    { code: "INVALID_REQUEST", message: "Check the submitted fields." },
    400,
  );

export const agentOrigin = (env: Env): string =>
  env.AGENT_ORIGIN ?? env.PUBLIC_ORIGIN;

export const isUnique = (error: unknown): boolean =>
  String(error).includes("UNIQUE");
