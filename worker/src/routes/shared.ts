import { z } from "zod";

import type { Env, KrynodesContext } from "../env";

export const machineName = z
  .string()
  .trim()
  .min(1)
  .max(64)
  .refine((name) => !/\p{Cc}/u.test(name));

export const isMember = async (db: D1Database, nodeId: string) =>
  (await db
    .prepare("SELECT 1 FROM network_members WHERE node_id = ? AND state = 'in'")
    .bind(nodeId)
    .first()) !== null;

export const networkMember = (context: KrynodesContext, name: string) =>
  context.json(
    {
      code: "NETWORK_MEMBER",
      message: `Remove ${name} from the private network first.`,
    },
    409,
  );

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

export function dnsName(name: string): string {
  let label = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, "-")
    .replace(/^-+|-+$/gu, "");
  if (label.length > 63) label = label.slice(0, 63).replace(/-+$/u, "");
  return label === "" ? "server" : label;
}

export async function dnsClash(
  db: D1Database,
  name: string,
  then: string,
  except?: string,
): Promise<string | null> {
  const label = dnsName(name);
  const { results } = await db
    .prepare("SELECT id, name FROM nodes")
    .all<{ id: string; name: string }>();
  const other = results.find(
    (one) =>
      one.id !== except && one.name !== name && dnsName(one.name) === label,
  );
  return other
    ? `${name} would have the same network name as ${other.name} (${label}.kry). ${then}`
    : null;
}
