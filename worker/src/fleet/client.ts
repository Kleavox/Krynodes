import type { HubMessage } from "@krynodes/protocol";

import type { Env } from "../env";

const hub = (env: Env) => env.FLEET.get(env.FLEET.idFromName("fleet"));

const PRIVATE = /^(authorization|cookie|cf-access.*|x-kry-.*)$/iu;

export function upgradeInto(
  env: Env,
  request: Request,
  path: "/connect" | "/watch",
  extra: Record<string, string> = {},
): Promise<Response> {
  const headers = new Headers();
  for (const [name, value] of request.headers) {
    if (!PRIVATE.test(name)) headers.set(name, value);
  }
  for (const [name, value] of Object.entries(extra)) headers.set(name, value);
  return hub(env).fetch(new Request(`https://fleet${path}`, { headers }));
}

export async function announce(env: Env, topics: string[]): Promise<void> {
  try {
    await hub(env).fetch("https://fleet/announce", {
      method: "POST",
      body: JSON.stringify({ topics }),
    });
  } catch (error) {
    console.error("[kry fleet]", error);
  }
}

async function post(env: Env, path: string, body: unknown): Promise<Response> {
  return hub(env).fetch(`https://fleet${path}`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function onlineNodes(env: Env): Promise<Set<string>> {
  const response = await hub(env).fetch("https://fleet/online");
  return new Set((await response.json()) as string[]);
}

export async function sendCommand(
  env: Env,
  nodeId: string,
  command: Extract<HubMessage, { type: "command" }>,
): Promise<boolean> {
  const response = await post(env, "/command", { nodeId, command });
  if (response.status === 409) return false;
  if (!response.ok)
    throw new Error(`the hub refused a command: ${response.status}`);
  return true;
}

export async function dropNode(env: Env, nodeId: string): Promise<void> {
  await post(env, "/drop", { nodeId });
}
