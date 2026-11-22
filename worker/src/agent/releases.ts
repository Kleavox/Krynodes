import type { Env } from "../env";
import { announce } from "../fleet/client";

const REPOSITORY = "Kleavox/Krynodes";
const LATEST = `https://github.com/${REPOSITORY}/releases/latest`;
const FEED = `https://github.com/${REPOSITORY}/releases.atom`;
const TAG = /^agent-v(\d+\.\d+\.\d+)$/u;
const ENTRY =
  /href="https:\/\/github\.com\/Kleavox\/Krynodes\/releases\/tag\/([^"]+)"/gu;
const HEADERS = { "user-agent": "kry-worker" };

export interface AgentRelease {
  version: string | null;
  checkedAt: string | null;
}

function missed(why: string): null {
  console.error("[kry release]", why);
  return null;
}

async function fetchNewest(any: boolean): Promise<string | null> {
  try {
    if (!any) {
      const response = await fetch(LATEST, {
        redirect: "manual",
        headers: HEADERS,
      });
      const version = TAG.exec(
        response.headers.get("location")?.split("/releases/tag/")[1] ?? "",
      )?.[1];
      return (
        version ??
        missed(`${LATEST} answered ${response.status}, no agent release`)
      );
    }
    const response = await fetch(FEED, { headers: HEADERS });
    if (!response.ok) return missed(`${FEED} answered ${response.status}`);
    for (const [, tag] of (await response.text()).matchAll(ENTRY)) {
      const version = TAG.exec(tag ?? "")?.[1];
      if (version) return version;
    }
    return missed(`${FEED} lists no agent release`);
  } catch (error) {
    return missed(error instanceof Error ? error.message : String(error));
  }
}

export async function readAgentRelease(db: D1Database): Promise<AgentRelease> {
  const row = await db
    .prepare("SELECT version, checked_at FROM agent_release WHERE id = 1")
    .first<{ version: string; checked_at: string }>();
  return { version: row?.version ?? null, checkedAt: row?.checked_at ?? null };
}

export async function checkAgentRelease(env: Env): Promise<AgentRelease> {
  const known = await readAgentRelease(env.DB);
  const version = await fetchNewest(env.RELEASES === "any");
  if (version === null) return known;
  const checkedAt = new Date().toISOString();
  await env.DB.prepare(
    "INSERT INTO agent_release (id, version, checked_at) VALUES (1, ?1, ?2) ON CONFLICT (id) DO UPDATE SET version = excluded.version, checked_at = excluded.checked_at",
  )
    .bind(version, checkedAt)
    .run();
  if (version !== known.version) await announce(env, ["fleet"]);
  return { version, checkedAt };
}
