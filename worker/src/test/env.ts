import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { app } from "../app";
import type { Env } from "../env";
import { sha256 } from "../lib/crypto";
import { freshDb } from "./db";

const INSTALLER = readFileSync(
  fileURLToPath(new URL("../../../app/public/install.sh", import.meta.url)),
  "utf8",
);

export const ORIGIN = "https://kry.example.test";
export const AGENT = "https://agent.example.test";

interface HubCall {
  path: string;
  body: Record<string, unknown> | null;
}

export function testEnv(overrides: Partial<Env> = {}) {
  const db = freshDb();
  const hub = {
    online: [] as string[],
    via: {} as Record<string, string> | null,
    calls: [] as HubCall[],
  };
  const env = {
    DB: db,
    ENVIRONMENT: "development",
    PUBLIC_ORIGIN: ORIGIN,
    AGENT_ORIGIN: AGENT,
    ASSETS: {
      fetch: async (request: Request) =>
        new URL(request.url).pathname === "/install.sh"
          ? new Response(INSTALLER)
          : new Response("from assets"),
    },
    FLEET: {
      idFromName: (name: string) => name,
      get: () => ({
        fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
          const request = new Request(input, init);
          const path = new URL(request.url).pathname;
          const text = request.method === "POST" ? await request.text() : "";
          const body = text
            ? (JSON.parse(text) as Record<string, unknown>)
            : null;
          hub.calls.push({ path, body });
          if (path === "/online") return Response.json(hub.online);
          if (path === "/via") {
            return hub.via
              ? Response.json(hub.via)
              : new Response(null, { status: 500 });
          }
          if (path === "/command") {
            return hub.online.includes(String(body?.nodeId))
              ? Response.json({ sent: true })
              : Response.json({ code: "OFFLINE" }, { status: 409 });
          }
          return new Response(null, { status: 204 });
        },
      }),
    },
    ...overrides,
  } as unknown as Env;
  const call = (path: string, init: RequestInit = {}) =>
    app.request(`${ORIGIN}${path}`, init, env);
  const send = (method: string, path: string, body?: unknown) =>
    call(path, {
      method,
      headers: { origin: ORIGIN, "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  return { db, env, hub, call, send };
}

export async function addNode(
  db: D1Database,
  id: string,
  name = "server-1",
  version: string | null = "0.7.90",
) {
  await db
    .prepare(
      "INSERT INTO nodes (id, name, agent_token_hash, enrolled_at, version) VALUES (?1, ?2, ?3, '2026-11-22T00:00:00.000Z', ?4)",
    )
    .bind(id, name, `hash-${id}`, version)
    .run();
}

export async function addDevice(
  db: D1Database,
  id: string,
  publicKey = `key-${id}`,
  name = id,
) {
  await db
    .prepare(
      "INSERT INTO devices (id, name, alg, public_key, synced, created_at) VALUES (?1, ?2, '-7', ?3, 0, '2026-11-22T00:00:00.000Z')",
    )
    .bind(id, name, publicKey)
    .run();
}

export async function addEnrollment(
  db: D1Database,
  token: string,
  options: {
    id?: string;
    name?: string;
    trust?: string[];
    expiresAt?: string;
    usedAt?: string | null;
  } = {},
) {
  await db
    .prepare(
      "INSERT INTO enrollments (id, token_hash, name, trust, created_at, expires_at, used_at) VALUES (?1, ?2, ?3, ?4, '2026-11-22T00:00:00.000Z', ?5, ?6)",
    )
    .bind(
      options.id ?? "e1",
      await sha256(token),
      options.name ?? "server-1",
      JSON.stringify(options.trust ?? ["d1"]),
      options.expiresAt ?? new Date(Date.now() + 3_600_000).toISOString(),
      options.usedAt ?? null,
    )
    .run();
}
