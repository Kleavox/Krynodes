import { loadStatus, statusVersion } from "./data";
import { LOCAL_TIMES, personalize, REFRESH_ROUNDS, renderStatus } from "./page";

export interface StatsEnv {
  DB: D1Database;
  STATS_RATE_LIMIT: RateLimit;
}

const MAX_AGE = 600;
const FRESH_MS = 300_000;
const VERSION_MS = 30_000;

const versions = new WeakMap<D1Database, { at: number; value: string }>();

async function currentVersion(db: D1Database, now: number): Promise<string> {
  const known = versions.get(db);
  if (known && now - known.at >= 0 && now - known.at < VERSION_MS) {
    return known.value;
  }
  const value = await statusVersion(db);
  versions.set(db, { at: now, value });
  return value;
}

const CSP =
  "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

let scriptHash: Promise<string> | undefined;

const pageCsp = async () => {
  scriptHash ??= crypto.subtle
    .digest("SHA-256", new TextEncoder().encode(LOCAL_TIMES))
    .then((digest) => btoa(String.fromCharCode(...new Uint8Array(digest))));
  return `${CSP}; script-src 'sha256-${await scriptHash}'`;
};

const HEADERS = {
  "Content-Security-Policy": CSP,
  "Referrer-Policy": "no-referrer",
  "Strict-Transport-Security": "max-age=31536000",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "X-Robots-Tag": "noindex, nofollow",
};

function text(
  body: string,
  status: number,
  extra: Record<string, string> = {},
): Response {
  return new Response(body, {
    status,
    headers: {
      ...HEADERS,
      "Content-Type": "text/plain; charset=utf-8",
      ...extra,
    },
  });
}

export async function serveStats(
  request: Request,
  env: StatsEnv,
  options: {
    now?: number;
    cache?: Cache;
    defer?: (work: Promise<unknown>) => void;
  } = {},
): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname !== "/") return text("Not found.", 404);
  if (request.method !== "GET" && request.method !== "HEAD") {
    return text("Method not allowed.", 405, { Allow: "GET, HEAD" });
  }
  if (!env.STATS_RATE_LIMIT) {
    return text("The status page is not configured.", 503);
  }
  const { success } = await env.STATS_RATE_LIMIT.limit({
    key: request.headers.get("cf-connecting-ip") ?? "unknown",
  });
  if (!success) {
    return text("Too many requests. Try again in a minute.", 429, {
      "Retry-After": "60",
    });
  }

  const now = options.now ?? Date.now();
  const key = new Request(`${url.origin}/`);
  const round = refreshRound(url);
  const version = await currentVersion(env.DB, now);
  let response = await options.cache?.match(key);
  if (
    !response ||
    response.headers.get("X-Version") !== version ||
    now - Number(response.headers.get("X-Rendered-At")) >= FRESH_MS
  ) {
    response = new Response(renderStatus(await loadStatus(env.DB, now), now), {
      headers: {
        ...HEADERS,
        "Content-Security-Policy": await pageCsp(),
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": `public, max-age=${MAX_AGE}`,
        "X-Rendered-At": String(now),
        "X-Version": version,
      },
    });
    if (options.cache) {
      const stored = options.cache.put(key, response.clone());
      if (options.defer) options.defer(stored);
      else await stored;
    }
  }
  const renderedAt = Number(response.headers.get("X-Rendered-At") ?? now);
  const headers = new Headers(response.headers);
  headers.delete("Content-Length");
  headers.set("Cache-Control", "no-cache");
  const body =
    request.method === "HEAD"
      ? null
      : personalize(await response.text(), round, renderedAt);
  return new Response(body, { status: response.status, headers });
}

function refreshRound(url: URL): number {
  const value = Number(url.searchParams.get("r") ?? "0");
  return Number.isInteger(value) && value > 0
    ? Math.min(value, REFRESH_ROUNDS)
    : 0;
}

export default {
  fetch(request: Request, env: StatsEnv, context: ExecutionContext) {
    return serveStats(request, env, {
      cache: caches.default,
      defer: (work) => context.waitUntil(work),
    });
  },
};
