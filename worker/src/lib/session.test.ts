import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { app } from "../app";
import type { Env } from "../env";
import {
  ACCESS_AUD,
  ACCESS_TEAM,
  accessClaims,
  accessKeys,
  serveAccessCerts,
  signAccessToken,
} from "../test/access-token";

let keys: Awaited<ReturnType<typeof accessKeys>>;

beforeAll(async () => {
  keys = await accessKeys();
});

afterEach(() => vi.unstubAllGlobals());

const assets = {
  fetch: async () => new Response("from assets"),
};

function production(extra: Partial<Env> = {}) {
  const env = {
    ASSETS: assets,
    ENVIRONMENT: "production",
    ACCESS_TEAM_DOMAIN: ACCESS_TEAM,
    ACCESS_AUD,
    ...extra,
  } as unknown as Env;
  return (path: string, token?: string) =>
    app.request(
      `https://kry.example.test${path}`,
      { headers: token ? { "cf-access-jwt-assertion": token } : {} },
      env,
    );
}

describe("production", () => {
  it("refuses to serve at all when Access does not guard it", async () => {
    const call = production({
      ACCESS_TEAM_DOMAIN: undefined,
      ACCESS_AUD: undefined,
    });
    expect((await call("/health")).status).toBe(500);
    expect((await call("/api/nodes")).status).toBe(500);
  });

  it("lets the operator in through Cloudflare Access as the standalone owner", async () => {
    serveAccessCerts(keys.jwk);
    const call = production();
    const token = await signAccessToken(
      keys.privateKey,
      accessClaims(Date.now()),
    );

    const session = await call("/api/session", token);
    expect(await session.json()).toEqual({
      authenticated: true,
      via: "access",
      identity: {
        id: "standalone",
        email: "operator@example.test",
        username: null,
      },
    });
    expect((await call("/api/unknown", token)).status).toBe(404);
  });

  it("answers 401 to a request that skipped Access", async () => {
    serveAccessCerts(keys.jwk);
    const call = production();
    const response = await call("/api/nodes");
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ code: "UNAUTHORIZED" });
    expect(await (await call("/api/session")).json()).toEqual({
      authenticated: false,
      via: "access",
    });
  });

  it("answers the health check and serves the app without a token", async () => {
    serveAccessCerts(keys.jwk);
    const call = production();
    expect(await (await call("/health")).json()).toEqual({
      service: "kry",
      status: "ok",
    });
    expect(await (await call("/")).text()).toBe("from assets");
  });
});

describe("development", () => {
  it("still opens as the standalone operator", async () => {
    const response = await app.request(
      "https://kry.example.test/api/session",
      {},
      { ENVIRONMENT: "development" } as unknown as Env,
    );
    expect(await response.json()).toMatchObject({
      authenticated: true,
      via: "standalone",
      identity: { id: "standalone" },
    });
  });
});
