import { describe, expect, it } from "vitest";

import { app } from "./app";
import type { Env } from "./env";
import { createTestDb } from "./test/sqlite-d1";

describe("Krynodes without Kleavox", () => {
  it.each([
    "/api/admin/link/admin/reports",
    "/api/admin/drop/admin/file-reports",
    "/api/projects",
    "/api/notes",
  ])("has no %s", async (path) => {
    const response = await app.request(`https://kry.example.test${path}`, {}, {
      ENVIRONMENT: "development",
    } as unknown as Env);
    expect(response.status).toBe(404);
  });
});

describe("changes from another site", () => {
  const ORIGIN = "https://kry.example.test";
  const env = () =>
    ({
      DB: createTestDb().db,
      PUBLIC_ORIGIN: ORIGIN,
      ENVIRONMENT: "development",
    }) as unknown as Env;

  it("are refused, while the dashboard and the agents still get through", async () => {
    const post = (headers: Record<string, string>, path = "/api/enrollments") =>
      app.request(
        `${ORIGIN}${path}`,
        { method: "POST", headers, body: "{}" },
        env(),
      );
    for (const headers of [
      { origin: "https://evil.example", "content-type": "text/plain" },
      { "sec-fetch-site": "cross-site" },
      { "sec-fetch-site": "same-site", origin: "https://stats.example.test" },
    ] as Record<string, string>[]) {
      const response = await post(headers);
      expect(response.status, JSON.stringify(headers)).toBe(403);
      expect(await response.json()).toMatchObject({ code: "CROSS_SITE" });
    }
    expect(
      (
        await post({
          origin: ORIGIN,
          "sec-fetch-site": "same-origin",
          "content-type": "application/json",
        })
      ).status,
    ).toBe(201);
    expect(
      (await post({ origin: "https://evil.example" }, "/api/agent/enroll"))
        .status,
    ).not.toBe(403);
  });

  it("keeps the live feed to the dashboard", async () => {
    const response = await app.request(
      `${ORIGIN}/api/live`,
      { headers: { upgrade: "websocket", origin: "https://evil.example" } },
      env(),
    );
    expect(response.status).toBe(403);
  });
});
