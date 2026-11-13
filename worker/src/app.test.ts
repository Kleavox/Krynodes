import { describe, expect, it } from "vitest";

import { app } from "./app";
import type { Env } from "./env";
import { LAPTOP } from "./test/keys";
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
  const env = () => {
    const { db, sqlite } = createTestDb();
    sqlite
      .prepare(
        "INSERT INTO settings (key, value, updated_at) VALUES ('enroll_defaults', ?, 'now')",
      )
      .run(JSON.stringify({ docker: false, hour: 3, keys: [LAPTOP] }));
    return {
      DB: db,
      PUBLIC_ORIGIN: ORIGIN,
      ENVIRONMENT: "development",
    } as unknown as Env;
  };

  it("are refused, while the dashboard and the agents still get through", async () => {
    const post = (headers: Record<string, string>, path = "/api/enrollments") =>
      app.request(
        `${ORIGIN}${path}`,
        {
          method: "POST",
          headers,
          body: JSON.stringify({ rebootHour: 3, adminName: "user1" }),
        },
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

  it("refuses a body over two megabytes before reading it", async () => {
    const send = (size: number) =>
      app.request(
        `${ORIGIN}/api/agent/enroll`,
        { method: "POST", body: "x".repeat(size) },
        env(),
      );
    const response = await send(2 * 1024 * 1024 + 1);
    expect(response.status).toBe(413);
    expect(await response.json()).toMatchObject({ code: "TOO_LARGE" });
    expect((await send(2 * 1024 * 1024)).status).toBe(400);
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
