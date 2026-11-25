import { Hono } from "hono";
import { describe, expect, it } from "vitest";

import { serveStats, type StatsEnv } from "../stats/index";
import { securityHeaders } from "./security-headers";

const HSTS = "max-age=31536000";

describe("HTTPS only", () => {
  it("tells browsers to use HTTPS for the dashboard and the status page", async () => {
    const app = new Hono();
    app.use("*", securityHeaders({ referrerPolicy: "same-origin" }));
    app.get("/", (context) => context.text("ok"));
    const dashboard = await app.request("https://kry.example.test/");
    expect(dashboard.headers.get("strict-transport-security")).toBe(HSTS);
    const stats = await serveStats(
      new Request("https://stats.example.test/missing"),
      {} as StatsEnv,
    );
    expect(stats.headers.get("strict-transport-security")).toBe(HSTS);
  });
});
