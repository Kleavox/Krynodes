import { Hono } from "hono";
import { describe, expect, it } from "vitest";

import { securityHeaders } from "./security-headers";

describe("HTTPS only", () => {
  it("tells browsers to use HTTPS for the dashboard", async () => {
    const app = new Hono();
    app.use("*", securityHeaders({ referrerPolicy: "same-origin" }));
    app.get("/", (context) => context.text("ok"));
    const dashboard = await app.request("https://kry.example.test/");
    expect(dashboard.headers.get("strict-transport-security")).toBe(
      "max-age=31536000",
    );
  });
});
