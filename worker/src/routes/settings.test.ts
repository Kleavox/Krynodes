import { describe, expect, it } from "vitest";

import { app } from "../app";
import type { Env } from "../env";
import { seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";

const NODE = "11111111-1111-4111-8111-111111111111";

function setup() {
  const { db, sqlite } = createTestDb();
  seedNode(sqlite, { id: NODE });
  const env = { DB: db } as unknown as Env;
  const call = (method: string, path: string, body?: unknown) =>
    app.request(
      `https://kry.example.test${path}`,
      {
        method,
        headers: { "content-type": "application/json" },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      },
      env,
    );
  return { call, sqlite };
}

const security = {
  checkedAt: "2026-10-10T09:00:00.000Z",
  findings: [
    {
      id: "public-ports",
      severity: "warning",
      detail:
        "Listening on public addresses outside Krynodes: 57969/tcp (tailscaled), 41641/udp (tailscaled)",
    },
  ],
  recipes: [],
  lockdown: false,
  rebootHour: null,
  listeners: [
    {
      address: "100.79.66.29",
      port: 57969,
      protocol: "tcp",
      process: "tailscaled",
    },
    { address: "0.0.0.0", port: 41641, protocol: "udp", process: "tailscaled" },
  ],
};

describe("addresses that are not public", () => {
  it("starts empty and stores normalized ranges once each", async () => {
    const { call } = setup();
    expect(
      await (await call("GET", "/api/settings/private-ranges")).json(),
    ).toEqual({ ranges: [] });
    const saved = await call("PUT", "/api/settings/private-ranges", {
      ranges: ["100.64.0.0/10", " fd7a:115c:a1e0::/48 ", "100.64.0.1/10"],
    });
    expect(saved.status).toBe(200);
    expect(await saved.json()).toEqual({
      ranges: ["100.64.0.0/10", "fd7a:115c:a1e0::/48"],
    });
    expect(
      await (await call("GET", "/api/settings/private-ranges")).json(),
    ).toEqual({ ranges: ["100.64.0.0/10", "fd7a:115c:a1e0::/48"] });
  });

  it("names the entry it cannot read", async () => {
    const { call } = setup();
    const response = await call("PUT", "/api/settings/private-ranges", {
      ranges: ["10.0.0.0/8", "10.0.0/8"],
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      code: "INVALID_RANGE",
      message: "10.0.0/8 is not an address range, such as 10.8.0.0/24.",
    });
    expect(
      (
        await call("PUT", "/api/settings/private-ranges", {
          ranges: Array.from(
            { length: 33 },
            (_, index) => `10.${index}.0.0/16`,
          ),
        })
      ).status,
    ).toBe(400);
  });

  it("applies the ranges to every server's security report", async () => {
    const { call, sqlite } = setup();
    sqlite
      .prepare("UPDATE nodes SET security = ? WHERE id = ?")
      .run(JSON.stringify(security), NODE);
    const detail = async () =>
      (
        (await (await call("GET", "/api/services")).json()) as {
          nodes: { security: { findings: { detail: string }[] } }[];
        }
      ).nodes[0]!.security.findings[0]?.detail;
    expect(await detail()).toContain("57969/tcp");
    await call("PUT", "/api/settings/private-ranges", {
      ranges: ["100.64.0.0/10"],
    });
    expect(await detail()).toBe(
      "Listening on public addresses outside Krynodes: 41641/udp (tailscaled)",
    );
  });
});
