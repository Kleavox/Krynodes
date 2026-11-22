import { afterEach, describe, expect, it, vi } from "vitest";

import worker from "../index";
import { testEnv } from "../test/env";

const latest = (version: string) =>
  vi.stubGlobal(
    "fetch",
    async () =>
      new Response(null, {
        status: 302,
        headers: {
          location: `https://github.com/Kleavox/Krynodes/releases/tag/agent-v${version}`,
        },
      }),
  );

afterEach(() => vi.unstubAllGlobals());

describe("release routes", () => {
  it("GET answers what is known, null before a check", async () => {
    const { call } = testEnv();
    const response = await call("/api/release");
    expect(await response.json()).toEqual({ version: null, checkedAt: null });
  });

  it("POST check reads the newest release and stores it", async () => {
    const { send, call } = testEnv();
    latest("0.7.90");
    const checked = await send("POST", "/api/release/check");
    expect(checked.status).toBe(200);
    const body = (await checked.json()) as {
      version: string;
      checkedAt: string;
    };
    expect(body.version).toBe("0.7.90");
    expect(await (await call("/api/release")).json()).toEqual(body);
  });

  it("the daily cron runs the same check", async () => {
    const { env, db } = testEnv();
    latest("0.7.91");
    const pending: Promise<unknown>[] = [];
    await worker.scheduled(
      { cron: "17 3 * * *", scheduledTime: 0 } as ScheduledController,
      env,
      {
        waitUntil: (promise: Promise<unknown>) => pending.push(promise),
      } as unknown as ExecutionContext,
    );
    await Promise.all(pending);
    expect(
      await db.prepare("SELECT version FROM agent_release").first(),
    ).toEqual({ version: "0.7.91" });
  });
});
