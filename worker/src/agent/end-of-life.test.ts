import { afterEach, describe, expect, it, vi } from "vitest";

import type { Env } from "../env";
import worker from "../index";
import { createTestDb } from "../test/sqlite-d1";
import {
  endOfLifeDate,
  eolFinding,
  readEndOfLife,
  runEndOfLifeCheck,
} from "./end-of-life";

afterEach(() => vi.unstubAllGlobals());

const DEBIAN = [
  { name: "13", eolFrom: "2030-06-30" },
  { name: "12", eolFrom: "2028-06-30" },
  { name: "x", eolFrom: "soon" },
  { name: "sid", eolFrom: null },
];

function answer(products: Record<string, unknown>) {
  const fetch = vi.fn(async (url: string) => {
    const product = url.split("/").at(-1)!;
    const releases = products[product];
    if (releases === undefined) return new Response("down", { status: 500 });
    return Response.json({ result: { releases } });
  });
  vi.stubGlobal("fetch", fetch);
  return fetch;
}

describe("end of life from endoflife.date", () => {
  it("stores each release's end of life", async () => {
    const fetch = answer({ debian: DEBIAN });
    const { db } = createTestDb();
    await runEndOfLifeCheck(db);
    expect((await readEndOfLife(db)).debian).toEqual({
      "13": "2030-06-30",
      "12": "2028-06-30",
    });
    expect(fetch).toHaveBeenCalledWith(
      "https://endoflife.date/api/v1/products/debian",
      { headers: { "user-agent": "kry-worker" } },
    );
    expect(fetch).toHaveBeenCalledTimes(7);
  });

  it("keeps yesterday's dates for a product that fails", async () => {
    answer({ debian: DEBIAN });
    const { db, sqlite } = createTestDb();
    sqlite
      .prepare(
        "INSERT INTO settings (key, value, updated_at) VALUES ('os_end_of_life', ?, ?)",
      )
      .run(
        JSON.stringify({ ubuntu: { "24.04": "2029-05-31" } }),
        "2026-10-27T03:17:00.000Z",
      );
    await runEndOfLifeCheck(db);
    const table = await readEndOfLife(db);
    expect(table.ubuntu).toEqual({ "24.04": "2029-05-31" });
    expect(table.debian).toEqual({ "13": "2030-06-30", "12": "2028-06-30" });
  });

  it("keeps an entry when an answer has no valid release", async () => {
    answer({ debian: [{ name: "12", eolFrom: "soon" }], ubuntu: "junk" });
    const { db, sqlite } = createTestDb();
    sqlite
      .prepare(
        "INSERT INTO settings (key, value, updated_at) VALUES ('os_end_of_life', ?, ?)",
      )
      .run(
        JSON.stringify({ debian: { "12": "2028-06-30" } }),
        "2026-10-27T03:17:00.000Z",
      );
    await runEndOfLifeCheck(db);
    expect((await readEndOfLife(db)).debian).toEqual({ "12": "2028-06-30" });
  });

  it("runs from the daily cron", async () => {
    answer({ debian: DEBIAN });
    const { db } = createTestDb();
    const pending: Promise<unknown>[] = [];
    worker.scheduled(
      {} as ScheduledController,
      { DB: db } as unknown as Env,
      {
        waitUntil: (promise: Promise<unknown>) => pending.push(promise),
      } as unknown as ExecutionContext,
    );
    await Promise.all(pending);
    expect((await readEndOfLife(db)).debian?.["12"]).toBe("2028-06-30");
  });

  it("reads nothing from a missing or unreadable row", async () => {
    const { db, sqlite } = createTestDb();
    expect(await readEndOfLife(db)).toEqual({});
    sqlite
      .prepare(
        "INSERT INTO settings (key, value, updated_at) VALUES ('os_end_of_life', 'nope', ?)",
      )
      .run("2026-10-27T03:17:00.000Z");
    expect(await readEndOfLife(db)).toEqual({});
  });

  it("finds a date by the server's ID", () => {
    const table = {
      "rocky-linux": { "9": "2032-05-31" },
      ubuntu: { "24.04": "2029-05-31" },
      rhel: { "9": "2032-05-31" },
    };
    expect(endOfLifeDate(table, "rocky", "9")).toBe("2032-05-31");
    expect(endOfLifeDate(table, "ubuntu", "24.04")).toBe("2029-05-31");
    expect(endOfLifeDate(table, "rhel", "9.6")).toBe("2032-05-31");
    expect(endOfLifeDate(table, "linuxmint", "22")).toBeNull();
  });

  it("warns 90 days ahead", () => {
    const end = Date.parse("2028-06-30T00:00:00Z");
    const day = 86_400_000;
    expect(
      eolFinding("Debian GNU/Linux 12", "2028-06-30", end - 89 * day),
    ).toEqual({
      id: "os-eol",
      severity: "warning",
      detail:
        "Debian GNU/Linux 12 stops getting security updates on 30 Jun 2028",
    });
    expect(
      eolFinding("Debian GNU/Linux 12", "2028-06-30", end - 91 * day),
    ).toBeNull();
    expect(eolFinding("Debian GNU/Linux 12", "2028-06-30", end + day)).toEqual({
      id: "os-eol",
      severity: "serious",
      detail:
        "Debian GNU/Linux 12 no longer gets security updates (since 30 Jun 2028)",
    });
    expect(eolFinding("Debian GNU/Linux 12", null, end)).toBeNull();
  });
});
