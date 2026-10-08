import { afterEach, describe, expect, it, vi } from "vitest";

import { seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";
import {
  canUpdateRemotely,
  checkAgentRelease,
  parseReleaseLocation,
  readAgentRelease,
  requestAutoUpdates,
} from "./releases";

afterEach(() => vi.unstubAllGlobals());

function redirectTo(location: string) {
  const fetch = vi.fn(
    async () => new Response(null, { status: 302, headers: { location } }),
  );
  vi.stubGlobal("fetch", fetch);
  return fetch;
}

describe("canUpdateRemotely", () => {
  it("lets every released agent update itself", () => {
    expect(canUpdateRemotely("0.1.0")).toBe(true);
    expect(canUpdateRemotely("0.6.2")).toBe(true);
    expect(canUpdateRemotely("dev")).toBe(false);
    expect(canUpdateRemotely(null)).toBe(false);
  });
});

describe("parseReleaseLocation", () => {
  it("reads the version from the latest-release redirect", () => {
    expect(
      parseReleaseLocation(
        "https://github.com/Kleavox/Krynodes/releases/tag/agent-v0.5.1",
      ),
    ).toBe("0.5.1");
    expect(
      parseReleaseLocation("https://github.com/Kleavox/Krynodes/releases"),
    ).toBeNull();
    expect(parseReleaseLocation(null)).toBeNull();
  });
});

describe("checkAgentRelease", () => {
  it("asks GitHub without the API and remembers the answer", async () => {
    const fetch = redirectTo(
      "https://github.com/Kleavox/Krynodes/releases/tag/agent-v0.5.1",
    );
    const { db } = createTestDb();
    const now = Date.parse("2026-09-28T08:00:00Z");

    expect(await checkAgentRelease(db, now)).toEqual({
      version: "0.5.1",
      checkedAt: "2026-09-28T08:00:00.000Z",
    });
    expect(fetch).toHaveBeenCalledWith(
      "https://github.com/Kleavox/Krynodes/releases/latest",
      expect.objectContaining({ redirect: "manual" }),
    );
    expect(await readAgentRelease(db)).toEqual({
      version: "0.5.1",
      checkedAt: "2026-09-28T08:00:00.000Z",
    });
  });

  it("keeps the last known version when GitHub gives no answer", async () => {
    const { db } = createTestDb();
    redirectTo("https://github.com/Kleavox/Krynodes/releases/tag/agent-v0.5.1");
    await checkAgentRelease(db, Date.parse("2026-09-28T08:00:00Z"));
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("down", { status: 503 })),
    );
    expect(
      await checkAgentRelease(db, Date.parse("2026-09-29T08:00:00Z")),
    ).toEqual({ version: "0.5.1", checkedAt: "2026-09-29T08:00:00.000Z" });
  });
});

describe("requestAutoUpdates", () => {
  it("asks a fleet of 60 servers to update in one statement", async () => {
    const { db, sqlite } = createTestDb();
    for (let index = 0; index < 60; index++) {
      const id = `fleet-${index}`;
      seedNode(sqlite, { id });
      sqlite
        .prepare(
          "UPDATE nodes SET agent_version = '0.1.0', auto_update = 1 WHERE id = ?",
        )
        .run(id);
    }
    let statements = 0;
    const prepare = db.prepare.bind(db);
    db.prepare = ((sql: string) => {
      statements += 1;
      return prepare(sql);
    }) as typeof db.prepare;
    expect(
      await requestAutoUpdates(db, "0.2.0", Date.parse("2026-09-28T08:00:00Z")),
    ).toBe(60);
    expect(statements).toBeLessThanOrEqual(2);
    expect(
      sqlite
        .prepare(
          "SELECT COUNT(*) AS n FROM nodes WHERE update_requested_version = '0.2.0'",
        )
        .get(),
    ).toEqual({ n: 60 });
  });

  it("asks only opted-in, capable, outdated and idle nodes to update", async () => {
    const { db, sqlite } = createTestDb();
    const set = sqlite.prepare(
      "UPDATE nodes SET agent_version = ?, auto_update = ?, update_requested_version = ? WHERE id = ?",
    );
    for (const id of ["due", "opted-out", "dev", "current", "busy"]) {
      seedNode(sqlite, { id });
    }
    set.run("0.1.0", 1, null, "due");
    set.run("0.1.0", 0, null, "opted-out");
    set.run("dev", 1, null, "dev");
    set.run("0.2.0", 1, null, "current");
    set.run("0.1.0", 1, "0.2.0", "busy");

    const now = Date.parse("2026-09-28T08:00:00Z");
    expect(await requestAutoUpdates(db, "0.2.0", now)).toBe(1);
    expect(
      sqlite
        .prepare(
          "SELECT id FROM nodes WHERE update_requested_at = '2026-09-28T08:00:00.000Z'",
        )
        .all(),
    ).toEqual([{ id: "due" }]);
  });
});
