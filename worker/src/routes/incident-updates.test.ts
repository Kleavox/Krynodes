import { describe, expect, it } from "vitest";

import { app } from "../app";
import type { Env } from "../env";
import { seedCheck, seedIncident, seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";

const NODE = "11111111-1111-4111-8111-111111111111";
const CHECK = "22222222-2222-4222-8222-222222222222";
const OPEN = "33333333-3333-4333-8333-333333333333";
const CLOSED = "44444444-4444-4444-8444-444444444444";

function setup() {
  const { db, sqlite } = createTestDb();
  seedNode(sqlite, { id: NODE });
  seedCheck(sqlite, { id: CHECK, nodeId: NODE });
  sqlite.prepare("UPDATE checks SET public = 1 WHERE id = ?").run(CHECK);
  seedIncident(sqlite, {
    id: OPEN,
    checkId: CHECK,
    status: "OPEN",
    startedAt: new Date(Date.now() - 600_000).toISOString(),
  });
  seedIncident(sqlite, {
    id: CLOSED,
    checkId: CHECK,
    status: "RESOLVED",
    startedAt: new Date(Date.now() - 86_400_000).toISOString(),
  });
  const env = { DB: db } as unknown as Env;
  const call = (method: string, path: string, body?: unknown) =>
    app.request(
      `https://kry.example.test${path}`,
      {
        method,
        headers: { "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      },
      env,
    );
  return { sqlite, call };
}

describe("incident updates", () => {
  it("are posted while the incident is open and read back with their author", async () => {
    const t = setup();
    const posted = await t.call("POST", `/api/incidents/${OPEN}/updates`, {
      status: "investigating",
      message: "  The database is restarting.  ",
    });
    expect(posted.status).toBe(201);
    const detail = (await (
      await t.call("GET", `/api/incidents/${OPEN}`)
    ).json()) as {
      public: boolean;
      updates: { status: string; message: string; author: string }[];
    };
    expect(detail.public).toBe(true);
    expect(
      detail.updates.map(({ status, message, author }) => ({
        status,
        message,
        author,
      })),
    ).toEqual([
      {
        status: "investigating",
        message: "The database is restarting.",
        author: "standalone@localhost",
      },
    ]);
    const overview = (await (await t.call("GET", "/api/overview")).json()) as {
      incidents: { id: string; update_status: string | null }[];
    };
    expect(
      Object.fromEntries(
        overview.incidents.map((incident) => [
          incident.id,
          incident.update_status,
        ]),
      ),
    ).toEqual({ [OPEN]: "investigating", [CLOSED]: null });
  });

  it("are refused once resolved, empty, too long or with an unknown status", async () => {
    const t = setup();
    const post = (id: string, body: unknown) =>
      t.call("POST", `/api/incidents/${id}/updates`, body);
    const late = await post(CLOSED, { status: "update", message: "Late" });
    expect(late.status).toBe(409);
    expect(await late.json()).toMatchObject({ code: "INCIDENT_RESOLVED" });
    expect(
      (await post(OPEN, { status: "update", message: "   " })).status,
    ).toBe(400);
    expect(
      (await post(OPEN, { status: "update", message: "x".repeat(1001) }))
        .status,
    ).toBe(400);
    expect(
      (await post(OPEN, { status: "resolved", message: "Fixed" })).status,
    ).toBe(400);
    expect(
      (
        await post("55555555-5555-4555-8555-555555555555", {
          status: "update",
          message: "Who?",
        })
      ).status,
    ).toBe(404);
  });

  it("are deleted only by their author", async () => {
    const t = setup();
    t.sqlite
      .prepare(
        `INSERT INTO incident_updates (id, incident_id, status, message, author, created_at)
         VALUES ('theirs', ?, 'update', 'Hi', 'friend@example.test', '2026-10-14T06:00:00.000Z')`,
      )
      .run(OPEN);
    const mine = (await (
      await t.call("POST", `/api/incidents/${OPEN}/updates`, {
        status: "identified",
        message: "Found it",
      })
    ).json()) as { id: string };
    expect(
      (await t.call("DELETE", `/api/incidents/${OPEN}/updates/theirs`)).status,
    ).toBe(403);
    expect(
      (await t.call("DELETE", `/api/incidents/${OPEN}/updates/${mine.id}`))
        .status,
    ).toBe(204);
    expect(
      t.sqlite.prepare("SELECT id FROM incident_updates ORDER BY id").all(),
    ).toEqual([{ id: "theirs" }]);
  });
});
