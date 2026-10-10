import { describe, expect, it } from "vitest";

import { app } from "../app";
import type { Env } from "../env";
import { seedCheck, seedIncident, seedNode, seedResult } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";

const NODE = "11111111-1111-4111-8111-111111111111";
const CHECK = "22222222-2222-4222-8222-222222222222";

function setup() {
  const { db, sqlite } = createTestDb();
  seedNode(sqlite, { id: NODE });
  seedCheck(sqlite, { id: CHECK, nodeId: NODE });
  const env = { DB: db } as unknown as Env;
  const patch = (body: unknown) =>
    app.request(
      `https://kry.example.test/api/checks/${CHECK}`,
      {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      },
      env,
    );
  const row = () =>
    sqlite
      .prepare("SELECT public, public_note FROM checks WHERE id = ?")
      .get(CHECK);
  return { env, patch, row };
}

describe("public check fields", () => {
  it("starts hidden without a note", () => {
    expect(setup().row()).toEqual({ public: 0, public_note: null });
  });

  it("publishes with a trimmed note, clears an empty note, and keeps the note when hidden", async () => {
    const { patch, row } = setup();
    expect(
      (await patch({ public: true, publicNote: "  Main website  " })).status,
    ).toBe(200);
    expect(row()).toEqual({ public: 1, public_note: "Main website" });
    expect((await patch({ public: false })).status).toBe(200);
    expect(row()).toEqual({ public: 0, public_note: "Main website" });
    expect((await patch({ publicNote: "   " })).status).toBe(200);
    expect(row()).toEqual({ public: 0, public_note: null });
  });

  it.each([{ publicNote: "x".repeat(201) }, { public: "yes" }, { public: 1 }])(
    "refuses %j",
    async (body) => {
      const { patch, row } = setup();
      expect((await patch(body)).status).toBe(400);
      expect(row()).toEqual({ public: 0, public_note: null });
    },
  );

  it("returns both fields in the overview", async () => {
    const { env, patch } = setup();
    await patch({ public: true, publicNote: "DNS" });
    const overview = (await (
      await app.request("https://kry.example.test/api/overview", {}, env)
    ).json()) as { checks: { public: number; public_note: string | null }[] };
    expect(overview.checks[0]).toMatchObject({ public: 1, public_note: "DNS" });
  });
});

describe("editing a check", () => {
  const OTHER = "33333333-3333-4333-8333-333333333333";

  function edit() {
    const { db, sqlite } = createTestDb();
    seedNode(sqlite, { id: NODE });
    seedNode(sqlite, { id: OTHER });
    seedCheck(sqlite, { id: CHECK, nodeId: NODE });
    sqlite
      .prepare(
        "UPDATE checks SET status = 'DOWN', consecutive_failures = 4, latency_ms = 120, last_message = 'timeout', last_checked_at = '2026-09-30 10:00:00' WHERE id = ?",
      )
      .run(CHECK);
    seedIncident(sqlite, {
      id: "i1",
      checkId: CHECK,
      status: "OPEN",
      startedAt: "2026-09-30 09:58:00",
    });
    seedResult(sqlite, CHECK, "2026-09-30 10:00:00", "DOWN");
    const env = { DB: db } as unknown as Env;
    const patch = (body: unknown) =>
      app.request(
        `https://kry.example.test/api/checks/${CHECK}`,
        {
          method: "PATCH",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        },
        env,
      );
    const check = () =>
      sqlite
        .prepare(
          "SELECT node_id, name, kind, target, timeout_seconds, enabled, status, consecutive_failures, latency_ms, last_message, last_checked_at FROM checks WHERE id = ?",
        )
        .get(CHECK) as Record<string, unknown>;
    const incident = () =>
      sqlite
        .prepare("SELECT status, resolved_at FROM incidents WHERE id = 'i1'")
        .get() as { status: string; resolved_at: string | null };
    const results = () =>
      (
        sqlite
          .prepare(
            "SELECT COUNT(*) AS n FROM node_windows WHERE json_extract(checks, '$.' || ?) IS NOT NULL",
          )
          .get(CHECK) as { n: number }
      ).n;
    return { sqlite, patch, check, incident, results };
  }

  const FRESH = {
    status: "UNKNOWN",
    consecutive_failures: 0,
    latency_ms: null,
    last_message: null,
    last_checked_at: null,
  };

  it("renames and changes the timeout without touching the status", async () => {
    const t = edit();
    const response = await t.patch({ name: "  Website  ", timeoutSeconds: 20 });
    expect(response.status).toBe(200);
    expect(t.check()).toMatchObject({
      name: "Website",
      timeout_seconds: 20,
      status: "DOWN",
      consecutive_failures: 4,
    });
    expect(t.incident().status).toBe("OPEN");
  });

  it("starts fresh when the target changes, closing the open incident and keeping history", async () => {
    const t = edit();
    expect(
      (await t.patch({ target: "https://example.com/ready" })).status,
    ).toBe(200);
    expect(t.check()).toMatchObject({
      target: "https://example.com/ready",
      ...FRESH,
    });
    expect(t.incident().status).toBe("RESOLVED");
    expect(t.incident().resolved_at).not.toBeNull();
    expect(t.results()).toBe(1);
  });

  it("changes the kind and target together, validated for the new kind", async () => {
    const t = edit();
    expect(
      (await t.patch({ kind: "TCP", target: "https://example.com" })).status,
    ).toBe(400);
    expect((await t.patch({ kind: "TCP" })).status).toBe(400);
    expect(t.check()).toMatchObject({ kind: "HTTP", status: "DOWN" });
    expect(
      (await t.patch({ kind: "TCP", target: "DB.internal:5432" })).status,
    ).toBe(200);
    expect(t.check()).toMatchObject({
      kind: "TCP",
      target: "db.internal:5432",
      ...FRESH,
    });
  });

  it("moves to another owned node within its check limit", async () => {
    const t = edit();
    expect(
      (await t.patch({ nodeId: "44444444-4444-4444-8444-444444444444" }))
        .status,
    ).toBe(404);
    for (let index = 0; index < 10; index += 1) {
      seedCheck(t.sqlite, { id: `full-${index}`, nodeId: OTHER });
    }
    expect((await t.patch({ nodeId: OTHER })).status).toBe(400);
    t.sqlite.prepare("DELETE FROM checks WHERE id = 'full-0'").run();
    expect((await t.patch({ nodeId: OTHER })).status).toBe(200);
    expect(t.check()).toMatchObject({ node_id: OTHER, ...FRESH });
    expect(t.incident().status).toBe("RESOLVED");
  });

  it("pauses by closing the open incident and resumes from a fresh status", async () => {
    const t = edit();
    expect((await t.patch({ enabled: false })).status).toBe(200);
    expect(t.check()).toMatchObject({ enabled: 0, ...FRESH });
    expect(t.incident().status).toBe("RESOLVED");
    expect((await t.patch({ enabled: true })).status).toBe(200);
    expect(t.check()).toMatchObject({ enabled: 1, status: "UNKNOWN" });
  });

  it("keeps the status when an edit changes nothing that is checked", async () => {
    const t = edit();
    expect(
      (
        await t.patch({
          kind: "HTTP",
          target: "https://example.com/health",
          nodeId: NODE,
          enabled: true,
        })
      ).status,
    ).toBe(200);
    expect(t.check()).toMatchObject({
      status: "DOWN",
      consecutive_failures: 4,
    });
    expect(t.incident().status).toBe("OPEN");
  });
});

describe("auto-restart follows its check", () => {
  function watched() {
    const { db, sqlite } = createTestDb();
    seedNode(sqlite, { id: NODE });
    sqlite
      .prepare("UPDATE nodes SET agent_version = '0.4.0' WHERE id = ?")
      .run(NODE);
    sqlite
      .prepare(
        "INSERT INTO checks (id, node_id, name, kind, target, enabled, auto_restart) VALUES (?, ?, 'nginx', 'SERVICE', 'nginx', 1, 1)",
      )
      .run(CHECK, NODE);
    const env = { DB: db } as unknown as Env;
    const call = (method: string, body?: unknown) =>
      app.request(
        `https://kry.example.test/api/checks/${CHECK}`,
        {
          method,
          headers: { "content-type": "application/json" },
          body: body === undefined ? undefined : JSON.stringify(body),
        },
        env,
      );
    const manual = () =>
      sqlite
        .prepare("SELECT name, status FROM actions WHERE action = 'manual'")
        .all();
    const flag = () =>
      (
        sqlite
          .prepare("SELECT auto_restart FROM checks WHERE id = ?")
          .get(CHECK) as { auto_restart: number }
      ).auto_restart;
    return { sqlite, call, manual, flag };
  }

  it("turns it off on the server when the check is removed", async () => {
    const t = watched();
    expect((await t.call("DELETE")).status).toBeLessThan(300);
    expect(t.manual()).toEqual([{ name: "nginx.service", status: "queued" }]);
  });

  it("turns it off when the check watches another unit, not on a rename", async () => {
    const t = watched();
    expect((await t.call("PATCH", { name: "web" })).status).toBe(200);
    expect(t.manual()).toEqual([]);
    expect(t.flag()).toBe(1);
    expect((await t.call("PATCH", { target: "caddy.service" })).status).toBe(
      200,
    );
    expect(t.flag()).toBe(0);
    expect(t.manual()).toEqual([{ name: "nginx.service", status: "queued" }]);
  });

  it("keeps the unit listed while another check still restarts it", async () => {
    const t = watched();
    t.sqlite
      .prepare(
        "INSERT INTO checks (id, node_id, name, kind, target, enabled, auto_restart) VALUES ('other', ?, 'nginx again', 'SERVICE', 'nginx.service', 1, 1)",
      )
      .run(NODE);
    expect((await t.call("DELETE")).status).toBeLessThan(300);
    expect(t.manual()).toEqual([]);
  });
});

describe("container checks", () => {
  function containers(version: string | null) {
    const { db, sqlite } = createTestDb();
    seedNode(sqlite, { id: NODE });
    sqlite
      .prepare("UPDATE nodes SET agent_version = ? WHERE id = ?")
      .run(version, NODE);
    seedCheck(sqlite, { id: CHECK, nodeId: NODE });
    const env = { DB: db } as unknown as Env;
    const send = (method: string, path: string, body: unknown) =>
      app.request(
        `https://kry.example.test${path}`,
        {
          method,
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        },
        env,
      );
    return { send, sqlite };
  }
  const create = {
    nodeId: NODE,
    name: "AdGuard",
    kind: "CONTAINER",
    target: "adguard-adguard-1",
  };

  it("creates one on agent 0.6.4 or newer", async () => {
    const { send, sqlite } = containers("0.6.4");
    expect((await send("POST", "/api/checks", create)).status).toBe(201);
    expect(
      sqlite
        .prepare("SELECT kind, target FROM checks WHERE name = 'AdGuard'")
        .get(),
    ).toEqual({ kind: "CONTAINER", target: "adguard-adguard-1" });
  });

  it.each(["0.6.3", null])("refuses agent %s", async (version) => {
    const { send } = containers(version);
    const response = await send("POST", "/api/checks", create);
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({
      code: "AGENT_TOO_OLD",
      message: "This server needs agent 0.6.4 or newer for container checks.",
    });
    const changed = await send("PATCH", `/api/checks/${CHECK}`, {
      kind: "CONTAINER",
      target: "web",
    });
    expect(changed.status).toBe(409);
  });

  it("refuses a name Docker would not give a container", async () => {
    const { send } = containers("0.6.4");
    for (const target of ["-web", "web/1", "web 1", "x".repeat(129)]) {
      expect(
        (await send("POST", "/api/checks", { ...create, target })).status,
      ).toBe(400);
    }
  });
});
